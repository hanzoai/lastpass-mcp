import crypto from 'node:crypto';
import http from 'node:http';
import readline from 'node:readline';
import { LastPassEnterpriseClient } from './enterprise.js';
import { KmsEgressBridge } from './kms-egress.js';
import { LpassCliAdapter, matchVaultEntry } from './lpass-cli.js';
import {
  assertNoSecretLeak,
  sanitizeAccountMetadata,
  scrubError,
} from './scrub.js';
import type {
  AutofillResult,
  EgressFetchResult,
  JsonRpcRequest,
  JsonRpcResponse,
  LastPassLoginResult,
  LastPassStatusResult,
  SealToKmsResult,
  VaultCredential,
  VaultEntryMetadata,
} from './types.js';
import { LastPassVaultClient } from './vault-protocol.js';
import { ZapBrowserClient } from './zap-client.js';

export * from './types.js';
export * from './scrub.js';
export * from './vault-protocol.js';
export * from './lpass-cli.js';
export * from './zap-client.js';
export * from './enterprise.js';
export * from './kms-egress.js';

export const SERVER_NAME = '@hanzo/lastpass-mcp';
export const SERVER_VERSION = '0.1.0';
export const DEFAULT_PROTOCOL_VERSION = '2024-11-05';
const SUPPORTED_PROTOCOL_VERSIONS = new Set(['2024-11-05', '2025-03-26']);

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: {
    title?: string;
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
}

export const LASTPASS_MCP_TOOLS: ReadonlyArray<ToolDefinition> = [
  {
    name: 'lastpass_status',
    description:
      'Reports lpass CLI binary & login status, connected Chrome lastpass.com session presence over ZAP (cookie names only, never values), Hanzo KMS health (~/.local/bin/hanzo kms health), and HANZO_EGRESS_URL configuration.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        asOrg: {
          type: 'string',
          description: 'Optional Hanzo organization slug for `hanzo --as <org> kms health`.',
        },
      },
    },
    annotations: {
      title: 'LastPass & Custody Status',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'lastpass_login',
    description:
      'Initiates out-of-band LastPass authentication either by opening https://lastpass.com/?ac=1 in the user\'s connected Chrome over ZAP or starting non-echoing `lpass login --trust <email>`. Master passwords never transit MCP.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        email: {
          type: 'string',
          description: 'LastPass account email (required when mode is "cli").',
        },
        mode: {
          type: 'string',
          enum: ['auto', 'browser', 'cli'],
          description:
            'Authentication path: "browser" opens https://lastpass.com/?ac=1 via ZAP; "cli" spawns out-of-band `lpass login --trust <email>`; "auto" prefers browser ZAP when connected.',
        },
      },
    },
    annotations: {
      title: 'Initiate LastPass Login',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'lastpass_list',
    description:
      'Lists or searches LastPass vault entry metadata (`id`, `name`, `fullname`, `username`, `url`, `group`, `lastModifiedGmt`, `hasTotp`). Strictly strips all passwords, notes, and TOTP seeds.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        query: {
          type: 'string',
          description: 'Optional substring filter across name, fullname, username, url, or group.',
        },
        url: {
          type: 'string',
          description: 'Optional domain or URL filter (e.g., "github.com").',
        },
        name: {
          type: 'string',
          description: 'Optional entry name filter.',
        },
        username: {
          type: 'string',
          description: 'Optional username filter (e.g., "hanzoai").',
        },
      },
    },
    annotations: {
      title: 'List Vault Metadata',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'lastpass_autofill',
    description:
      'Resolves a matching LastPass credential in memory and fills `username`, `password`, and optional RFC 6238 `totp` directly into the open browser tab over ZAP (`hanzo.act` op="fill" or `lastpass.fill`). Never returns secret values.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        id: {
          type: 'string',
          description: 'Exact LastPass item ID if known.',
        },
        url: {
          type: 'string',
          description: 'Target site URL or domain to match (e.g., "https://github.com/login").',
        },
        name: {
          type: 'string',
          description: 'Vault entry name to match.',
        },
        username: {
          type: 'string',
          description: 'Optional username disambiguator (e.g., "hanzoai").',
        },
        tabId: {
          oneOf: [{ type: 'string' }, { type: 'number' }],
          description: 'Optional browser tab ID on the ZAP router.',
        },
      },
    },
    annotations: {
      title: 'Autofill Credential in Browser',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: 'lastpass_seal_to_kms',
    description:
      'Seals one or all matching LastPass items directly from memory into Hanzo KMS (`kms.hanzo.ai`) at `credentials/<slug>/USERNAME`, `PASSWORD`, `URL`, and `TOTP_SECRET` for IAM-governed custody via hanzoai/egress.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        id: {
          type: 'string',
          description: 'Specific LastPass entry ID to seal.',
        },
        name: {
          type: 'string',
          description: 'Entry name filter.',
        },
        url: {
          type: 'string',
          description: 'Entry URL/domain filter.',
        },
        username: {
          type: 'string',
          description: 'Optional username filter.',
        },
        all: {
          type: 'boolean',
          description: 'Set true to seal all vault entries matching the filter (or entire vault if unfiltered).',
        },
        slug: {
          type: 'string',
          description: 'Optional custom KMS slug override when sealing a single item.',
        },
        pathPrefix: {
          type: 'string',
          description: 'KMS path prefix (defaults to "credentials").',
        },
        env: {
          type: 'string',
          description: 'Optional KMS environment name (`--env`).',
        },
        asOrg: {
          type: 'string',
          description: 'Optional Hanzo organization slug (`--as <org>`).',
        },
        enrollInEgress: {
          type: 'boolean',
          description: 'Also enroll the secret into hanzoai/egress POST /v1/enroll.',
        },
        egressProvider: {
          type: 'string',
          description: 'Provider name when enrollInEgress=true.',
        },
        egressLabel: {
          type: 'string',
          description: 'Account label when enrollInEgress=true (defaults to "default").',
        },
        iamToken: {
          type: 'string',
          description: 'Optional IAM bearer token for egress enrollment (defaults to HANZO_IAM_TOKEN).',
        },
      },
    },
    annotations: {
      title: 'Seal Vault Item to Hanzo KMS',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: 'lastpass_egress_fetch',
    description:
      'Executes an outbound authenticated HTTP request either via hanzoai/egress (`POST ${HANZO_EGRESS_URL}/v1/fetch` spending KMS-custodied credentials) or in-process injecting a LastPass secret into an outbound header while scrubbing all raw/base64/URL-encoded credential bytes from responses and errors.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        provider: {
          type: 'string',
          description:
            'Cloud provider registered in hanzoai/egress (e.g., "digitalocean", "hetzner") for Egress broker mode.',
        },
        label: {
          type: 'string',
          description: 'Credential label in Egress broker mode (defaults to "default").',
        },
        path: {
          type: 'string',
          description: 'Rooted API path (e.g., "/v2/account") in Egress broker mode.',
        },
        iamToken: {
          type: 'string',
          description: 'Caller IAM bearer token for Egress broker mode (or HANZO_IAM_TOKEN env).',
        },
        id: {
          type: 'string',
          description: 'LastPass item ID for custodied in-process fetch mode.',
        },
        name: {
          type: 'string',
          description: 'LastPass item name for custodied in-process fetch mode.',
        },
        url: {
          type: 'string',
          description: 'Vault item site match for custodied in-process fetch mode.',
        },
        username: {
          type: 'string',
          description: 'Optional vault item username disambiguator.',
        },
        targetUrl: {
          type: 'string',
          description: 'HTTPS endpoint URL to call in custodied in-process fetch mode.',
        },
        method: {
          type: 'string',
          enum: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'],
          description: 'HTTP method (defaults to GET).',
        },
        authScheme: {
          type: 'string',
          enum: ['bearer', 'basic', 'header'],
          description: 'How to inject the custodied secret in in-process mode (defaults to "bearer").',
        },
        headerName: {
          type: 'string',
          description: 'Header name when authScheme="header" (defaults to "X-API-Key").',
        },
        headers: {
          type: 'object',
          additionalProperties: { type: 'string' },
          description: 'Non-sensitive request headers (Authorization, Cookie, Host are forbidden).',
        },
        body: {
          description: 'Optional JSON or string request body for POST/PUT/PATCH.',
        },
      },
    },
    annotations: {
      title: 'Custodied Outbound Fetch',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
];

export interface LastPassMcpServerDeps {
  lpass?: LpassCliAdapter;
  zap?: ZapBrowserClient;
  kmsEgress?: KmsEgressBridge;
  vaultClient?: LastPassVaultClient;
  enterpriseClient?: LastPassEnterpriseClient;
  /**
   * Optional in-memory credential resolver hook (e.g. decrypted vault blob
   * session or synthetic test fixture). Never exposed outside this class.
   */
  resolveVaultCredentials?: () => Promise<VaultCredential[]>;
}

export class LastPassMcpServer {
  public readonly lpass: LpassCliAdapter;
  public readonly zap: ZapBrowserClient;
  public readonly kmsEgress: KmsEgressBridge;
  public readonly vaultClient: LastPassVaultClient;
  public readonly enterpriseClient: LastPassEnterpriseClient;
  private readonly resolveVaultCredentials?: () => Promise<VaultCredential[]>;

  constructor(deps: LastPassMcpServerDeps = {}) {
    this.lpass = deps.lpass ?? new LpassCliAdapter();
    this.zap = deps.zap ?? new ZapBrowserClient();
    this.kmsEgress = deps.kmsEgress ?? new KmsEgressBridge();
    this.vaultClient = deps.vaultClient ?? new LastPassVaultClient();
    this.enterpriseClient = deps.enterpriseClient ?? new LastPassEnterpriseClient();
    this.resolveVaultCredentials = deps.resolveVaultCredentials;
  }

  private async loadInMemoryCredentials(): Promise<VaultCredential[]> {
    if (this.resolveVaultCredentials) {
      return await this.resolveVaultCredentials();
    }
    const status = await this.lpass.getStatus();
    if (status.available && status.loggedIn) {
      return await this.lpass.loadCredentialsInMemory();
    }
    return [];
  }

  private async resolveSingleCredential(selector: {
    id?: string;
    url?: string;
    name?: string;
    username?: string;
  }): Promise<VaultCredential | null> {
    if (this.resolveVaultCredentials) {
      const creds = await this.resolveVaultCredentials();
      const matches = creds.filter((c) => matchVaultEntry(c, selector));
      if (matches.length === 0) return null;
      if (selector.username) {
        const exact = matches.find(
          (m) => m.username.toLowerCase() === selector.username!.toLowerCase(),
        );
        if (exact) return exact;
      }
      return matches[0];
    }

    const status = await this.lpass.getStatus();
    if (status.available && status.loggedIn) {
      return await this.lpass.resolveOneInMemory(selector);
    }
    return null;
  }

  async toolStatus(args: Record<string, unknown> = {}): Promise<LastPassStatusResult> {
    const asOrg = typeof args.asOrg === 'string' ? args.asOrg : undefined;
    const [lpass, zapBrowser, kms] = await Promise.all([
      this.lpass.getStatus(),
      this.zap.probeStatus(),
      this.kmsEgress.checkKmsHealth(asOrg),
    ]);
    return {
      lpass,
      zapBrowser,
      kms,
      egress: this.kmsEgress.getEgressStatus(),
      vaultProtocolReady: true,
    };
  }

  async toolLogin(args: Record<string, unknown> = {}): Promise<LastPassLoginResult> {
    const email = typeof args.email === 'string' ? args.email.trim() : undefined;
    const mode =
      args.mode === 'browser' || args.mode === 'cli' || args.mode === 'auto'
        ? args.mode
        : 'auto';

    const browserUrl = 'https://lastpass.com/?ac=1';

    if (mode === 'browser' || mode === 'auto') {
      const zapStatus = await this.zap.probeStatus();
      if (zapStatus.browserConnected) {
        await this.zap.openVaultLoginTab(browserUrl);
        return {
          initiated: true,
          mode: 'browser_zap',
          ...(email ? { email } : {}),
          browserUrl,
          detail:
            'Opened https://lastpass.com/?ac=1 in connected Chrome via ZAP so you can sign in directly in the browser.',
        };
      }
      if (mode === 'browser') {
        throw new Error(
          `Cannot open LastPass in browser: no Chrome provider connected on ZAP (${zapStatus.socketPath})`,
        );
      }
    }

    if (!email) {
      throw new Error(
        'Provide `email` to initiate `lpass login --trust <email>`, or connect Chrome over ZAP for browser sign-in.',
      );
    }

    const cliRes = await this.lpass.initiateOutOfBandLogin(email);
    return {
      initiated: cliRes.started,
      mode: 'lpass_cli',
      email,
      detail: cliRes.detail,
    };
  }

  async toolList(args: Record<string, unknown> = {}): Promise<{
    count: number;
    source: 'vault_memory' | 'lpass_cli' | 'zap_browser' | 'none';
    entries: VaultEntryMetadata[];
  }> {
    const filter = {
      query: typeof args.query === 'string' ? args.query : undefined,
      url: typeof args.url === 'string' ? args.url : undefined,
      name: typeof args.name === 'string' ? args.name : undefined,
      username: typeof args.username === 'string' ? args.username : undefined,
    };

    if (this.resolveVaultCredentials) {
      const creds = await this.resolveVaultCredentials();
      const entries = creds
        .filter((c) => matchVaultEntry(c, filter))
        .map((c) => sanitizeAccountMetadata(c));
      return { count: entries.length, source: 'vault_memory', entries };
    }

    const lpassStatus = await this.lpass.getStatus();
    if (lpassStatus.available && lpassStatus.loggedIn) {
      const entries = await this.lpass.listMetadata(filter);
      return { count: entries.length, source: 'lpass_cli', entries };
    }

    const zapStatus = await this.zap.probeStatus();
    if (zapStatus.browserConnected) {
      try {
        const entries = await this.zap.listAccountsMetadata(filter);
        return { count: entries.length, source: 'zap_browser', entries };
      } catch {
        // Fall through if extension hasn't unlocked vault tab yet
      }
    }

    return { count: 0, source: 'none', entries: [] };
  }

  async toolAutofill(
    args: Record<string, unknown> = {},
  ): Promise<{ result: AutofillResult; touchedSecrets: Array<string | undefined> }> {
    const id = typeof args.id === 'string' ? args.id : undefined;
    const url = typeof args.url === 'string' ? args.url : undefined;
    const name = typeof args.name === 'string' ? args.name : undefined;
    const username = typeof args.username === 'string' ? args.username : undefined;
    const tabId =
      typeof args.tabId === 'string' || typeof args.tabId === 'number'
        ? args.tabId
        : undefined;

    if (!id && !url && !name) {
      throw new Error('lastpass_autofill requires at least one of `url`, `name`, or `id`');
    }

    const cred = await this.resolveSingleCredential({ id, url, name, username });
    if (cred) {
      const result = await this.zap.autofillCredentialInTab(cred, { tabId });
      return {
        result,
        touchedSecrets: [cred.password, cred.totpSecret, cred.note],
      };
    }

    // Fallback: ask signed-in Chrome LastPass vault over ZAP (`lastpass.fill`)
    const result = await this.zap.autofillViaBrowserVault({ url, name, username, tabId });
    return {
      result,
      touchedSecrets: [],
    };
  }

  async toolSealToKms(
    args: Record<string, unknown> = {},
  ): Promise<{ result: SealToKmsResult; touchedSecrets: Array<string | undefined> }> {
    const id = typeof args.id === 'string' ? args.id : undefined;
    const name = typeof args.name === 'string' ? args.name : undefined;
    const url = typeof args.url === 'string' ? args.url : undefined;
    const username = typeof args.username === 'string' ? args.username : undefined;
    const sealAll = Boolean(args.all);
    const iamToken = typeof args.iamToken === 'string' ? args.iamToken : undefined;

    if (!sealAll && !id && !name && !url) {
      throw new Error(
        'Specify `id`, `name`, or `url` to seal one item, or set `all: true` to seal all matching items.',
      );
    }

    let targets: VaultCredential[] = [];
    if (!sealAll) {
      const one = await this.resolveSingleCredential({ id, url, name, username });
      if (!one) {
        throw new Error('No matching LastPass vault item found to seal');
      }
      targets = [one];
    } else {
      const allCreds = await this.loadInMemoryCredentials();
      targets = allCreds.filter((c) => matchVaultEntry(c, { id, url, name, username }));
      if (targets.length === 0) {
        throw new Error('No matching LastPass vault items found to seal');
      }
    }

    const touchedSecrets: Array<string | undefined> = [iamToken];
    for (const t of targets) {
      touchedSecrets.push(t.password, t.totpSecret, t.note);
    }

    const result = await this.kmsEgress.sealCredentialsToKms(targets, {
      slugOverride: typeof args.slug === 'string' ? args.slug : undefined,
      pathPrefix: typeof args.pathPrefix === 'string' ? args.pathPrefix : undefined,
      env: typeof args.env === 'string' ? args.env : undefined,
      asOrg: typeof args.asOrg === 'string' ? args.asOrg : undefined,
      enrollInEgress: Boolean(args.enrollInEgress),
      egressProvider: typeof args.egressProvider === 'string' ? args.egressProvider : undefined,
      egressLabel: typeof args.egressLabel === 'string' ? args.egressLabel : undefined,
      iamToken,
    });

    return { result, touchedSecrets };
  }

  async toolEgressFetch(
    args: Record<string, unknown> = {},
  ): Promise<{ result: EgressFetchResult; touchedSecrets: Array<string | undefined> }> {
    const provider = typeof args.provider === 'string' ? args.provider.trim() : '';
    const apiPath = typeof args.path === 'string' ? args.path.trim() : '';
    const method = typeof args.method === 'string' ? args.method : 'GET';
    const iamToken = typeof args.iamToken === 'string' ? args.iamToken : undefined;

    if (provider) {
      if (!apiPath) {
        throw new Error('`path` (e.g. "/v2/account") is required when `provider` is set');
      }
      const result = await this.kmsEgress.fetchViaEgressBroker({
        provider,
        label: typeof args.label === 'string' ? args.label : undefined,
        method,
        path: apiPath,
        body: args.body,
        iamToken,
      });
      return { result, touchedSecrets: [iamToken] };
    }

    const targetUrl = typeof args.targetUrl === 'string' ? args.targetUrl.trim() : '';
    if (!targetUrl) {
      throw new Error(
        'Provide either `provider` + `path` (for hanzoai/egress broker mode) or `targetUrl` + item selector (`id`/`name`/`url`) for custodied fetch mode.',
      );
    }

    const selector = {
      id: typeof args.id === 'string' ? args.id : undefined,
      name: typeof args.name === 'string' ? args.name : undefined,
      url:
        typeof args.url === 'string'
          ? args.url
          : !args.id && !args.name
            ? targetUrl
            : undefined,
      username: typeof args.username === 'string' ? args.username : undefined,
    };

    const cred = await this.resolveSingleCredential(selector);
    if (!cred) {
      throw new Error('No matching LastPass credential found for custodied outbound fetch');
    }

    const authScheme =
      args.authScheme === 'bearer' || args.authScheme === 'basic' || args.authScheme === 'header'
        ? args.authScheme
        : 'bearer';

    const headers =
      args.headers && typeof args.headers === 'object' && !Array.isArray(args.headers)
        ? (args.headers as Record<string, string>)
        : undefined;

    const result = await this.kmsEgress.fetchWithCustodiedCredential(cred, {
      targetUrl,
      method,
      authScheme,
      headerName: typeof args.headerName === 'string' ? args.headerName : undefined,
      headers,
      body: args.body,
    });

    return {
      result,
      touchedSecrets: [cred.password, cred.totpSecret, cred.note],
    };
  }

  /**
   * Handles a single MCP JSON-RPC 2.0 message. Returns `null` for notifications.
   */
  async handleJsonRpc(req: JsonRpcRequest): Promise<JsonRpcResponse | null> {
    if (!req || req.jsonrpc !== '2.0' || typeof req.method !== 'string') {
      return {
        jsonrpc: '2.0',
        id: req?.id ?? null,
        error: { code: -32600, message: 'Invalid JSON-RPC 2.0 request' },
      };
    }

    const isNotification = req.id === undefined;

    if (req.method === 'notifications/initialized' || req.method.startsWith('notifications/')) {
      return null;
    }

    if (req.method === 'ping') {
      return isNotification ? null : { jsonrpc: '2.0', id: req.id ?? null, result: {} };
    }

    if (req.method === 'initialize') {
      const requested =
        typeof req.params?.protocolVersion === 'string'
          ? req.params.protocolVersion
          : DEFAULT_PROTOCOL_VERSION;
      const negotiated = SUPPORTED_PROTOCOL_VERSIONS.has(requested)
        ? requested
        : DEFAULT_PROTOCOL_VERSION;
      return {
        jsonrpc: '2.0',
        id: req.id ?? null,
        result: {
          protocolVersion: negotiated,
          capabilities: {
            tools: { listChanged: false },
          },
          serverInfo: {
            name: SERVER_NAME,
            version: SERVER_VERSION,
          },
        },
      };
    }

    if (req.method === 'tools/list') {
      return {
        jsonrpc: '2.0',
        id: req.id ?? null,
        result: {
          tools: LASTPASS_MCP_TOOLS,
        },
      };
    }

    if (req.method === 'tools/call') {
      const toolName = typeof req.params?.name === 'string' ? req.params.name : '';
      const rawArgs =
        req.params?.arguments &&
        typeof req.params.arguments === 'object' &&
        !Array.isArray(req.params.arguments)
          ? (req.params.arguments as Record<string, unknown>)
          : {};

      const knownTool = LASTPASS_MCP_TOOLS.some((t) => t.name === toolName);
      if (!knownTool) {
        return {
          jsonrpc: '2.0',
          id: req.id ?? null,
          error: {
            code: -32602,
            message: `Unknown tool: ${toolName}`,
          },
        };
      }

      let touchedSecrets: Array<string | undefined> = [];
      try {
        let payload: unknown;
        switch (toolName) {
          case 'lastpass_status':
            payload = await this.toolStatus(rawArgs);
            break;
          case 'lastpass_login':
            payload = await this.toolLogin(rawArgs);
            break;
          case 'lastpass_list':
            payload = await this.toolList(rawArgs);
            break;
          case 'lastpass_autofill': {
            const out = await this.toolAutofill(rawArgs);
            payload = out.result;
            touchedSecrets = out.touchedSecrets;
            break;
          }
          case 'lastpass_seal_to_kms': {
            const out = await this.toolSealToKms(rawArgs);
            payload = out.result;
            touchedSecrets = out.touchedSecrets;
            break;
          }
          case 'lastpass_egress_fetch': {
            const out = await this.toolEgressFetch(rawArgs);
            payload = out.result;
            touchedSecrets = out.touchedSecrets;
            break;
          }
        }

        const safeJson = assertNoSecretLeak(JSON.stringify(payload, null, 2), touchedSecrets);
        const safeStructured = JSON.parse(safeJson) as unknown;

        return {
          jsonrpc: '2.0',
          id: req.id ?? null,
          result: {
            content: [{ type: 'text', text: safeJson }],
            structuredContent: safeStructured,
          },
        };
      } catch (err) {
        const cleanErr = scrubError(err, touchedSecrets);
        return {
          jsonrpc: '2.0',
          id: req.id ?? null,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ error: cleanErr.message }),
              },
            ],
            isError: true,
          },
        };
      }
    }

    if (isNotification) return null;

    return {
      jsonrpc: '2.0',
      id: req.id ?? null,
      error: {
        code: -32601,
        message: `Method not found: ${req.method}`,
      },
    };
  }

  /**
   * Starts MCP over newline-delimited JSON-RPC stdio (`process.stdin` / `process.stdout`).
   */
  startStdio(
    input: NodeJS.ReadableStream = process.stdin,
    output: NodeJS.WritableStream = process.stdout,
  ): { close: () => void } {
    const rl = readline.createInterface({
      input,
      crlfDelay: Infinity,
      terminal: false,
    });

    rl.on('line', (line) => {
      const trimmed = line.trim();
      if (!trimmed || /^content-length:/i.test(trimmed)) return;
      void (async () => {
        try {
          const parsed = JSON.parse(trimmed) as JsonRpcRequest | JsonRpcRequest[];
          if (Array.isArray(parsed)) {
            const responses = (
              await Promise.all(parsed.map((item) => this.handleJsonRpc(item)))
            ).filter((r): r is JsonRpcResponse => r !== null);
            if (responses.length > 0) {
              output.write(`${JSON.stringify(responses)}\n`);
            }
          } else {
            const resp = await this.handleJsonRpc(parsed);
            if (resp !== null) {
              output.write(`${JSON.stringify(resp)}\n`);
            }
          }
        } catch {
          const errResp: JsonRpcResponse = {
            jsonrpc: '2.0',
            id: null,
            error: { code: -32700, message: 'Parse error' },
          };
          output.write(`${JSON.stringify(errResp)}\n`);
        }
      })();
    });

    return {
      close: () => rl.close(),
    };
  }

  /**
   * Starts Streamable HTTP MCP server (`POST /mcp` and `GET /healthz`).
   */
  async startHttp(opts?: {
    port?: number;
    host?: string;
  }): Promise<{ server: http.Server; port: number; host: string; close: () => Promise<void> }> {
    const port = opts?.port ?? 3847;
    const host = opts?.host ?? '127.0.0.1';
    const sessions = new Set<string>();

    const httpServer = http.createServer((req, res) => {
      const urlObj = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

      if (req.method === 'GET' && urlObj.pathname === '/healthz') {
        const body = JSON.stringify({
          ok: true,
          service: SERVER_NAME,
          version: SERVER_VERSION,
        });
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        res.end(body);
        return;
      }

      if (urlObj.pathname === '/mcp') {
        if (req.method === 'DELETE') {
          const sid = req.headers['mcp-session-id'];
          if (typeof sid === 'string') sessions.delete(sid);
          res.writeHead(204);
          res.end();
          return;
        }

        if (req.method !== 'POST') {
          res.writeHead(405, {
            Allow: 'POST, DELETE',
            'Content-Type': 'application/json; charset=utf-8',
          });
          res.end(JSON.stringify({ error: 'Method Not Allowed; use POST /mcp' }));
          return;
        }

        const chunks: Buffer[] = [];
        let total = 0;
        const maxBody = 2 * 1024 * 1024;
        let aborted = false;

        req.on('data', (chunk: Buffer) => {
          total += chunk.length;
          if (total > maxBody) {
            aborted = true;
            res.writeHead(413, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ error: 'Payload too large' }));
            req.destroy();
            return;
          }
          chunks.push(chunk);
        });

        req.on('end', () => {
          if (aborted) return;
          void (async () => {
            const rawText = Buffer.concat(chunks).toString('utf8').trim();
            let parsed: JsonRpcRequest | JsonRpcRequest[];
            try {
              parsed = JSON.parse(rawText) as JsonRpcRequest | JsonRpcRequest[];
            } catch {
              res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
              res.end(
                JSON.stringify({
                  jsonrpc: '2.0',
                  id: null,
                  error: { code: -32700, message: 'Parse error' },
                }),
              );
              return;
            }

            let sessionId =
              typeof req.headers['mcp-session-id'] === 'string'
                ? req.headers['mcp-session-id']
                : undefined;

            const isInit = !Array.isArray(parsed) && parsed.method === 'initialize';
            if (isInit && !sessionId) {
              sessionId = crypto.randomUUID();
              sessions.add(sessionId);
            }

            const baseHeaders: Record<string, string> = {
              'Cache-Control': 'no-store',
            };
            if (sessionId) {
              baseHeaders['Mcp-Session-Id'] = sessionId;
            }

            if (Array.isArray(parsed)) {
              const responses = (
                await Promise.all(parsed.map((item) => this.handleJsonRpc(item)))
              ).filter((r): r is JsonRpcResponse => r !== null);
              if (responses.length === 0) {
                res.writeHead(202, baseHeaders);
                res.end();
                return;
              }
              res.writeHead(200, {
                ...baseHeaders,
                'Content-Type': 'application/json; charset=utf-8',
              });
              res.end(JSON.stringify(responses));
              return;
            }

            const response = await this.handleJsonRpc(parsed);
            if (response === null) {
              res.writeHead(202, baseHeaders);
              res.end();
              return;
            }

            res.writeHead(200, {
              ...baseHeaders,
              'Content-Type': 'application/json; charset=utf-8',
            });
            res.end(JSON.stringify(response));
          })();
        });
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'Not Found' }));
    });

    await new Promise<void>((resolve, reject) => {
      httpServer.once('error', reject);
      httpServer.listen(port, host, () => {
        httpServer.removeListener('error', reject);
        resolve();
      });
    });

    const addr = httpServer.address();
    const boundPort = typeof addr === 'object' && addr ? addr.port : port;

    return {
      server: httpServer,
      port: boundPort,
      host,
      close: () =>
        new Promise<void>((resolve, reject) => {
          httpServer.close((err) => (err ? reject(err) : resolve()));
        }),
    };
  }
}

export function createLastPassMcpServer(deps?: LastPassMcpServerDeps): LastPassMcpServer {
  return new LastPassMcpServer(deps);
}
