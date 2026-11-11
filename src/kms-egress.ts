import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {
  defaultExecFileRunner,
  type ExecFileRunner,
} from './lpass-cli.js';
import {
  redactSecrets,
  scrubError,
  scrubHeaders,
  toKmsSlug,
} from './scrub.js';
import type {
  EgressFetchResult,
  EgressStatus,
  KmsHealthStatus,
  SealedItemSummary,
  SealToKmsResult,
  VaultCredential,
} from './types.js';

const FORBIDDEN_HANZO_PATH = '/usr/bin/hanzo';
const MAX_RESPONSE_BODY_BYTES = 1 << 20; // 1 MiB, matching `mostBody` in hanzoai/egress/fetch.go

const ALLOWED_HTTP_METHODS = new Set([
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
]);

/**
 * Resolves `~/.local/bin/hanzo` exclusively (NEVER `/usr/bin/hanzo`).
 */
export function resolveHanzoCliPath(overridePath?: string): string {
  const candidate =
    overridePath || path.join(os.homedir(), '.local', 'bin', 'hanzo');
  const resolved = path.resolve(candidate);
  if (resolved === FORBIDDEN_HANZO_PATH) {
    throw new Error(
      'Refusing /usr/bin/hanzo; Hanzo KMS operations require ~/.local/bin/hanzo',
    );
  }
  return resolved;
}

function isExecutableFile(filePath: string): boolean {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validates rooted API paths for `hanzoai/egress` `/v1/fetch`, matching
 * `rooted()` in `egress/fetch.go`.
 */
export function validateRootedPath(apiPath: string): void {
  if (!apiPath.startsWith('/') || apiPath.startsWith('//')) {
    throw new Error('path must begin with a single /');
  }
  if (apiPath.includes('\\')) {
    throw new Error('path must not contain a backslash');
  }
}

function isPrivateOrReservedIp(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split('.').map((n) => Number.parseInt(n, 10));
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // Cloud metadata 169.254.169.254
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    return false;
  }
  if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // ULA fc00::/7
    if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) {
      return true; // Link-local fe80::/10
    }
    if (lower.startsWith('::ffff:')) {
      return isPrivateOrReservedIp(lower.slice('::ffff:'.length));
    }
  }
  return false;
}

export function validateCustodiedTargetUrl(
  rawUrl: string,
  allowLoopbackHttp = false,
): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('Invalid targetUrl');
  }

  if (parsed.username || parsed.password) {
    throw new Error('targetUrl must not embed credentials');
  }

  const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const isLoopback = host === '127.0.0.1' || host === 'localhost' || host === '::1';

  if (allowLoopbackHttp && isLoopback) {
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('Unsupported URL scheme');
    }
    return parsed;
  }

  if (parsed.protocol !== 'https:') {
    throw new Error('Custodied outbound fetch requires an https:// URL');
  }

  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.internal') ||
    host === 'metadata.google.internal'
  ) {
    throw new Error('Refusing non-public target hostname');
  }

  if (net.isIP(host) && isPrivateOrReservedIp(host)) {
    throw new Error('Refusing private, loopback, or metadata IP target');
  }

  return parsed;
}

export interface KmsEgressBridgeOptions {
  hanzoBinPath?: string;
  egressUrl?: string;
  runner?: ExecFileRunner;
  fetchImpl?: typeof fetch;
  allowLoopbackHttpForTests?: boolean;
}

export class KmsEgressBridge {
  private readonly hanzoBinPath: string;
  private readonly egressUrl: string | null;
  private readonly runner: ExecFileRunner;
  private readonly fetchImpl: typeof fetch;
  private readonly allowLoopbackHttpForTests: boolean;

  constructor(opts: KmsEgressBridgeOptions = {}) {
    this.hanzoBinPath = resolveHanzoCliPath(opts.hanzoBinPath);
    const configuredUrl = (opts.egressUrl ?? process.env.HANZO_EGRESS_URL ?? '').trim();
    this.egressUrl = configuredUrl ? configuredUrl.replace(/\/+$/, '') : null;
    this.runner = opts.runner ?? defaultExecFileRunner;
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch;
    this.allowLoopbackHttpForTests = Boolean(opts.allowLoopbackHttpForTests);
  }

  getEgressStatus(): EgressStatus {
    return {
      configured: Boolean(this.egressUrl),
      url: this.egressUrl,
    };
  }

  async checkKmsHealth(asOrg?: string): Promise<KmsHealthStatus> {
    const present = isExecutableFile(this.hanzoBinPath);
    if (!present) {
      return {
        hanzoBinPath: this.hanzoBinPath,
        hanzoBinPresent: false,
        healthy: false,
        detail: `${this.hanzoBinPath} not found or not executable`,
      };
    }

    const args: string[] = [];
    if (asOrg) args.push('--as', asOrg);
    args.push('kms', 'health');

    try {
      const res = await this.runner(this.hanzoBinPath, args, { timeoutMs: 8_000 });
      const detail = (res.stdout.trim() || res.stderr.trim() || `exit ${res.exitCode}`).slice(
        0,
        240,
      );
      return {
        hanzoBinPath: this.hanzoBinPath,
        hanzoBinPresent: true,
        healthy: res.exitCode === 0,
        detail,
      };
    } catch (err) {
      return {
        hanzoBinPath: this.hanzoBinPath,
        hanzoBinPresent: true,
        healthy: false,
        detail: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private async putKmsSecret(params: {
    kmsPath: string;
    name: 'USERNAME' | 'PASSWORD' | 'URL' | 'TOTP_SECRET';
    value: string;
    env?: string;
    asOrg?: string;
    secretsToScrub: ReadonlyArray<string | undefined>;
  }): Promise<void> {
    const args: string[] = [];
    if (params.asOrg) {
      args.push('--as', params.asOrg);
    }
    args.push('kms', 'secrets', 'create');
    if (params.env) {
      args.push('--env', params.env);
    }
    args.push('--path', params.kmsPath, '--name', params.name, '--value', params.value);

    try {
      const res = await this.runner(this.hanzoBinPath, args, { timeoutMs: 12_000 });
      if (res.exitCode !== 0) {
        throw new Error(
          res.stderr.trim() ||
            res.stdout.trim() ||
            `hanzo kms secrets create exited with ${res.exitCode}`,
        );
      }
    } catch (err) {
      throw scrubError(err, params.secretsToScrub);
    }
  }

  /**
   * Seals one or more in-memory LastPass credentials into Hanzo KMS at:
   *   `credentials/<slug>/USERNAME`
   *   `credentials/<slug>/PASSWORD`
   *   `credentials/<slug>/URL`
   *   `credentials/<slug>/TOTP_SECRET` (when present)
   *
   * Never returns any secret value!
   */
  async sealCredentialsToKms(
    credentials: ReadonlyArray<VaultCredential>,
    opts?: {
      slugOverride?: string;
      pathPrefix?: string;
      env?: string;
      asOrg?: string;
      enrollInEgress?: boolean;
      egressProvider?: string;
      egressLabel?: string;
      iamToken?: string;
    },
  ): Promise<SealToKmsResult> {
    const prefix = (opts?.pathPrefix || 'credentials').replace(/^\/+|\/+$/g, '');
    if (!/^[a-zA-Z0-9/_-]+$/.test(prefix) || prefix.includes('..')) {
      throw new Error('Invalid KMS pathPrefix');
    }

    const items: SealedItemSummary[] = [];

    for (const cred of credentials) {
      const slug = toKmsSlug({
        slug: credentials.length === 1 ? opts?.slugOverride : undefined,
        name: cred.name,
        fullname: cred.fullname,
        url: cred.url,
        id: cred.id,
      });
      const kmsPath = `${prefix}/${slug}`;
      const secretsToScrub = [cred.password, cred.totpSecret, cred.note, opts?.iamToken];
      const keysSealed: Array<'USERNAME' | 'PASSWORD' | 'URL' | 'TOTP_SECRET'> = [];

      if (cred.username) {
        await this.putKmsSecret({
          kmsPath,
          name: 'USERNAME',
          value: cred.username,
          env: opts?.env,
          asOrg: opts?.asOrg,
          secretsToScrub,
        });
        keysSealed.push('USERNAME');
      }

      if (cred.password) {
        await this.putKmsSecret({
          kmsPath,
          name: 'PASSWORD',
          value: cred.password,
          env: opts?.env,
          asOrg: opts?.asOrg,
          secretsToScrub,
        });
        keysSealed.push('PASSWORD');
      }

      if (cred.url) {
        await this.putKmsSecret({
          kmsPath,
          name: 'URL',
          value: cred.url,
          env: opts?.env,
          asOrg: opts?.asOrg,
          secretsToScrub,
        });
        keysSealed.push('URL');
      }

      if (cred.totpSecret) {
        await this.putKmsSecret({
          kmsPath,
          name: 'TOTP_SECRET',
          value: cred.totpSecret,
          env: opts?.env,
          asOrg: opts?.asOrg,
          secretsToScrub,
        });
        keysSealed.push('TOTP_SECRET');
      }

      let egressEnrolled: boolean | undefined;
      if (opts?.enrollInEgress && cred.password) {
        if (!this.egressUrl) {
          throw new Error('HANZO_EGRESS_URL is required when enrollInEgress=true');
        }
        const token = opts.iamToken || process.env.HANZO_IAM_TOKEN || process.env.HANZO_API_KEY;
        if (!token) {
          throw new Error('IAM bearer token is required to enroll a credential in egress');
        }
        const provider = opts.egressProvider || slug;
        const label = opts.egressLabel || 'default';
        try {
          const res = await this.fetchImpl(`${this.egressUrl}/v1/enroll`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({
              provider,
              label,
              key: cred.password,
            }),
            redirect: 'manual',
            signal: AbortSignal.timeout(12_000),
          });
          if (!res.ok) {
            const errBody = await res.text();
            throw new Error(`egress /v1/enroll refused with HTTP ${res.status}: ${errBody}`);
          }
          egressEnrolled = true;
        } catch (err) {
          throw scrubError(err, secretsToScrub, cred.username);
        }
      }

      items.push({
        id: cred.id,
        name: cred.name,
        slug,
        kmsPath,
        keysSealed,
        ...(egressEnrolled !== undefined ? { egressEnrolled } : {}),
      });
    }

    return {
      sealedCount: items.length,
      items,
    };
  }

  /**
   * Mode 1: Delegates outbound call to `hanzoai/egress` (`POST ${HANZO_EGRESS_URL}/v1/fetch`)
   * using the caller's IAM bearer token so Egress spends the KMS-custodied credential.
   */
  async fetchViaEgressBroker(params: {
    provider: string;
    label?: string;
    method: string;
    path: string;
    body?: unknown;
    iamToken?: string;
    egressUrlOverride?: string;
  }): Promise<EgressFetchResult> {
    const baseUrl = (params.egressUrlOverride || this.egressUrl || '').replace(/\/+$/, '');
    if (!baseUrl) {
      throw new Error('HANZO_EGRESS_URL is not configured');
    }

    const token =
      params.iamToken || process.env.HANZO_IAM_TOKEN || process.env.HANZO_API_KEY || '';
    if (!token) {
      throw new Error('Refused: IAM bearer token is required for egress /v1/fetch');
    }

    const method = params.method.trim().toUpperCase();
    if (!ALLOWED_HTTP_METHODS.has(method)) {
      throw new Error(`Unsupported HTTP method: ${method}`);
    }
    validateRootedPath(params.path);

    const payload: Record<string, unknown> = {
      provider: params.provider,
      label: params.label || 'default',
      method,
      path: params.path,
    };
    if (params.body !== undefined) {
      payload.body = params.body;
    }

    const started = Date.now();
    try {
      const res = await this.fetchImpl(`${baseUrl}/v1/fetch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
        redirect: 'manual',
        signal: AbortSignal.timeout(30_000),
      });

      const rawText = await readBoundedText(res, MAX_RESPONSE_BODY_BYTES);
      const cleanText = redactSecrets(rawText, [token]);

      if (!res.ok) {
        throw new Error(`egress /v1/fetch refused (${res.status}): ${cleanText}`);
      }

      const parsed = JSON.parse(cleanText) as {
        status: number;
        body: unknown;
        scope?: string;
        millis?: number;
      };

      return {
        mode: 'egress_broker',
        status: parsed.status,
        body: parsed.body,
        scope: parsed.scope,
        millis: parsed.millis ?? Date.now() - started,
      };
    } catch (err) {
      throw scrubError(err, [token]);
    }
  }

  /**
   * Mode 2: Executes an in-process custodied HTTP request injecting a LastPass
   * secret into an outbound auth header, refusing redirects and scrubbing all
   * raw, base64, basic-auth, and URL-encoded secret representations from
   * status, headers, body, and errors before returning.
   */
  async fetchWithCustodiedCredential(
    cred: VaultCredential,
    params: {
      targetUrl: string;
      method?: string;
      authScheme?: 'bearer' | 'basic' | 'header';
      headerName?: string;
      headers?: Record<string, string>;
      body?: unknown;
    },
  ): Promise<EgressFetchResult> {
    if (!cred.password) {
      throw new Error(`Matched vault item '${cred.name || cred.id}' has an empty secret`);
    }

    const validatedUrl = validateCustodiedTargetUrl(
      params.targetUrl,
      this.allowLoopbackHttpForTests,
    );

    const method = (params.method || 'GET').trim().toUpperCase();
    if (!ALLOWED_HTTP_METHODS.has(method)) {
      throw new Error(`Unsupported HTTP method: ${method}`);
    }

    const outboundHeaders: Record<string, string> = {
      Accept: 'application/json, text/plain;q=0.9, */*;q=0.8',
    };

    const forbiddenCallerHeaders = new Set([
      'authorization',
      'proxy-authorization',
      'cookie',
      'host',
    ]);

    if (params.headers) {
      for (const [k, v] of Object.entries(params.headers)) {
        if (forbiddenCallerHeaders.has(k.toLowerCase())) {
          throw new Error(`Caller may not set restricted header '${k}'`);
        }
        outboundHeaders[k] = String(v);
      }
    }

    const scheme = params.authScheme || 'bearer';
    if (scheme === 'bearer') {
      outboundHeaders['Authorization'] = `Bearer ${cred.password}`;
    } else if (scheme === 'basic') {
      const token = Buffer.from(`${cred.username}:${cred.password}`, 'utf8').toString('base64');
      outboundHeaders['Authorization'] = `Basic ${token}`;
    } else if (scheme === 'header') {
      const hName = (params.headerName || 'X-API-Key').trim();
      if (!/^[A-Za-z0-9-]+$/.test(hName) || forbiddenCallerHeaders.has(hName.toLowerCase())) {
        throw new Error(`Invalid custom auth headerName '${hName}'`);
      }
      outboundHeaders[hName] = cred.password;
    } else {
      throw new Error(`Unsupported authScheme '${String(scheme)}'`);
    }

    let encodedBody: string | undefined;
    if (params.body !== undefined && method !== 'GET' && method !== 'HEAD') {
      if (typeof params.body === 'string') {
        encodedBody = params.body;
      } else {
        encodedBody = JSON.stringify(params.body);
        if (!outboundHeaders['Content-Type'] && !outboundHeaders['content-type']) {
          outboundHeaders['Content-Type'] = 'application/json';
        }
      }
    }

    const secretsToScrub = [cred.password, cred.totpSecret, cred.note];
    const started = Date.now();

    try {
      const res = await this.fetchImpl(validatedUrl.toString(), {
        method,
        headers: outboundHeaders,
        ...(encodedBody !== undefined ? { body: encodedBody } : {}),
        redirect: 'manual', // Never follow redirects carrying a custodied secret!
        signal: AbortSignal.timeout(30_000),
      });

      const rawText = await readBoundedText(res, MAX_RESPONSE_BODY_BYTES);
      const scrubbedText = redactSecrets(rawText, secretsToScrub, {
        username: cred.username,
      });
      const scrubbedHeaders = scrubHeaders(res.headers.entries(), secretsToScrub, cred.username);

      let parsedBody: unknown = scrubbedText;
      const trimmed = scrubbedText.trim();
      if (!trimmed) {
        parsedBody = null;
      } else {
        try {
          parsedBody = JSON.parse(trimmed);
        } catch {
          parsedBody = scrubbedText;
        }
      }

      return {
        mode: 'custodied_in_process',
        status: res.status,
        headers: scrubbedHeaders,
        body: parsedBody,
        millis: Date.now() - started,
        account: {
          id: cred.id,
          name: cred.name,
          username: cred.username,
          url: cred.url,
        },
      };
    } catch (err) {
      throw scrubError(err, secretsToScrub, cred.username);
    }
  }
}

async function readBoundedText(res: Response, maxBytes: number): Promise<string> {
  if (!res.body) {
    const text = await res.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
      throw new Error(`Upstream response exceeded ${maxBytes} bytes`);
    }
    return text;
  }

  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error(`Upstream response exceeded ${maxBytes} bytes`);
      }
      chunks.push(value);
    }
  }

  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}
