/**
 * Domain & MCP JSON-RPC types for `@hanzo/lastpass-mcp`.
 *
 * Security law (inherited from `hanzoai/egress`):
 *   NEVER return a credential.
 *   VaultEntryMetadata is the ONLY item shape permitted in MCP responses.
 */

export interface VaultEntryMetadata {
  id: string;
  name: string;
  fullname: string;
  username: string;
  url: string;
  group: string;
  lastModifiedGmt: string;
  hasTotp: boolean;
}

export interface VaultCustomField {
  name: string;
  type: string;
  value: string;
  checked?: boolean;
}

/**
 * Internal-only credential representation held transiently on a single call's
 * stack for autofill, KMS sealing, or custodied outbound fetch.
 * NEVER return or serialize raw fields to callers.
 */
export interface VaultCredential extends VaultEntryMetadata {
  readonly password: string;
  readonly note: string;
  readonly totpSecret?: string;
  readonly fields?: ReadonlyArray<VaultCustomField>;
}

export interface LpassCliStatus {
  available: boolean;
  binPath: string | null;
  version: string | null;
  loggedIn: boolean;
  accountEmail: string | null;
}

export interface ZapBrowserStatus {
  socketPath: string;
  socketPresent: boolean;
  browserConnected: boolean;
  providerId: string | null;
  lastpassSessionPresent: boolean;
  cookieNames: string[];
}

export interface KmsHealthStatus {
  hanzoBinPath: string;
  hanzoBinPresent: boolean;
  healthy: boolean;
  detail: string;
}

export interface EgressStatus {
  configured: boolean;
  url: string | null;
}

export interface LastPassStatusResult {
  lpass: LpassCliStatus;
  zapBrowser: ZapBrowserStatus;
  kms: KmsHealthStatus;
  egress: EgressStatus;
  vaultProtocolReady: boolean;
}

export interface LastPassLoginResult {
  initiated: boolean;
  mode: 'browser_zap' | 'lpass_cli';
  email?: string;
  browserUrl?: string;
  detail: string;
}

export interface AutofillResult {
  filled: true | false;
  account: {
    id: string;
    name: string;
    username: string;
    url: string;
  };
  fieldsFilled: Array<'username' | 'password' | 'totp'>;
  via: 'zap_act_fill' | 'zap_lastpass_fill';
  tabId?: string | number;
}

export interface SealedItemSummary {
  id: string;
  name: string;
  slug: string;
  kmsPath: string;
  keysSealed: Array<'USERNAME' | 'PASSWORD' | 'URL' | 'TOTP_SECRET'>;
  egressEnrolled?: boolean;
}

export interface SealToKmsResult {
  sealedCount: number;
  items: SealedItemSummary[];
}

export interface EgressFetchResult {
  mode: 'egress_broker' | 'custodied_in_process';
  status: number;
  headers?: Record<string, string>;
  body: unknown;
  scope?: string;
  millis: number;
  account?: {
    id: string;
    name: string;
    username: string;
    url: string;
  };
}

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}
