import fs from 'node:fs';
import net from 'node:net';
import {
  generateTotpCode,
  sanitizeAccountMetadata,
  scrubError,
} from './scrub.js';
import { matchVaultEntry } from './lpass-cli.js';
import type {
  AutofillResult,
  VaultCredential,
  VaultEntryMetadata,
  ZapBrowserStatus,
} from './types.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

function putU16(arr: number[], n: number): void {
  arr.push(n & 0xff, (n >> 8) & 0xff);
}

function putU32(arr: number[], n: number): void {
  arr.push(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
}

function putStr(arr: number[], s: string): void {
  const bytes = enc.encode(s);
  putU16(arr, bytes.length);
  for (let i = 0; i < bytes.length; i++) arr.push(bytes[i]);
}

export function encodeZapHello(role: number, brand: string, caps: ReadonlyArray<string>): Uint8Array {
  const arr: number[] = [role & 0xff];
  putStr(arr, brand);
  putU16(arr, caps.length);
  for (const c of caps) putStr(arr, c);
  putU16(arr, 0); // 0 attrs
  return new Uint8Array(arr);
}

export function encodeZapCmd(method: string, params: Record<string, unknown> = {}): Uint8Array {
  const arr: number[] = [];
  putStr(arr, method);
  const keys = Object.keys(params).filter((k) => params[k] !== undefined);
  putU16(arr, keys.length);
  for (const k of keys) {
    putStr(arr, k);
    const val = params[k];
    const vb = enc.encode(typeof val === 'string' ? val : JSON.stringify(val));
    putU32(arr, vb.length);
    for (let i = 0; i < vb.length; i++) arr.push(vb[i]);
  }
  return new Uint8Array(arr);
}

export function decodeZapCmd(payload: Uint8Array): {
  method: string;
  params: Record<string, unknown>;
} {
  const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  let o = 0;
  const readStr = () => {
    const len = dv.getUint16(o, true);
    o += 2;
    const s = dec.decode(payload.subarray(o, o + len));
    o += len;
    return s;
  };
  const method = readStr();
  const count = dv.getUint16(o, true);
  o += 2;
  const params: Record<string, unknown> = {};
  for (let i = 0; i < count; i++) {
    const key = readStr();
    const vLen = dv.getUint32(o, true);
    o += 4;
    const rawText = dec.decode(payload.subarray(o, o + vLen));
    o += vLen;
    try {
      params[key] = JSON.parse(rawText);
    } catch {
      params[key] = rawText;
    }
  }
  return { method, params };
}

export function encodeZapFrame(
  frameType: number,
  from: string,
  to: string,
  payload: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const f = enc.encode(from);
  const d = enc.encode(to);
  const len = 11 + f.length + d.length + payload.length;
  const out = new Uint8Array(4 + len);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, len, true);
  dv.setUint8(4, frameType);
  dv.setUint16(5, 0, true);
  dv.setUint16(7, f.length, true);
  dv.setUint16(9, d.length, true);
  dv.setUint32(11, payload.length, true);
  out.set(f, 15);
  out.set(d, 15 + f.length);
  out.set(payload, 15 + f.length + d.length);
  return out;
}

export interface ZapProviderInfo {
  id: string;
  role: number;
  brand: string;
  caps: string[];
  attrs: Record<string, string>;
}

export function decodeZapProviders(payload: Uint8Array): ZapProviderInfo[] {
  const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  let o = 0;
  const str = () => {
    const n = dv.getUint16(o, true);
    o += 2;
    const s = dec.decode(payload.subarray(o, o + n));
    o += n;
    return s;
  };
  const count = dv.getUint16(o, true);
  o += 2;
  const providers: ZapProviderInfo[] = [];
  for (let i = 0; i < count; i++) {
    const id = str();
    const role = dv.getUint8(o);
    o += 1;
    const brand = str();
    const nc = dv.getUint16(o, true);
    o += 2;
    const caps: string[] = [];
    for (let c = 0; c < nc; c++) caps.push(str());
    const na = dv.getUint16(o, true);
    o += 2;
    const attrs: Record<string, string> = {};
    for (let j = 0; j < na; j++) {
      const k = str();
      attrs[k] = str();
    }
    providers.push({ id, role, brand, caps, attrs });
  }
  return providers;
}

export function defaultZapSocketPath(): string {
  if (process.env.HANZO_ZAP_SOCKET) return process.env.HANZO_ZAP_SOCKET;
  const runtimeDir =
    process.env.XDG_RUNTIME_DIR || `/run/user/${process.getuid?.() ?? 1000}`;
  return `${runtimeDir}/zap/zapd.sock`;
}

const LASTPASS_AUTH_COOKIE_PATTERNS = [
  /^PHPSESSID$/i,
  /^LPVID$/i,
  /^LPSESS/i,
  /^lastpass/i,
  /^__Host-LP/i,
];

export interface ZapClientOptions {
  socketPath?: string;
  providerId?: string;
  timeoutMs?: number;
}

/**
 * Local ZAP router client (`/run/user/$UID/zap/zapd.sock`) speaking the native
 * binary ZAP wire protocol to the user's connected Chrome extension.
 */
export class ZapBrowserClient {
  private readonly socketPath: string;
  private readonly explicitProviderId?: string;
  private readonly timeoutMs: number;

  constructor(opts: ZapClientOptions = {}) {
    this.socketPath = opts.socketPath ?? defaultZapSocketPath();
    this.explicitProviderId = opts.providerId ?? process.env.HANZO_ZAP_PROVIDER;
    this.timeoutMs = opts.timeoutMs ?? 8_000;
  }

  getSocketPath(): string {
    return this.socketPath;
  }

  isSocketPresent(): boolean {
    try {
      return fs.existsSync(this.socketPath);
    } catch {
      return false;
    }
  }

  async listProviders(): Promise<ZapProviderInfo[]> {
    if (!this.isSocketPresent()) return [];
    return new Promise((resolve, reject) => {
      const sock = net.createConnection(this.socketPath);
      let buf = Buffer.alloc(0);
      let myId = `agent/lastpass-mcp-${Math.random().toString(16).slice(2, 8)}`;
      const timer = setTimeout(() => {
        sock.destroy();
        reject(new Error('ZAP provider discovery timed out'));
      }, this.timeoutMs);

      sock.on('connect', () => {
        sock.write(encodeZapFrame(1, myId, '', encodeZapHello(0, 'hanzo', [])));
      });

      sock.on('data', (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 4) {
          const len = buf.readUInt32LE(0);
          if (buf.length < 4 + len) break;
          const raw = new Uint8Array(buf.subarray(0, 4 + len));
          buf = buf.subarray(4 + len);
          const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
          const t = dv.getUint8(4);
          const fl = dv.getUint16(7, true);
          const tl = dv.getUint16(9, true);
          const pl = dv.getUint32(11, true);
          const to = dec.decode(raw.subarray(15 + fl, 15 + fl + tl));
          const payload = raw.slice(15 + fl + tl, 15 + fl + tl + pl);

          if (t === 2) {
            myId = to || myId;
            sock.write(encodeZapFrame(3, myId, ''));
          } else if (t === 4) {
            clearTimeout(timer);
            sock.destroy();
            resolve(decodeZapProviders(payload));
            return;
          } else if (t === 7) {
            clearTimeout(timer);
            sock.destroy();
            reject(new Error(dec.decode(payload)));
            return;
          }
        }
      });

      sock.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  async callBrowserMethod(
    method: string,
    params: Record<string, unknown> = {},
    secretsToScrubOnError: ReadonlyArray<string | undefined> = [],
  ): Promise<unknown> {
    if (!this.isSocketPresent()) {
      throw new Error(`ZAP socket not found at ${this.socketPath}`);
    }

    return new Promise((resolve, reject) => {
      const sock = net.createConnection(this.socketPath);
      let buf = Buffer.alloc(0);
      let myId = `agent/lastpass-mcp-${Math.random().toString(16).slice(2, 8)}`;
      const timer = setTimeout(() => {
        sock.destroy();
        reject(new Error(`ZAP call '${method}' timed out`));
      }, this.timeoutMs);

      sock.on('connect', () => {
        sock.write(encodeZapFrame(1, myId, '', encodeZapHello(0, 'hanzo', [])));
      });

      sock.on('data', (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 4) {
          const len = buf.readUInt32LE(0);
          if (buf.length < 4 + len) break;
          const raw = new Uint8Array(buf.subarray(0, 4 + len));
          buf = buf.subarray(4 + len);
          const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
          const t = dv.getUint8(4);
          const fl = dv.getUint16(7, true);
          const tl = dv.getUint16(9, true);
          const pl = dv.getUint32(11, true);
          const to = dec.decode(raw.subarray(15 + fl, 15 + fl + tl));
          const payload = raw.slice(15 + fl + tl, 15 + fl + tl + pl);

          if (t === 2) {
            myId = to || myId;
            sock.write(encodeZapFrame(3, myId, ''));
          } else if (t === 4) {
            const providers = decodeZapProviders(payload);
            const target = this.explicitProviderId
              ? providers.find((p) => p.id === this.explicitProviderId)
              : providers.find((p) => p.id.startsWith('browser/'));
            if (!target) {
              clearTimeout(timer);
              sock.destroy();
              reject(new Error('No connected browser provider on ZAP router'));
              return;
            }
            sock.write(encodeZapFrame(16, myId, target.id, encodeZapCmd(method, params)));
          } else if (t === 17) {
            clearTimeout(timer);
            sock.destroy();
            const text = dec.decode(payload);
            try {
              resolve(JSON.parse(text));
            } catch {
              resolve(text);
            }
            return;
          } else if (t === 7) {
            clearTimeout(timer);
            sock.destroy();
            reject(scrubError(new Error(dec.decode(payload)), secretsToScrubOnError));
            return;
          }
        }
      });

      sock.on('error', (err) => {
        clearTimeout(timer);
        reject(scrubError(err, secretsToScrubOnError));
      });
    });
  }

  /**
   * Probes `lastpass.com` session state via `hanzo.getCookies`, retaining ONLY
   * cookie names and immediately discarding any cookie values in memory.
   */
  async probeStatus(): Promise<ZapBrowserStatus> {
    const socketPresent = this.isSocketPresent();
    if (!socketPresent) {
      return {
        socketPath: this.socketPath,
        socketPresent: false,
        browserConnected: false,
        providerId: null,
        lastpassSessionPresent: false,
        cookieNames: [],
      };
    }

    let browserProvider: ZapProviderInfo | undefined;
    try {
      const providers = await this.listProviders();
      browserProvider = this.explicitProviderId
        ? providers.find((p) => p.id === this.explicitProviderId)
        : providers.find((p) => p.id.startsWith('browser/'));
    } catch {
      return {
        socketPath: this.socketPath,
        socketPresent: true,
        browserConnected: false,
        providerId: null,
        lastpassSessionPresent: false,
        cookieNames: [],
      };
    }

    if (!browserProvider) {
      return {
        socketPath: this.socketPath,
        socketPresent: true,
        browserConnected: false,
        providerId: null,
        lastpassSessionPresent: false,
        cookieNames: [],
      };
    }

    try {
      const rawCookies = await this.callBrowserMethod('hanzo.getCookies', {
        domain: 'lastpass.com',
        url: 'https://lastpass.com/',
      });
      const list: Array<{ name?: unknown }> = Array.isArray(rawCookies)
        ? rawCookies
        : rawCookies &&
            typeof rawCookies === 'object' &&
            Array.isArray((rawCookies as { cookies?: unknown }).cookies)
          ? ((rawCookies as { cookies: Array<{ name?: unknown }> }).cookies)
          : [];

      // Extract ONLY cookie names — never retain or return cookie values!
      const cookieNames = Array.from(
        new Set(
          list
            .map((c) => (typeof c?.name === 'string' ? c.name.trim() : ''))
            .filter(Boolean),
        ),
      ).sort();

      const lastpassSessionPresent = cookieNames.some((n) =>
        LASTPASS_AUTH_COOKIE_PATTERNS.some((rx) => rx.test(n)),
      );

      return {
        socketPath: this.socketPath,
        socketPresent: true,
        browserConnected: true,
        providerId: browserProvider.id,
        lastpassSessionPresent,
        cookieNames,
      };
    } catch {
      return {
        socketPath: this.socketPath,
        socketPresent: true,
        browserConnected: true,
        providerId: browserProvider.id,
        lastpassSessionPresent: false,
        cookieNames: [],
      };
    }
  }

  /**
   * Opens `https://lastpass.com/?ac=1` directly in the user's connected Chrome
   * over ZAP so the user signs in locally inside their own browser session.
   */
  async openVaultLoginTab(loginUrl = 'https://lastpass.com/?ac=1'): Promise<{
    opened: boolean;
    tabId?: string | number;
  }> {
    try {
      const res = (await this.callBrowserMethod('hanzo.open', {
        url: loginUrl,
        active: true,
      })) as { tabId?: string | number; id?: string | number } | null;
      return { opened: true, tabId: res?.tabId ?? res?.id };
    } catch {
      const res = (await this.callBrowserMethod('Target.createTarget', {
        url: loginUrl,
      })) as { targetId?: string } | null;
      return { opened: true, tabId: res?.targetId };
    }
  }

  /**
   * Queries `lastpass.accounts` on the connected Chrome ZAP provider and
   * strictly strips all secret fields before returning.
   */
  async listAccountsMetadata(filter?: {
    query?: string;
    url?: string;
    name?: string;
    username?: string;
  }): Promise<VaultEntryMetadata[]> {
    const raw = await this.callBrowserMethod('lastpass.accounts', {
      query: filter?.query || '',
    });
    const list: Array<Record<string, unknown>> = Array.isArray(raw)
      ? raw
      : raw &&
          typeof raw === 'object' &&
          Array.isArray((raw as { accounts?: unknown }).accounts)
        ? ((raw as { accounts: Array<Record<string, unknown>> }).accounts)
        : [];

    return list
      .map((item) => sanitizeAccountMetadata(item))
      .filter((meta) => (filter ? matchVaultEntry(meta, filter) : true));
  }

  /**
   * Fills `username`, `password`, and optional RFC 6238 `totp` directly into
   * the open browser tab over ZAP (`hanzo.act` `op: "fill"`), returning ONLY
   * non-secret metadata (`{ filled, account, fieldsFilled }`).
   */
  async autofillCredentialInTab(
    cred: VaultCredential,
    opts?: {
      tabId?: string | number;
      usernameSelector?: string;
      passwordSelector?: string;
      totpSelector?: string;
      timestampMs?: number;
    },
  ): Promise<AutofillResult> {
    const fieldsFilled: Array<'username' | 'password' | 'totp'> = [];
    let totpCode: string | undefined;
    if (cred.totpSecret) {
      totpCode = generateTotpCode(cred.totpSecret, opts?.timestampMs);
    }

    const secretsToScrub = [cred.password, cred.totpSecret, totpCode, cred.note];

    const usernameSelector =
      opts?.usernameSelector ||
      'input[autocomplete="username"], input[type="email"], input[name*="user" i], input[name*="email" i], input[name*="login" i], input[id*="user" i]';
    const passwordSelector =
      opts?.passwordSelector ||
      'input[autocomplete="current-password"], input[type="password"], input[name*="pass" i]';
    const totpSelector =
      opts?.totpSelector ||
      'input[autocomplete="one-time-code"], input[name*="totp" i], input[name*="otp" i], input[name*="code" i], input[name*="2fa" i]';

    try {
      if (cred.username) {
        await this.callBrowserMethod(
          'hanzo.act',
          {
            op: 'fill',
            ...(opts?.tabId !== undefined ? { tabId: opts.tabId } : {}),
            selector: usernameSelector,
            value: cred.username,
          },
          secretsToScrub,
        );
        fieldsFilled.push('username');
      }

      if (cred.password) {
        await this.callBrowserMethod(
          'hanzo.act',
          {
            op: 'fill',
            ...(opts?.tabId !== undefined ? { tabId: opts.tabId } : {}),
            selector: passwordSelector,
            value: cred.password,
          },
          secretsToScrub,
        );
        fieldsFilled.push('password');
      }

      if (totpCode) {
        try {
          await this.callBrowserMethod(
            'hanzo.act',
            {
              op: 'fill',
              ...(opts?.tabId !== undefined ? { tabId: opts.tabId } : {}),
              selector: totpSelector,
              value: totpCode,
            },
            secretsToScrub,
          );
          fieldsFilled.push('totp');
        } catch {
          // Page may not currently display a TOTP input step; username/password succeeded.
        }
      }

      return {
        filled: fieldsFilled.length > 0,
        account: {
          id: cred.id,
          name: cred.name,
          username: cred.username,
          url: cred.url,
        },
        fieldsFilled,
        via: 'zap_act_fill',
        ...(opts?.tabId !== undefined ? { tabId: opts.tabId } : {}),
      };
    } catch (err) {
      throw scrubError(err, secretsToScrub, cred.username);
    }
  }

  /**
   * Delegates autofill to the signed-in `https://lastpass.com` Chrome vault tab
   * via `lastpass.fill` when `lpass` CLI has no local vault session, returning
   * ONLY stripped `{ filled, account, fieldsFilled }`.
   */
  async autofillViaBrowserVault(params: {
    url?: string;
    name?: string;
    username?: string;
    tabId?: string | number;
  }): Promise<AutofillResult> {
    const raw = (await this.callBrowserMethod('lastpass.fill', {
      ...(params.url ? { url: params.url } : {}),
      ...(params.name ? { name: params.name } : {}),
      ...(params.username ? { username: params.username } : {}),
      ...(params.tabId !== undefined ? { tabId: params.tabId } : {}),
    })) as Record<string, unknown> | null;

    if (!raw || typeof raw !== 'object') {
      throw new Error('lastpass.fill returned an empty response from browser provider');
    }

    const acctRaw =
      raw.account && typeof raw.account === 'object'
        ? (raw.account as Record<string, unknown>)
        : raw;
    const safeAcct = sanitizeAccountMetadata(acctRaw);

    const allowedFields = new Set(['username', 'password', 'totp']);
    const fieldsFilled = Array.isArray(raw.fieldsFilled)
      ? raw.fieldsFilled.filter(
          (f): f is 'username' | 'password' | 'totp' =>
            typeof f === 'string' && allowedFields.has(f),
        )
      : (['username', 'password'] as Array<'username' | 'password'>);

    return {
      filled: Boolean(raw.filled ?? true),
      account: {
        id: safeAcct.id,
        name: safeAcct.name,
        username: safeAcct.username,
        url: safeAcct.url,
      },
      fieldsFilled,
      via: 'zap_lastpass_fill',
      ...(params.tabId !== undefined ? { tabId: params.tabId } : {}),
    };
  }
}
