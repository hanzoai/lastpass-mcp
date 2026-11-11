import crypto from 'node:crypto';
import type { VaultCredential, VaultCustomField, VaultEntryMetadata } from './types.js';

const INSPECT_CUSTOM = Symbol.for('nodejs.util.inspect.custom');

/**
 * Shortest shared substring length scrubbed from error messages, matching
 * `const span = 4` in `hanzoai/egress/call.go`.
 */
export const ERROR_SCRUB_SPAN = 4;

/**
 * Wraps an internal VaultCredential so accidental `JSON.stringify` or
 * `util.inspect` only ever emits stripped metadata.
 */
export function guardCredential(cred: VaultCredential): VaultCredential {
  const safeMeta = sanitizeAccountMetadata(cred);
  const guarded: VaultCredential = {
    ...safeMeta,
    password: cred.password,
    note: cred.note,
    totpSecret: cred.totpSecret,
    fields: cred.fields,
  };
  Object.defineProperty(guarded, 'toJSON', {
    value: () => safeMeta,
    enumerable: false,
  });
  Object.defineProperty(guarded, INSPECT_CUSTOM, {
    value: () => `[CustodiedCredential id=${safeMeta.id} name=${JSON.stringify(safeMeta.name)}]`,
    enumerable: false,
  });
  return guarded;
}

/**
 * Strictly strips passwords, notes, TOTP seeds, custom field values, cookies,
 * and private keys, returning ONLY safe metadata fields.
 */
export function sanitizeAccountMetadata(raw: {
  id?: unknown;
  name?: unknown;
  fullname?: unknown;
  username?: unknown;
  url?: unknown;
  group?: unknown;
  lastModifiedGmt?: unknown;
  last_modified_gmt?: unknown;
  hasTotp?: unknown;
  totp?: unknown;
  totpSecret?: unknown;
  note?: unknown;
  fields?: ReadonlyArray<VaultCustomField>;
}): VaultEntryMetadata {
  const id = typeof raw.id === 'string' || typeof raw.id === 'number' ? String(raw.id) : '';
  const name = typeof raw.name === 'string' ? raw.name : '';
  const group = typeof raw.group === 'string' ? raw.group : '';
  const fullname =
    typeof raw.fullname === 'string' && raw.fullname.length > 0
      ? raw.fullname
      : group
        ? `${group}/${name}`
        : name;
  const username = typeof raw.username === 'string' ? raw.username : '';
  const url = typeof raw.url === 'string' ? raw.url : '';
  const lastModifiedGmt =
    typeof raw.lastModifiedGmt === 'string'
      ? raw.lastModifiedGmt
      : typeof raw.last_modified_gmt === 'string'
        ? raw.last_modified_gmt
        : '';

  const hasTotp =
    typeof raw.hasTotp === 'boolean'
      ? raw.hasTotp
      : Boolean(
          extractTotpSecret(
            typeof raw.totpSecret === 'string'
              ? raw.totpSecret
              : typeof raw.totp === 'string'
                ? raw.totp
                : undefined,
            typeof raw.note === 'string' ? raw.note : undefined,
            raw.fields,
          ),
        );

  return {
    id,
    name,
    fullname,
    username,
    url,
    group,
    lastModifiedGmt,
    hasTotp,
  };
}

/**
 * Produces all wire representations a secret can take when sent upstream
 * (raw, standard Base64, Basic Auth combinations, Base64URL, URL-encoded,
 * form-encoded, JSON-escaped, and hex).
 */
export function secretForms(secret: string, username?: string): string[] {
  if (!secret) return [];
  const set = new Set<string>();
  const add = (v: string) => {
    if (v && v.length > 0) set.add(v);
  };

  add(secret);
  const buf = Buffer.from(secret, 'utf8');
  add(buf.toString('base64'));
  add(buf.toString('base64').replace(/=+$/, ''));
  add(buf.toString('base64url'));
  add(Buffer.from(`${secret}:`, 'utf8').toString('base64'));
  add(Buffer.from(`:${secret}`, 'utf8').toString('base64'));
  if (username) {
    const basic = Buffer.from(`${username}:${secret}`, 'utf8');
    add(basic.toString('base64'));
    add(basic.toString('base64').replace(/=+$/, ''));
    add(basic.toString('base64url'));
  }
  add(encodeURIComponent(secret));
  const formEncoded = new URLSearchParams({ v: secret }).toString().slice(2);
  add(formEncoded);
  const jsonEscaped = JSON.stringify(secret).slice(1, -1);
  add(jsonEscaped);
  if (buf.length >= 4) {
    add(buf.toString('hex'));
    add(buf.toString('hex').toUpperCase());
  }

  return Array.from(set).sort((a, b) => b.length - a.length);
}

/**
 * Shared prefix run length from `text` appearing anywhere in `secret`,
 * directly mirroring `shared()` + `redact()` in `hanzoai/egress/call.go`.
 */
function sharedRunLength(text: string, secret: string): number {
  let n = 0;
  while (n < text.length && secret.includes(text.slice(0, n + 1))) {
    n++;
  }
  return n;
}

/**
 * Redacts all exact representations of `secrets` (raw, base64, URL-encoded,
 * basic-auth, hex, JSON-escaped). When `partialSpan` is provided (used for
 * error strings), also redacts any shared substring of length >= `partialSpan`.
 */
export function redactSecrets(
  text: string,
  secrets: ReadonlyArray<string | undefined>,
  opts?: { username?: string; partialSpan?: number },
): string {
  if (!text) return text;
  const cleanSecrets = secrets.filter((s): s is string => Boolean(s && s.length > 0));
  if (cleanSecrets.length === 0) return text;

  const allForms: string[] = [];
  for (const s of cleanSecrets) {
    for (const f of secretForms(s, opts?.username)) {
      if (!allForms.includes(f)) allForms.push(f);
    }
  }
  allForms.sort((a, b) => b.length - a.length);

  let out = text;
  for (const form of allForms) {
    if (out.includes(form)) {
      out = out.split(form).join('[REDACTED]');
    }
  }

  if (opts?.partialSpan !== undefined && opts.partialSpan > 0) {
    let least = opts.partialSpan;
    for (const s of cleanSecrets) {
      if (s.length < least) least = s.length;
    }
    let built = '';
    for (let i = 0; i < out.length; ) {
      if (out.startsWith('[REDACTED]', i)) {
        built += '[REDACTED]';
        i += '[REDACTED]'.length;
        continue;
      }
      let maxMatch = 0;
      for (const f of allForms) {
        const m = sharedRunLength(out.slice(i), f);
        if (m > maxMatch) maxMatch = m;
      }
      if (maxMatch < least) {
        built += out[i];
        i++;
      } else {
        built += '[REDACTED]';
        i += maxMatch;
      }
    }
    out = built;
  }

  return out;
}

/**
 * Scrubs an Error (message + cause) against any candidate secret material so
 * thrown or returned errors can never quote a password, token, cookie, or TOTP.
 */
export function scrubError(
  err: unknown,
  secrets: ReadonlyArray<string | undefined> = [],
  username?: string,
): Error {
  const rawMessage = err instanceof Error ? err.message : String(err);
  const scrubbed = redactSecrets(rawMessage, secrets, {
    username,
    partialSpan: ERROR_SCRUB_SPAN,
  });
  return new Error(scrubbed);
}

const SENSITIVE_RESPONSE_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
]);

/**
 * Scrubs HTTP response headers to guarantee neither upstream echoed auth
 * headers nor session cookies ever return to an MCP caller.
 */
export function scrubHeaders(
  headers: Iterable<[string, string]> | Record<string, string>,
  secrets: ReadonlyArray<string | undefined>,
  username?: string,
): Record<string, string> {
  const out: Record<string, string> = {};
  const entries =
    Symbol.iterator in Object(headers)
      ? (headers as Iterable<[string, string]>)
      : Object.entries(headers as Record<string, string>);

  for (const [k, v] of entries) {
    const lower = k.toLowerCase();
    if (SENSITIVE_RESPONSE_HEADERS.has(lower)) {
      out[lower] = '[REDACTED]';
    } else {
      out[lower] = redactSecrets(String(v), secrets, { username });
    }
  }
  return out;
}

/**
 * Final outbound backstop run on serialized MCP tool outputs.
 */
export function assertNoSecretLeak(
  serializedJson: string,
  secrets: ReadonlyArray<string | undefined>,
  username?: string,
): string {
  return redactSecrets(serializedJson, secrets, { username });
}

/**
 * Produces a deterministic KMS path segment matching `hanzoai/egress`'s
 * `segment()` allowlist (`[a-z0-9][a-z0-9-_]{0,62}`).
 */
export function toKmsSlug(input: {
  slug?: string;
  name?: string;
  fullname?: string;
  url?: string;
  id?: string;
}): string {
  const candidate =
    input.slug?.trim() ||
    input.name?.trim() ||
    input.fullname?.trim() ||
    (() => {
      if (input.url) {
        try {
          return new URL(input.url).hostname;
        } catch {
          return input.url;
        }
      }
      return '';
    })() ||
    `item-${input.id || 'unknown'}`;

  let cleaned = candidate
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');

  if (!cleaned || !/^[a-z0-9]/.test(cleaned)) {
    cleaned = `item-${cleaned || 'credential'}`;
  }
  if (cleaned.length > 63) {
    cleaned = cleaned.slice(0, 63).replace(/-+$/, '');
  }
  return cleaned;
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function decodeBase32(input: string): Buffer {
  const normalized = input
    .trim()
    .replace(/[\s-]+/g, '')
    .replace(/=+$/, '')
    .toUpperCase();

  if (!normalized) {
    throw new Error('Empty Base32 TOTP secret');
  }

  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (let i = 0; i < normalized.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(normalized[i]);
    if (idx === -1) {
      throw new Error('Invalid Base32 character in TOTP secret');
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

export function isLikelyTotpSecret(candidate: string): boolean {
  const trimmed = candidate.trim();
  if (!trimmed) return false;
  if (/^otpauth:\/\/totp\//i.test(trimmed)) return true;
  const compact = trimmed.replace(/[\s-]+/g, '').replace(/=+$/, '');
  return compact.length >= 16 && compact.length <= 128 && /^[A-Za-z2-7]+$/.test(compact);
}

/**
 * Extracts a TOTP seed from explicit `totp` attribute, custom fields, or
 * structured notes in memory (never returned to callers).
 */
export function extractTotpSecret(
  rawTotp?: string,
  note?: string,
  fields?: ReadonlyArray<VaultCustomField>,
): string | undefined {
  if (rawTotp && isLikelyTotpSecret(rawTotp)) {
    return rawTotp.trim();
  }

  if (fields) {
    for (const f of fields) {
      if (/^(totp|otp|totp[_-]?secret|mfa|two[_-]?factor|authenticator)$/i.test(f.name.trim())) {
        if (isLikelyTotpSecret(f.value)) return f.value.trim();
      }
    }
  }

  if (note) {
    const uriMatch = note.match(/otpauth:\/\/totp\/[^\s\r\n]+/i);
    if (uriMatch) return uriMatch[0];

    const lineMatch = note.match(
      /^(?:totp(?:\s*secret)?|otp|one[- ]time\s*password)\s*:\s*([A-Za-z2-7\s=-]{16,128})$/im,
    );
    if (lineMatch && isLikelyTotpSecret(lineMatch[1])) {
      return lineMatch[1].trim();
    }
  }

  return undefined;
}

/**
 * Generates an RFC 6238 TOTP code in memory exclusively for direct browser
 * autofill over ZAP (`hanzo.act` `op: "fill"`). Never return this value!
 */
export function generateTotpCode(secretOrUri: string, timestampMs: number = Date.now()): string {
  let secret = secretOrUri.trim();
  let digits = 6;
  let period = 30;
  let algorithm: 'sha1' | 'sha256' | 'sha512' = 'sha1';

  if (/^otpauth:\/\/totp\//i.test(secret)) {
    const parsed = new URL(secret);
    const s = parsed.searchParams.get('secret');
    if (!s) {
      throw new Error('otpauth URI is missing secret parameter');
    }
    secret = s;
    const d = Number(parsed.searchParams.get('digits') || '6');
    if (d === 6 || d === 7 || d === 8) digits = d;
    const p = Number(parsed.searchParams.get('period') || '30');
    if (Number.isFinite(p) && p > 0) period = p;
    const alg = (parsed.searchParams.get('algorithm') || 'SHA1').toUpperCase();
    if (alg === 'SHA256') algorithm = 'sha256';
    else if (alg === 'SHA512') algorithm = 'sha512';
  }

  const keyBytes = decodeBase32(secret);
  try {
    const counter = BigInt(Math.floor(timestampMs / 1000 / period));
    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(counter, 0);

    const digest = crypto.createHmac(algorithm, keyBytes).update(counterBuf).digest();
    const offset = digest[digest.length - 1] & 0x0f;
    const binary =
      ((digest[offset] & 0x7f) << 24) |
      ((digest[offset + 1] & 0xff) << 16) |
      ((digest[offset + 2] & 0xff) << 8) |
      (digest[offset + 3] & 0xff);

    const mod = 10 ** digits;
    return String(binary % mod).padStart(digits, '0');
  } finally {
    keyBytes.fill(0);
  }
}
