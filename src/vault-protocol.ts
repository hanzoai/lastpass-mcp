import crypto from 'node:crypto';
import {
  extractTotpSecret,
  guardCredential,
  isLikelyTotpSecret,
  sanitizeAccountMetadata,
  scrubError,
} from './scrub.js';
import type { VaultCredential, VaultCustomField, VaultEntryMetadata } from './types.js';

export const KDF_HASH_LEN = 32;
export const MINIMUM_ITERATIONS = 2;
export const CIPHER_MARKER_CBC = 0x21; // '!'
export const CIPHER_MARKER_GCM = 0x23; // '#'
export const AES_BLOCK_SIZE = 16;
export const AES_GCM_IV_LEN = 12;
export const AES_GCM_TAG_LEN = 16;
export const AES_GCM_MIN_LEN = 1 + AES_GCM_IV_LEN + AES_GCM_TAG_LEN;

const LP_PKEY_PREFIX = 'LastPassPrivateKey<';
const LP_PKEY_SUFFIX = '>LastPassPrivateKey';

export type CipherAesMode = 'ecb' | 'cbc' | 'gcm';

interface AesLayout {
  mode: CipherAesMode;
  marker: number;
  ivLen: number;
  minDataLen: number;
  dataMultiple: number;
}

const AES_LAYOUTS: ReadonlyArray<AesLayout> = [
  {
    mode: 'gcm',
    marker: CIPHER_MARKER_GCM,
    ivLen: AES_GCM_IV_LEN,
    minDataLen: AES_GCM_TAG_LEN,
    dataMultiple: 1,
  },
  {
    mode: 'cbc',
    marker: CIPHER_MARKER_CBC,
    ivLen: AES_BLOCK_SIZE,
    minDataLen: AES_BLOCK_SIZE,
    dataMultiple: AES_BLOCK_SIZE,
  },
];

function layoutOfMarker(byte: number): AesLayout | null {
  for (const l of AES_LAYOUTS) {
    if (l.marker === byte) return l;
  }
  return null;
}

export function isCipherMarker(byte: number): boolean {
  return layoutOfMarker(byte) !== null;
}

function layoutFitting(ciphertext: Buffer): AesLayout | null {
  for (const layout of AES_LAYOUTS) {
    const header = 1 + layout.ivLen;
    if (
      ciphertext.length >= header + layout.minDataLen &&
      ciphertext[0] === layout.marker &&
      (ciphertext.length - header) % layout.dataMultiple === 0
    ) {
      return layout;
    }
  }
  return null;
}

/**
 * Derives the 32-byte LastPass vault decryption key using PBKDF2-HMAC-SHA256,
 * matching `kdf_decryption_key` in `c-cli/kdf.c`.
 */
export function deriveDecryptionKey(
  username: string,
  masterPassword: string,
  iterations: number,
): Buffer {
  if (!Number.isInteger(iterations) || iterations < MINIMUM_ITERATIONS) {
    throw new Error(
      `LastPass iteration count (${iterations}) is below minimum (${MINIMUM_ITERATIONS})`,
    );
  }
  const userLower = username.trim().toLowerCase();
  return crypto.pbkdf2Sync(
    Buffer.from(masterPassword, 'utf8'),
    Buffer.from(userLower, 'utf8'),
    iterations,
    KDF_HASH_LEN,
    'sha256',
  );
}

/**
 * Derives the 64-char hex LastPass login hash using 1 additional PBKDF2-SHA256
 * round over the 32-byte decryption key with the password as salt, matching
 * `kdf_login_key` in `c-cli/kdf.c`.
 */
export function deriveLoginHash(
  username: string,
  masterPassword: string,
  iterations: number,
): string {
  const key = deriveDecryptionKey(username, masterPassword, iterations);
  try {
    const loginDigest = crypto.pbkdf2Sync(
      key,
      Buffer.from(masterPassword, 'utf8'),
      1,
      KDF_HASH_LEN,
      'sha256',
    );
    const hex = loginDigest.toString('hex');
    loginDigest.fill(0);
    return hex;
  } finally {
    key.fill(0);
  }
}

function decryptCbc(iv: Buffer, data: Buffer, key: Buffer): string | null {
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const out = Buffer.concat([decipher.update(data), decipher.final()]);
    return out.toString('utf8');
  } catch {
    return null;
  }
}

function decryptEcb(data: Buffer, key: Buffer): string | null {
  if (data.length === 0 || data.length % AES_BLOCK_SIZE !== 0) return null;
  try {
    const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
    const out = Buffer.concat([decipher.update(data), decipher.final()]);
    return out.toString('utf8');
  } catch {
    return null;
  }
}

function decryptGcm(ciphertext: Buffer, key: Buffer): string | null {
  if (ciphertext.length < AES_GCM_MIN_LEN) return null;
  const iv = ciphertext.subarray(1, 1 + AES_GCM_IV_LEN);
  const dataLen = ciphertext.length - AES_GCM_MIN_LEN;
  const data = ciphertext.subarray(1 + AES_GCM_IV_LEN, 1 + AES_GCM_IV_LEN + dataLen);
  const tag = ciphertext.subarray(1 + AES_GCM_IV_LEN + dataLen);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const out = Buffer.concat([decipher.update(data), decipher.final()]);
    return out.toString('utf8');
  } catch {
    return null;
  }
}

/**
 * Decrypts raw binary ciphertexts from a LastPass blob (`!iv+cbc`, `#iv+gcm+tag`,
 * or legacy raw 16*N `ecb` including ECB ciphertexts starting with `!` or `#`).
 */
export function decryptAes256Raw(
  ciphertext: Buffer,
  key: Buffer,
  allowEcb: boolean = true,
): { plaintext: string; mode: CipherAesMode } | null {
  if (key.length !== KDF_HASH_LEN) {
    throw new Error(`Invalid AES-256 key length: expected ${KDF_HASH_LEN}`);
  }
  if (ciphertext.length === 0) {
    return { plaintext: '', mode: 'ecb' };
  }

  const layout = layoutFitting(ciphertext);
  if (layout?.mode === 'gcm') {
    const p = decryptGcm(ciphertext, key);
    if (p !== null) return { plaintext: p, mode: 'gcm' };
  } else if (layout?.mode === 'cbc') {
    const iv = ciphertext.subarray(1, 1 + layout.ivLen);
    const data = ciphertext.subarray(1 + layout.ivLen);
    const p = decryptCbc(iv, data, key);
    if (p !== null) return { plaintext: p, mode: 'cbc' };
  }

  if (allowEcb && ciphertext.length > 0 && ciphertext.length % AES_BLOCK_SIZE === 0) {
    const p = decryptEcb(ciphertext, key);
    if (p !== null) return { plaintext: p, mode: 'ecb' };
  }

  return null;
}

/**
 * Decodes LastPass text-encoded ciphertext (`!b64(iv)|b64(data)`,
 * `#b64(iv)|b64(data+tag)`, or plain `b64(ecb)`).
 */
export function cipherUnbase64(encoded: string): Buffer | null {
  if (!encoded) return null;
  const firstByte = encoded.charCodeAt(0);
  const layout = layoutOfMarker(firstByte);
  if (layout) {
    const rest = encoded.slice(1);
    const pipeIdx = rest.indexOf('|');
    if (pipeIdx <= 0 || pipeIdx === rest.length - 1) return null;
    const ivPart = rest.slice(0, pipeIdx);
    const dataPart = rest.slice(pipeIdx + 1);
    const iv = Buffer.from(ivPart, 'base64');
    const data = Buffer.from(dataPart, 'base64');
    if (iv.length !== layout.ivLen) return null;
    if (data.length < layout.minDataLen || data.length % layout.dataMultiple !== 0) return null;
    return Buffer.concat([Buffer.from([firstByte]), iv, data]);
  }
  const raw = Buffer.from(encoded, 'base64');
  return raw.length > 0 ? raw : null;
}

export function cipherBase64Mode(raw: Buffer, mode: CipherAesMode): string {
  const layout = layoutFitting(raw);
  if (layout && layout.mode === mode) {
    const marker = String.fromCharCode(raw[0]);
    const iv = raw.subarray(1, 1 + layout.ivLen).toString('base64');
    const data = raw.subarray(1 + layout.ivLen).toString('base64');
    return `${marker}${iv}|${data}`;
  }
  return raw.toString('base64');
}

/**
 * Decrypts LastPass base64-formatted ciphertexts (`!iv|ct`, `#iv|ct`, or `ecb`),
 * matching `cipher_aes_decrypt_base64` in `c-cli/cipher.c`.
 */
export function decryptAes256Base64(encoded: string, key: Buffer): string | null {
  if (!encoded) return '';
  const raw = cipherUnbase64(encoded);
  if (!raw) return null;
  const hasExplicitMarker = isCipherMarker(encoded.charCodeAt(0));
  const res = decryptAes256Raw(raw, key, !hasExplicitMarker);
  return res ? res.plaintext : null;
}

/**
 * Encrypts UTF-8 plaintext into LastPass binary CBC format (`'!' + 16B IV + ct`).
 */
export function encryptAes256CbcRaw(plaintext: string, key: Buffer, iv?: Buffer): Buffer {
  if (key.length !== KDF_HASH_LEN) {
    throw new Error(`Invalid AES-256 key length: expected ${KDF_HASH_LEN}`);
  }
  if (!plaintext) return Buffer.alloc(0);
  const actualIv = iv ?? crypto.randomBytes(AES_BLOCK_SIZE);
  if (actualIv.length !== AES_BLOCK_SIZE) {
    throw new Error('CBC IV must be 16 bytes');
  }
  const cipher = crypto.createCipheriv('aes-256-cbc', key, actualIv);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  return Buffer.concat([Buffer.from([CIPHER_MARKER_CBC]), actualIv, ct]);
}

export function encryptAes256CbcBase64(plaintext: string, key: Buffer, iv?: Buffer): string {
  if (!plaintext) return '';
  const raw = encryptAes256CbcRaw(plaintext, key, iv);
  return cipherBase64Mode(raw, 'cbc');
}

/**
 * Decrypts the LastPass sharing PKCS#8 RSA private key (v1 hex, v2 `!` CBC, or
 * v3 `#` GCM), matching `cipher_decrypt_private_key` in `c-cli/cipher.c`.
 */
export function decryptPrivateKey(encryptedKey: string, key: Buffer): Buffer | null {
  if (!encryptedKey) return null;

  let decrypted: string | null = null;
  if (isCipherMarker(encryptedKey.charCodeAt(0))) {
    decrypted = decryptAes256Base64(encryptedKey, key);
  } else {
    if (encryptedKey.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(encryptedKey)) {
      return null;
    }
    const ctBytes = Buffer.from(encryptedKey, 'hex');
    const v1Raw = Buffer.concat([
      Buffer.from([CIPHER_MARKER_CBC]),
      key.subarray(0, AES_BLOCK_SIZE),
      ctBytes,
    ]);
    const res = decryptAes256Raw(v1Raw, key, false);
    decrypted = res ? res.plaintext : null;
  }

  if (!decrypted) return null;
  const startIdx = decrypted.indexOf(LP_PKEY_PREFIX);
  const endIdx = decrypted.indexOf(LP_PKEY_SUFFIX);
  if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx) return null;

  const hexBody = decrypted.slice(startIdx + LP_PKEY_PREFIX.length, endIdx);
  if (hexBody.length === 0 || hexBody.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hexBody)) {
    return null;
  }
  return Buffer.from(hexBody, 'hex');
}

/**
 * RSA-OAEP (SHA-1) decryption of shared-folder AES keys (`SHAR` chunk),
 * matching `cipher_rsa_decrypt` in `c-cli/cipher.c`.
 */
export function rsaOaepDecrypt(ciphertext: Buffer, pkcs8DerKey: Buffer): string | null {
  if (ciphertext.length === 0 || pkcs8DerKey.length === 0) return null;
  try {
    const privateKey = crypto.createPrivateKey({
      key: pkcs8DerKey,
      format: 'der',
      type: 'pkcs8',
    });
    const out = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha1',
      },
      ciphertext,
    );
    return out.toString('utf8');
  } catch {
    return null;
  }
}

interface ChunkCursor {
  buf: Buffer;
  offset: number;
  end: number;
}

function readChunk(cursor: ChunkCursor): { name: string; chunk: ChunkCursor } | null {
  if (cursor.end - cursor.offset < 8) return null;
  const name = cursor.buf.subarray(cursor.offset, cursor.offset + 4).toString('ascii');
  const len = cursor.buf.readUInt32BE(cursor.offset + 4);
  const dataStart = cursor.offset + 8;
  const dataEnd = dataStart + len;
  if (dataEnd > cursor.end) return null;
  cursor.offset = dataEnd;
  return {
    name,
    chunk: { buf: cursor.buf, offset: dataStart, end: dataEnd },
  };
}

function readItem(chunk: ChunkCursor): Buffer | null {
  if (chunk.end - chunk.offset < 4) return null;
  const len = chunk.buf.readUInt32BE(chunk.offset);
  const start = chunk.offset + 4;
  const end = start + len;
  if (end > chunk.end) return null;
  chunk.offset = end;
  return chunk.buf.subarray(start, end);
}

function peekNextItemEncrypted(chunk: ChunkCursor): boolean {
  if (chunk.end - chunk.offset <= 4) return false;
  const len = chunk.buf.readUInt32BE(chunk.offset);
  if (len === 0 || chunk.offset + 4 + len > chunk.end) return false;
  return isCipherMarker(chunk.buf[chunk.offset + 4]);
}

function readPlainString(chunk: ChunkCursor): string | null {
  const item = readItem(chunk);
  if (!item) return null;
  return item.toString('utf8');
}

function readHexString(chunk: ChunkCursor): string | null {
  const item = readItem(chunk);
  if (!item) return null;
  if (item.length === 0) return '';
  const hex = item.toString('ascii');
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    return item.toString('utf8');
  }
  return Buffer.from(hex, 'hex').toString('utf8');
}

function readCryptString(chunk: ChunkCursor, key: Buffer): string | null {
  const item = readItem(chunk);
  if (!item) return null;
  if (item.length === 0) return '';
  const dec = decryptAes256Raw(item, key, true);
  return dec ? dec.plaintext : '';
}

function readBoolean(chunk: ChunkCursor): boolean | null {
  const item = readItem(chunk);
  if (!item) return null;
  return item.length === 1 && item[0] === 0x31; // '1'
}

interface ParsedShare {
  id: string;
  name: string;
  key: Buffer;
  readonly: boolean;
}

function parseShareChunk(chunk: ChunkCursor, privateKeyDer?: Buffer | null): ParsedShare | null {
  if (!privateKeyDer || privateKeyDer.length === 0) return null;
  const id = readPlainString(chunk);
  const encKeyHexItem = readItem(chunk);
  if (id === null || !encKeyHexItem || encKeyHexItem.length === 0 || encKeyHexItem.length % 2 !== 0) {
    return null;
  }
  const ciphertext = Buffer.from(encKeyHexItem.toString('ascii'), 'hex');
  const hexKey = rsaOaepDecrypt(ciphertext, privateKeyDer);
  if (!hexKey || hexKey.length !== KDF_HASH_LEN * 2) return null;
  const shareKey = Buffer.from(hexKey, 'hex');
  const base64Name = readPlainString(chunk);
  if (base64Name === null) return null;
  const name = decryptAes256Base64(base64Name, shareKey);
  if (name === null) return null;
  const readonly = readBoolean(chunk) ?? false;
  return { id, name, key: shareKey, readonly };
}

interface MutableAccount {
  id: string;
  name: string;
  group: string;
  fullname: string;
  url: string;
  username: string;
  password: string;
  note: string;
  lastModifiedGmt: string;
  totpRaw?: string;
  fields: VaultCustomField[];
}

function parseAccountChunk(
  chunk: ChunkCursor,
  key: Buffer,
  share: ParsedShare | null,
): MutableAccount | null {
  const id = readPlainString(chunk);
  let name = readCryptString(chunk, key);
  let group = readCryptString(chunk, key);
  if (id === null || name === null || group === null) return null;

  const url = peekNextItemEncrypted(chunk) ? readCryptString(chunk, key) : readHexString(chunk);
  const note = readCryptString(chunk, key);
  const fav = readBoolean(chunk);
  const sharedfromaid = readItem(chunk);
  const username = readCryptString(chunk, key);
  const password = readCryptString(chunk, key);
  const pwprotect = readBoolean(chunk);
  if (
    url === null ||
    note === null ||
    fav === null ||
    !sharedfromaid ||
    username === null ||
    password === null ||
    pwprotect === null
  ) {
    return null;
  }

  // Skip genpw, sn
  if (!readItem(chunk) || !readItem(chunk)) return null;
  const lastTouch = readPlainString(chunk);
  if (lastTouch === null) return null;

  // Skip 13 intermediate items (autologin..deleted) matching c-cli/blob.c lines 392-404
  for (let i = 0; i < 13; i++) {
    if (!readItem(chunk)) return null;
  }

  const attachkeyEncrypted = readPlainString(chunk);
  const attachpresent = readBoolean(chunk);
  if (attachkeyEncrypted === null || attachpresent === null) return null;

  // Skip individualshare, notetype, noalert
  for (let i = 0; i < 3; i++) {
    if (!readItem(chunk)) return null;
  }

  const lastModifiedGmt = readPlainString(chunk);
  if (lastModifiedGmt === null) return null;

  // Skip hasbeenshared, last_pwchange_gmt, created_gmt, vulnerable (items 32..35)
  for (let i = 0; i < 4; i++) {
    if (!readItem(chunk)) break;
  }

  // Optional trailing items in newer LastPass blobs (including encrypted TOTP seed)
  let totpRaw: string | undefined;
  while (chunk.offset < chunk.end) {
    const extra = readItem(chunk);
    if (!extra) break;
    if (extra.length > 0) {
      const dec = decryptAes256Raw(extra, key, true);
      if (dec && isLikelyTotpSecret(dec.plaintext)) {
        totpRaw = dec.plaintext.trim();
      } else {
        const plainCandidate = extra.toString('utf8').trim();
        if (isLikelyTotpSecret(plainCandidate)) {
          totpRaw = plainCandidate;
        }
      }
    }
  }

  if (name.charCodeAt(0) === 16) name = '';
  if (group.charCodeAt(0) === 16) group = '';

  const effectiveGroup = share
    ? group
      ? `${share.name}/${group}`
      : share.name
    : group;

  const fullname =
    effectiveGroup && (name || url === 'http://group')
      ? `${effectiveGroup}/${name}`
      : name;

  return {
    id,
    name,
    group: effectiveGroup,
    fullname,
    url,
    username,
    password,
    note,
    lastModifiedGmt,
    totpRaw,
    fields: [],
  };
}

function parseFieldChunk(chunk: ChunkCursor, key: Buffer): VaultCustomField | null {
  const name = readPlainString(chunk);
  const type = readPlainString(chunk);
  if (name === null || type === null) return null;

  const encryptedTypes = new Set(['email', 'tel', 'text', 'password', 'textarea']);
  const value = encryptedTypes.has(type) ? readCryptString(chunk, key) : readPlainString(chunk);
  if (value === null) return null;
  const checked = readBoolean(chunk) ?? false;
  return { name, type, value, checked };
}

export interface ParsedVaultBlob {
  version: number;
  localVersion: boolean;
  accounts: VaultCredential[];
}

/**
 * Parses a LastPass binary vault blob (`LPAV`, `ACCT`, `ACFL`, `ACOF`, `SHAR`)
 * completely in memory using `node:crypto`. Group marker placeholders
 * (`http://group`) are excluded from returned credential entries.
 */
export function parseVaultBlob(
  blob: Buffer,
  key: Buffer,
  privateKeyDer?: Buffer | null,
): ParsedVaultBlob {
  if (key.length !== KDF_HASH_LEN) {
    throw new Error(`Invalid vault decryption key length: expected ${KDF_HASH_LEN}`);
  }

  const cursor: ChunkCursor = { buf: blob, offset: 0, end: blob.length };
  let version = 0;
  let sawVersion = false;
  let localVersion = false;
  let currentShare: ParsedShare | null = null;
  let lastAccount: MutableAccount | null = null;
  const rawAccounts: MutableAccount[] = [];
  const shares: ParsedShare[] = [];

  try {
    let next: ReturnType<typeof readChunk>;
    while ((next = readChunk(cursor)) !== null) {
      const { name, chunk } = next;
      if (name === 'LPAV') {
        const vStr = chunk.buf.subarray(chunk.offset, chunk.end).toString('ascii');
        version = Number.parseInt(vStr, 10) || 0;
        sawVersion = true;
      } else if (name === 'LOCL') {
        localVersion = true;
      } else if (name === 'SHAR') {
        currentShare = parseShareChunk(chunk, privateKeyDer);
        if (currentShare) shares.push(currentShare);
      } else if (name === 'ACCT') {
        const acctKey = currentShare ? currentShare.key : key;
        const parsed = parseAccountChunk(chunk, acctKey, currentShare);
        if (!parsed) {
          throw new Error('Corrupt ACCT chunk in LastPass vault blob');
        }
        lastAccount = parsed;
        rawAccounts.push(parsed);
      } else if (name === 'ACFL' || name === 'ACOF') {
        if (lastAccount) {
          const acctKey = currentShare ? currentShare.key : key;
          const field = parseFieldChunk(chunk, acctKey);
          if (field) lastAccount.fields.push(field);
        }
      }
    }

    if (!sawVersion) {
      throw new Error('Invalid LastPass vault blob: missing LPAV header chunk');
    }

    const accounts: VaultCredential[] = [];
    for (const item of rawAccounts) {
      if (item.url === 'http://group') continue;
      const totpSecret = extractTotpSecret(item.totpRaw, item.note, item.fields);
      const meta = sanitizeAccountMetadata({
        id: item.id,
        name: item.name,
        fullname: item.fullname,
        username: item.username,
        url: item.url,
        group: item.group,
        lastModifiedGmt: item.lastModifiedGmt,
        hasTotp: Boolean(totpSecret),
      });
      accounts.push(
        guardCredential({
          ...meta,
          password: item.password,
          note: item.note,
          totpSecret,
          fields: item.fields,
        }),
      );
    }

    return { version, localVersion, accounts };
  } finally {
    for (const s of shares) {
      s.key.fill(0);
    }
  }
}

function encodeItem(data: Buffer): Buffer {
  const hdr = Buffer.alloc(4);
  hdr.writeUInt32BE(data.length, 0);
  return Buffer.concat([hdr, data]);
}

function encodeChunk(name: string, payload: Buffer): Buffer {
  const hdr = Buffer.alloc(8);
  hdr.write(name.slice(0, 4).padEnd(4, ' '), 0, 4, 'ascii');
  hdr.writeUInt32BE(payload.length, 4);
  return Buffer.concat([hdr, payload]);
}

export interface SyntheticVaultAccountInput {
  id: string;
  name: string;
  group?: string;
  url: string;
  username: string;
  password: string;
  note?: string;
  lastModifiedGmt?: string;
  totpSecret?: string;
  fields?: ReadonlyArray<VaultCustomField>;
}

/**
 * Encodes accounts into a standard binary LastPass vault blob (`LPAV` + `ACCT`
 * + `ACFL`) using AES-256-CBC so tests and local fixtures can verify exact
 * binary wire compatibility without touching network services.
 */
export function buildVaultBlob(
  items: ReadonlyArray<SyntheticVaultAccountInput>,
  key: Buffer,
  version: number = 1,
): Buffer {
  const chunks: Buffer[] = [encodeChunk('LPAV', Buffer.from(String(version), 'ascii'))];

  for (const item of items) {
    const acctItems: Buffer[] = [];
    const pushPlain = (s: string) => acctItems.push(encodeItem(Buffer.from(s, 'utf8')));
    const pushBool = (b: boolean) => acctItems.push(encodeItem(Buffer.from(b ? '1' : '0', 'ascii')));
    const pushCrypt = (s: string) =>
      acctItems.push(encodeItem(s ? encryptAes256CbcRaw(s, key) : Buffer.alloc(0)));

    pushPlain(item.id);
    pushCrypt(item.name);
    pushCrypt(item.group ?? '');
    acctItems.push(encodeItem(Buffer.from(Buffer.from(item.url, 'utf8').toString('hex'), 'ascii')));
    pushCrypt(item.note ?? '');
    pushBool(false); // fav
    pushPlain(''); // sharedfromaid
    pushCrypt(item.username);
    pushCrypt(item.password);
    pushBool(false); // pwprotect
    pushPlain('0'); // genpw
    pushPlain('0'); // sn
    pushPlain('0'); // last_touch
    for (let i = 0; i < 13; i++) pushPlain('');
    pushPlain(''); // attachkey_encrypted
    pushBool(false); // attachpresent
    for (let i = 0; i < 3; i++) pushPlain('');
    pushPlain(item.lastModifiedGmt ?? '1700000000');
    for (let i = 0; i < 4; i++) pushPlain('0');
    if (item.totpSecret) {
      pushCrypt(item.totpSecret);
    }

    chunks.push(encodeChunk('ACCT', Buffer.concat(acctItems)));

    if (item.fields) {
      for (const f of item.fields) {
        const encryptedTypes = new Set(['email', 'tel', 'text', 'password', 'textarea']);
        const fItems: Buffer[] = [
          encodeItem(Buffer.from(f.name, 'utf8')),
          encodeItem(Buffer.from(f.type, 'utf8')),
          encryptedTypes.has(f.type)
            ? encodeItem(f.value ? encryptAes256CbcRaw(f.value, key) : Buffer.alloc(0))
            : encodeItem(Buffer.from(f.value, 'utf8')),
          encodeItem(Buffer.from(f.checked ? '1' : '0', 'ascii')),
        ];
        chunks.push(encodeChunk('ACFL', Buffer.concat(fItems)));
      }
    }
  }

  return Buffer.concat(chunks);
}

function parseXmlAttr(xml: string, tag: string, attr: string): string | null {
  const tagRegex = new RegExp(`<${tag}\\b([^>]*)>`, 'i');
  const tagMatch = xml.match(tagRegex);
  if (!tagMatch) return null;
  const attrs = tagMatch[1];
  const attrRegex = new RegExp(`\\b${attr}\\s*=\\s*"([^"]*)"`, 'i');
  const attrMatch = attrs.match(attrRegex);
  if (!attrMatch) return null;
  return attrMatch[1]
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

export interface VaultProtocolSession {
  server: string;
  uid: string;
  sessionId: string;
  token: string;
  privateKeyEncrypted?: string;
}

export interface VaultProtocolClientOptions {
  server?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/**
 * Pure Node/TypeScript LastPass Vault HTTPS client (`iterations.php`,
 * `login.php`, `getaccts.php`). Keeps decryption keys and plaintext credentials
 * strictly in call-scoped memory.
 */
export class LastPassVaultClient {
  private readonly defaultServer: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: VaultProtocolClientOptions = {}) {
    this.defaultServer = opts.server || process.env.LASTPASS_SERVER || 'lastpass.com';
    this.fetchImpl = opts.fetchImpl || globalThis.fetch;
    this.timeoutMs = opts.timeoutMs ?? 15_000;
  }

  async fetchIterations(email: string, server = this.defaultServer): Promise<number> {
    const userLower = email.trim().toLowerCase();
    const body = new URLSearchParams({ email: userLower });
    const res = await this.fetchImpl(`https://${server}/iterations.php`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'LastPass-CLI/1.6.2',
      },
      body: body.toString(),
      redirect: 'error',
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) {
      throw new Error(`LastPass iterations.php returned HTTP ${res.status}`);
    }
    const text = (await res.text()).trim();
    const iterations = Number.parseInt(text, 10);
    if (!Number.isInteger(iterations) || iterations < MINIMUM_ITERATIONS) {
      throw new Error('LastPass returned an invalid PBKDF2 iteration count');
    }
    return iterations;
  }

  async login(
    email: string,
    masterPassword: string,
    opts?: { otp?: string; trustId?: string; server?: string; iterations?: number },
  ): Promise<{ session: VaultProtocolSession; iterations: number }> {
    const server = opts?.server || this.defaultServer;
    const userLower = email.trim().toLowerCase();
    const iterations = opts?.iterations ?? (await this.fetchIterations(userLower, server));
    const loginHash = deriveLoginHash(userLower, masterPassword, iterations);

    const params = new URLSearchParams({
      xml: '2',
      username: userLower,
      hash: loginHash,
      iterations: String(iterations),
      includeprivatekeyenc: '1',
      method: 'cli',
      outofbandsupported: '1',
    });
    if (opts?.otp) params.set('otp', opts.otp);
    if (opts?.trustId) params.set('uuid', opts.trustId);

    try {
      const res = await this.fetchImpl(`https://${server}/login.php`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'LastPass-CLI/1.6.2',
        },
        body: params.toString(),
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      const xml = await res.text();
      const sessionId = parseXmlAttr(xml, 'ok', 'sessionid');
      const uid = parseXmlAttr(xml, 'ok', 'uid') || '';
      const token = parseXmlAttr(xml, 'ok', 'token') || '';
      if (sessionId && token) {
        const privateKeyEncrypted = parseXmlAttr(xml, 'ok', 'privatekeyenc') || undefined;
        return {
          session: {
            server,
            uid,
            sessionId,
            token,
            privateKeyEncrypted,
          },
          iterations,
        };
      }

      const redirectServer = parseXmlAttr(xml, 'error', 'server');
      if (redirectServer === 'lastpass.eu' && server !== 'lastpass.eu') {
        return this.login(email, masterPassword, { ...opts, server: 'lastpass.eu', iterations });
      }

      const cause = parseXmlAttr(xml, 'error', 'cause') || 'login_rejected';
      const message = parseXmlAttr(xml, 'error', 'message') || 'LastPass login failed';
      throw new Error(`LastPass login failed (${cause}): ${message}`);
    } catch (err) {
      throw scrubError(err, [masterPassword, loginHash, opts?.otp], userLower);
    }
  }

  async fetchDecryptedAccounts(
    email: string,
    masterPassword: string,
    opts?: { otp?: string; trustId?: string },
  ): Promise<VaultCredential[]> {
    const { session, iterations } = await this.login(email, masterPassword, opts);
    const key = deriveDecryptionKey(email, masterPassword, iterations);
    let pkDer: Buffer | null = null;
    try {
      if (session.privateKeyEncrypted) {
        pkDer = decryptPrivateKey(session.privateKeyEncrypted, key);
      }
      const query = new URLSearchParams({
        mobile: '1',
        b64: '1',
        hash: '0.0',
        hasplugin: '1.6.2',
        requestsrc: 'cli',
      });
      const res = await this.fetchImpl(
        `https://${session.server}/getaccts.php?${query.toString()}`,
        {
          method: 'GET',
          headers: {
            Cookie: `PHPSESSID=${encodeURIComponent(session.sessionId)}`,
            'User-Agent': 'LastPass-CLI/1.6.2',
          },
          redirect: 'error',
          signal: AbortSignal.timeout(this.timeoutMs),
        },
      );
      if (!res.ok) {
        throw new Error(`LastPass getaccts.php returned HTTP ${res.status}`);
      }
      const rawBuf = Buffer.from(await res.arrayBuffer());
      const blobBuf =
        rawBuf.subarray(0, 4).toString('ascii') === 'LPAV'
          ? rawBuf
          : Buffer.from(rawBuf.toString('ascii').trim(), 'base64');

      const parsed = parseVaultBlob(blobBuf, key, pkDer);
      return parsed.accounts;
    } catch (err) {
      throw scrubError(err, [masterPassword, session.sessionId, session.token], email);
    } finally {
      key.fill(0);
      if (pkDer) pkDer.fill(0);
    }
  }

  async listSafeMetadata(
    email: string,
    masterPassword: string,
    opts?: { otp?: string; trustId?: string },
  ): Promise<VaultEntryMetadata[]> {
    const creds = await this.fetchDecryptedAccounts(email, masterPassword, opts);
    return creds.map((c) => sanitizeAccountMetadata(c));
  }
}
