import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { describe, it } from 'node:test';
import {
  buildVaultBlob,
  createLastPassMcpServer,
  decodeZapCmd,
  decryptAes256Base64,
  decryptAes256Raw,
  decryptPrivateKey,
  deriveDecryptionKey,
  deriveLoginHash,
  encodeZapFrame,
  generateTotpCode,
  KmsEgressBridge,
  LastPassEnterpriseClient,
  LastPassVaultClient,
  LpassCliAdapter,
  parseVaultBlob,
  redactSecrets,
  resolveHanzoCliPath,
  sanitizeAccountMetadata,
  scrubError,
  validateCustodiedTargetUrl,
  validateRootedPath,
  ZapBrowserClient,
  type JsonRpcResponse,
} from '../src/index.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * Helper: encodes a single ZAP `PROVIDERS` payload (frame type 4) for tests.
 */
function encodeSingleZapProvider(id: string, brand = 'chrome', caps: string[] = ['act', 'cookies']): Uint8Array {
  const bytes: number[] = [];
  const u16 = (n: number) => bytes.push(n & 0xff, (n >> 8) & 0xff);
  const str = (s: string) => {
    const b = enc.encode(s);
    u16(b.length);
    for (const x of b) bytes.push(x);
  };
  u16(1); // 1 provider
  str(id);
  bytes.push(1); // role = provider
  str(brand);
  u16(caps.length);
  for (const c of caps) str(c);
  u16(0); // 0 attrs
  return new Uint8Array(bytes);
}

/**
 * Spins up an in-process mock ZAP Unix domain socket router speaking the exact
 * binary framing used by `/run/user/$UID/zap/zapd.sock`.
 */
async function startMockZapRouter(
  handler: (method: string, params: Record<string, unknown>) => unknown | Promise<unknown>,
): Promise<{
  socketPath: string;
  recordedCalls: Array<{ method: string; params: Record<string, unknown> }>;
  close: () => Promise<void>;
}> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zap-test-'));
  const socketPath = path.join(tmpDir, 'zapd.sock');
  const recordedCalls: Array<{ method: string; params: Record<string, unknown> }> = [];

  const server = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    const assignedAgentId = 'agent/assigned-1';

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
        const from = dec.decode(raw.subarray(15, 15 + fl));
        const payload = raw.slice(15 + fl + tl, 15 + fl + tl + pl);

        if (t === 1) {
          // HELLO -> WELCOME (type 2)
          sock.write(encodeZapFrame(2, 'zapd', assignedAgentId));
        } else if (t === 3) {
          // LIST_PROVIDERS -> PROVIDERS (type 4)
          sock.write(
            encodeZapFrame(
              4,
              'zapd',
              from,
              encodeSingleZapProvider('browser/chrome-ext-1'),
            ),
          );
        } else if (t === 16) {
          // CMD -> RESP (type 17) or ERR (type 7)
          const decoded = decodeZapCmd(payload);
          recordedCalls.push(decoded);
          void Promise.resolve()
            .then(() => handler(decoded.method, decoded.params))
            .then((result) => {
              const body = enc.encode(JSON.stringify(result));
              sock.write(encodeZapFrame(17, 'browser/chrome-ext-1', from, body));
            })
            .catch((err: unknown) => {
              const msg = err instanceof Error ? err.message : String(err);
              sock.write(encodeZapFrame(7, 'browser/chrome-ext-1', from, enc.encode(msg)));
            });
        }
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => resolve());
  });

  return {
    socketPath,
    recordedCalls,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => {
          fs.rmSync(tmpDir, { recursive: true, force: true });
          resolve();
        });
      }),
  };
}

describe('Upstream LastPass Crypto, KDF & Binary Vault Blob Parsing', () => {
  const TEST_KEY = Buffer.from(
    Array.from({ length: 32 }, (_, i) => i), // 0x00..0x1f matching c-cli/test/unit/cipher_test.c
  );

  it('decrypts official upstream c-cli AES-256-GCM, AES-256-CBC, AES-256-ECB, and PrivateKey vectors', () => {
    const GCM = '#oKCgoKCgoKCgoKCg|adARl+6lPa6ZFs3PzUuV3bGY74DRmUZp2h0vni3sAxLz8c/EZ2pVfQ==';
    const GCM_EMPTY = '#oaGhoaGhoaGhoaGh|KBlKGEV7pitgcYdpaL/U/w==';
    const GCM_AMBIGUOUS = '#oqKioqKioqKioqKi|NON6aypPFJl6bHbWURlAT6jJJRgbIsivc6WAATVgE6YaNZo=';
    const CBC = '!sLGys7S1tre4ubq7vL2+vw==|7b3LiKoDwit82QExs/+9j/ME1OsZ1N8VLmw70wyyUno=';
    const ECB = 'gIb0dOQQAtl34tFkNJWi1rxS76TBYIuAZuYQ/ijgTAA=';
    const ECB_HASH = Buffer.from('I386F6OVaN1OD9T6u6uP3/v53KOT+44s+FrwFzM4ycU=', 'base64');
    const ECB_BANG = Buffer.from('IS/wBs00qAdwA9OEuazrXWLb+h+fy1hxUGJYiP7zZOQ=', 'base64');

    assert.equal(decryptAes256Base64(GCM, TEST_KEY), 'LastPass GCM test vector');
    assert.equal(decryptAes256Base64(GCM_EMPTY, TEST_KEY), '');
    assert.equal(decryptAes256Base64(GCM_AMBIGUOUS, TEST_KEY), 'ambiguous-gcm-19chr');
    assert.equal(decryptAes256Base64(CBC, TEST_KEY), 'LastPass CBC test vector');
    assert.equal(decryptAes256Base64(ECB, TEST_KEY), 'LastPass ECB test vector');

    // Legacy raw ECB items in binary blobs starting with '#' or '!'
    assert.equal(decryptAes256Raw(ECB_HASH, TEST_KEY, true)?.plaintext, '66-legacy-ecb-field');
    assert.equal(decryptAes256Raw(ECB_BANG, TEST_KEY, true)?.plaintext, '300-legacy-ecb-field');

    // Private key formats v1 (hex), v2 (CBC), v3 (GCM) -> 0x01..0x10
    const PK_V1 =
      'f2bea062545b1db528ee1ef6cd99f2c6544773ffbc8089d2dc8edae35ca03ebfe621f3733e1431361ef06b4f9b35f4a8e9dc29595abe2533d8e84d8460f3d45645041de615835f2433a77349c7bd22e4';
    const PK_V2 =
      '!sLGys7S1tre4ubq7vL2+vw==|CM9bO0hkzDbwbAk7JyQh7o9+osyyyp2qjbRyRfvF4ejER4FQ5aN0QGtpNMIOxVJkXoqP/mtuXunzSGD7oIWDnNoPRZTZczJpgJ90L9ASsHg=';
    const PK_V3 =
      '#o6Ojo6Ojo6Ojo6Oj|zibqqr5bVmAawlCITgYnNUdOJuIuloFGf7d46FiC7YLsA1V4Jp3vIsddcINFDTiLWDQ7wKhvFuzkfKTodiyi4VFEi3kZPrqKsCvDR/s8eole1JcdEE4=';
    const expectedPk = Buffer.from([
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ]);
    assert.deepEqual(decryptPrivateKey(PK_V1, TEST_KEY), expectedPk);
    assert.deepEqual(decryptPrivateKey(PK_V2, TEST_KEY), expectedPk);
    assert.deepEqual(decryptPrivateKey(PK_V3, TEST_KEY), expectedPk);
  });

  it('derives deterministic PBKDF2-SHA256 decryption keys and login hashes with lowercase normalization', () => {
    const k1 = deriveDecryptionKey('Dev@Hanzo.AI', 'correct-horse-staple-99!', 100100);
    const k2 = deriveDecryptionKey('dev@hanzo.ai', 'correct-horse-staple-99!', 100100);
    assert.equal(k1.length, 32);
    assert.deepEqual(k1, k2);

    const h1 = deriveLoginHash('Dev@Hanzo.AI', 'correct-horse-staple-99!', 100100);
    const h2 = deriveLoginHash('dev@hanzo.ai', 'correct-horse-staple-99!', 100100);
    assert.equal(h1.length, 64);
    assert.equal(h1, h2);
    assert.notEqual(h1, k1.toString('hex'));

    assert.throws(() => deriveDecryptionKey('dev@hanzo.ai', 'pw', 1), /below minimum/);
  });

  it('round-trips binary LPAV + ACCT + ACFL vault blobs and guards CustodiedCredential against JSON leaks', () => {
    const key = deriveDecryptionKey('ops@hanzo.ai', 'vault-master-key-test', 5000);
    const secretPw = 'lp-super-secret-prod-token-8821!';
    const secretNote = 'Recovery PIN: 991283\nSSH passphrase inside';
    const totpSeed = 'JBSWY3DPEHPK3PXP';

    const rawBlob = buildVaultBlob(
      [
        {
          id: '9001',
          name: 'GitHub Hanzo',
          group: 'Engineering',
          url: 'https://github.com/login',
          username: 'hanzoai',
          password: secretPw,
          note: secretNote,
          lastModifiedGmt: '1731000000',
          totpSecret: totpSeed,
          fields: [{ name: 'api_token', type: 'password', value: 'ghp_hiddenField999' }],
        },
      ],
      key,
      42,
    );

    const parsed = parseVaultBlob(rawBlob, key);
    assert.equal(parsed.version, 42);
    assert.equal(parsed.accounts.length, 1);

    const acct = parsed.accounts[0];
    assert.equal(acct.id, '9001');
    assert.equal(acct.name, 'GitHub Hanzo');
    assert.equal(acct.fullname, 'Engineering/GitHub Hanzo');
    assert.equal(acct.username, 'hanzoai');
    assert.equal(acct.hasTotp, true);
    assert.equal(acct.password, secretPw);
    assert.equal(acct.totpSecret, totpSeed);

    // Accidental JSON.stringify MUST NOT include password, note, totpSecret, or fields!
    const serialized = JSON.stringify(acct);
    assert.ok(!serialized.includes(secretPw));
    assert.ok(!serialized.includes(secretNote));
    assert.ok(!serialized.includes(totpSeed));
    assert.ok(!serialized.includes('ghp_hiddenField999'));
  });

  it('executes LastPassVaultClient iterations -> EU redirect login -> getaccts.php in memory', async () => {
    const email = 'eu-user@hanzo.ai';
    const masterPw = 'EuVaultMaster#2026!';
    const iterations = 5000;
    const key = deriveDecryptionKey(email, masterPw, iterations);
    const blob = buildVaultBlob(
      [
        {
          id: '77',
          name: 'Cloudflare',
          group: 'Infra',
          url: 'https://dash.cloudflare.com',
          username: 'infra@hanzo.ai',
          password: 'cf_secret_key_do_not_leak',
        },
      ],
      key,
      7,
    );

    const seenUrls: string[] = [];
    const mockFetch: typeof fetch = async (input, init) => {
      const url = String(input);
      seenUrls.push(url);
      if (url === 'https://lastpass.com/iterations.php') {
        return new Response(String(iterations), { status: 200 });
      }
      if (url === 'https://lastpass.com/login.php') {
        return new Response('<response><error server="lastpass.eu" cause="redirect" /></response>', {
          status: 200,
        });
      }
      if (url === 'https://lastpass.eu/login.php') {
        const bodyText = String(init?.body || '');
        assert.ok(!bodyText.includes(encodeURIComponent(masterPw)));
        return new Response(
          '<response><ok uid="1234" sessionid="sess_secret_abc" token="tok_xyz" /></response>',
          { status: 200 },
        );
      }
      if (url.startsWith('https://lastpass.eu/getaccts.php')) {
        return new Response(blob.toString('base64'), { status: 200 });
      }
      return new Response('not found', { status: 404 });
    };

    const client = new LastPassVaultClient({ fetchImpl: mockFetch });
    const safeList = await client.listSafeMetadata(email, masterPw);
    assert.equal(safeList.length, 1);
    assert.equal(safeList[0].name, 'Cloudflare');
    assert.ok(!JSON.stringify(safeList).includes('cf_secret_key_do_not_leak'));
    assert.equal(seenUrls.length, 4);
  });
});

describe('RFC 6238 TOTP & Zero-Leak Secret Scrubbing', () => {
  it('computes deterministic RFC 6238 TOTP codes for raw Base32 and otpauth:// URIs', () => {
    // RFC 6238 standard ASCII seed "12345678901234567890" = Base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    const rfcSeed = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    // At T = 59s (59000 ms), 8-digit SHA1 RFC 6238 test vector is "94287082", so 6-digit is "287082"
    assert.equal(generateTotpCode(rfcSeed, 59_000), '287082');

    const uri = `otpauth://totp/Hanzo:admin?secret=${rfcSeed}&digits=8&period=30&algorithm=SHA1`;
    assert.equal(generateTotpCode(uri, 59_000), '94287082');
  });

  it('scrubs raw, base64, basic-auth, base64url, URL-encoded, hex, and partial error echoes', () => {
    const secret = 'sk_live_99887766SecretKey/Plus+Space';
    const user = 'hanzoai';
    const rawB64 = Buffer.from(secret).toString('base64');
    const basicB64 = Buffer.from(`${user}:${secret}`).toString('base64');
    const urlEnc = encodeURIComponent(secret);
    const hexEnc = Buffer.from(secret).toString('hex');

    const leakyPayload = JSON.stringify({
      echoRaw: secret,
      echoB64: rawB64,
      echoBasic: `Basic ${basicB64}`,
      echoUrl: urlEnc,
      echoHex: hexEnc,
      okField: 'keep-me-intact',
    });

    const cleaned = redactSecrets(leakyPayload, [secret], { username: user });
    assert.ok(!cleaned.includes(secret));
    assert.ok(!cleaned.includes(rawB64));
    assert.ok(!cleaned.includes(basicB64));
    assert.ok(!cleaned.includes(urlEnc));
    assert.ok(!cleaned.includes(hexEnc));
    assert.ok(cleaned.includes('keep-me-intact'));

    // Partial echo in provider error (like "rejected key sk_live_...Space")
    const err = scrubError(new Error('Upstream rejected sk_live_9988****Space'), [secret], user);
    assert.ok(!err.message.includes('sk_live_9988'));
    assert.ok(!err.message.includes('Space'));
    assert.ok(err.message.includes('[REDACTED]'));
  });

  it('strips every non-metadata property in sanitizeAccountMetadata', () => {
    const meta = sanitizeAccountMetadata({
      id: '42',
      name: 'Stripe Prod',
      username: 'billing@hanzo.ai',
      url: 'https://dashboard.stripe.com',
      group: 'Finance',
      last_modified_gmt: '1700000123',
      password: 'NEVER_RETURN_THIS_PASSWORD',
      note: 'TOTP: JBSWY3DPEHPK3PXP',
      cookie: 'PHPSESSID=secret',
    } as Record<string, unknown>);

    assert.deepEqual(Object.keys(meta).sort(), [
      'fullname',
      'group',
      'hasTotp',
      'id',
      'lastModifiedGmt',
      'name',
      'url',
      'username',
    ]);
    assert.equal(meta.hasTotp, true);
    assert.ok(!JSON.stringify(meta).includes('NEVER_RETURN_THIS_PASSWORD'));
    assert.ok(!JSON.stringify(meta).includes('JBSWY3DPEHPK3PXP'));
  });
});

describe('MCP Tools, ZAP Browser Autofill, Hanzo KMS Sealing & Egress Custodied Fetch', () => {
  const SECRET_PW = 'HanzoVault!Prod#Secret9281';
  const SECRET_TOTP = 'JBSWY3DPEHPK3PXP';
  const SECRET_NOTE = 'Backup recovery codes: 1111-2222-3333';
  const SECRET_COOKIE_VALUE = 'LP_ULTRA_SECRET_SESSION_COOKIE_VALUE_777';

  it('enforces ~/.local/bin/hanzo and refuses /usr/bin/hanzo', () => {
    const defaultPath = resolveHanzoCliPath();
    assert.equal(defaultPath, path.join(os.homedir(), '.local', 'bin', 'hanzo'));
    assert.throws(() => resolveHanzoCliPath('/usr/bin/hanzo'), /Refusing \/usr\/bin\/hanzo/);
  });

  it('blocks SSRF and non-HTTPS URLs in custodied outbound fetch validation', () => {
    assert.throws(() => validateCustodiedTargetUrl('http://api.example.com/v1'), /https:\/\//);
    assert.throws(
      () => validateCustodiedTargetUrl('https://169.254.169.254/latest/meta-data/'),
      /private, loopback, or metadata IP/,
    );
    assert.throws(() => validateCustodiedTargetUrl('https://127.0.0.1/admin'), /private, loopback/);
    assert.throws(() => validateCustodiedTargetUrl('https://10.0.0.5/secret'), /private/);
    assert.throws(() => validateRootedPath('https://evil.example/x'), /single \//);
    assert.throws(() => validateRootedPath('//evil.example/x'), /single \//);
    assert.throws(() => validateRootedPath('/\\evil.example/x'), /backslash/);
  });

  it('serves MCP initialize, tools/list, status, list, ZAP autofill, KMS seal, and Egress fetch over Streamable HTTP & stdio with zero secret leaks', async () => {
    // 1. Stand up mock ZAP Unix socket router
    const zapRouter = await startMockZapRouter((method) => {
      if (method === 'hanzo.getCookies') {
        return {
          cookies: [
            { name: 'PHPSESSID', value: SECRET_COOKIE_VALUE },
            { name: 'LPVID', value: 'another_secret_cookie_value' },
          ],
        };
      }
      if (method === 'hanzo.act') {
        return { ok: true };
      }
      if (method === 'hanzo.open') {
        return { tabId: 108 };
      }
      return { ok: true };
    });

    // 2. Stand up mock upstream + Egress HTTP server on loopback
    let lastUpstreamAuthHeader = '';
    const mockHttpServer = http.createServer((req, res) => {
      const reqUrl = req.url || '/';
      if (req.method === 'POST' && reqUrl === '/v1/fetch') {
        // Acting as hanzoai/egress /v1/fetch
        const auth = req.headers.authorization || '';
        if (auth !== 'Bearer iam_valid_caller_token_123') {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'not identified' }));
          return;
        }
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          const parsed = JSON.parse(body) as { provider: string; path: string };
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              status: 200,
              body: { provider: parsed.provider, path: parsed.path, droplets: [] },
              scope: 'user',
              millis: 12,
            }),
          );
        });
        return;
      }

      if (reqUrl === '/echo-secret') {
        // Malicious/chatty upstream that echoes the credential in raw, base64, URL-encoded, and Set-Cookie!
        lastUpstreamAuthHeader = String(req.headers.authorization || '');
        const b64 = Buffer.from(SECRET_PW).toString('base64');
        const urlEnc = encodeURIComponent(SECRET_PW);
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Set-Cookie': `session=${SECRET_PW}; HttpOnly`,
          'X-Debug-Echo': `received ${SECRET_PW} and ${b64}`,
        });
        res.end(
          JSON.stringify({
            authenticated: true,
            echoRaw: SECRET_PW,
            echoBase64: b64,
            echoUrl: urlEnc,
            safeData: 'deployment-ready',
          }),
        );
        return;
      }

      if (reqUrl === '/redirect-trap') {
        res.writeHead(302, { Location: 'https://attacker.example/capture' });
        res.end();
        return;
      }

      res.writeHead(404);
      res.end('not found');
    });

    await new Promise<void>((resolve) => mockHttpServer.listen(0, '127.0.0.1', () => resolve()));
    const httpAddr = mockHttpServer.address() as net.AddressInfo;
    const mockBaseUrl = `http://127.0.0.1:${httpAddr.port}`;

    // 3. Create temporary executable mock `hanzo` CLI in a temp dir to verify exact execFile args
    const tmpBinDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hanzo-bin-'));
    const fakeHanzoBin = path.join(tmpBinDir, 'hanzo');
    fs.writeFileSync(fakeHanzoBin, '#!/bin/sh\nexit 0\n', { mode: 0o755 });

    const kmsRecordedCalls: Array<{ file: string; args: ReadonlyArray<string> }> = [];
    const mockKmsRunner = async (file: string, args: ReadonlyArray<string>) => {
      kmsRecordedCalls.push({ file, args });
      if (args.includes('health')) {
        return { stdout: '{"ready":true}', stderr: '', exitCode: 0 };
      }
      return { stdout: '{"created":true}', stderr: '', exitCode: 0 };
    };

    // 4. Build real encrypted LastPass binary blob in memory and parse it via vault-protocol
    const vaultKey = deriveDecryptionKey('z@hanzo.ai', 'MasterPass!2026', 5000);
    const encryptedBlob = buildVaultBlob(
      [
        {
          id: '101',
          name: 'GitHub Hanzo',
          group: 'Hanzo',
          url: 'https://github.com/login',
          username: 'hanzoai',
          password: SECRET_PW,
          note: SECRET_NOTE,
          totpSecret: SECRET_TOTP,
          lastModifiedGmt: '1731200000',
        },
      ],
      vaultKey,
      9,
    );

    const mcpServer = createLastPassMcpServer({
      lpass: new LpassCliAdapter({
        binPath: fakeHanzoBin, // simulate executable present
        runner: async (_file, args) => {
          if (args[0] === '--version') {
            return { stdout: 'LastPass CLI v1.6.2', stderr: '', exitCode: 0 };
          }
          return { stdout: 'Not logged in.', stderr: '', exitCode: 1 };
        },
      }),
      zap: new ZapBrowserClient({ socketPath: zapRouter.socketPath }),
      kmsEgress: new KmsEgressBridge({
        hanzoBinPath: fakeHanzoBin,
        egressUrl: mockBaseUrl,
        runner: mockKmsRunner,
        allowLoopbackHttpForTests: true,
      }),
      resolveVaultCredentials: async () => parseVaultBlob(encryptedBlob, vaultKey).accounts,
    });

    const httpTransport = await mcpServer.startHttp({ port: 0, host: '127.0.0.1' });
    const mcpEndpoint = `http://127.0.0.1:${httpTransport.port}`;

    try {
      // A. Healthz check
      const healthRes = await fetch(`${mcpEndpoint}/healthz`);
      assert.equal(healthRes.status, 200);
      const healthJson = (await healthRes.json()) as { ok: boolean; service: string };
      assert.equal(healthJson.ok, true);
      assert.equal(healthJson.service, '@hanzo/lastpass-mcp');

      // B. MCP initialize + notifications/initialized + tools/list
      const initRes = await fetch(`${mcpEndpoint}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '1.0' } },
        }),
      });
      assert.equal(initRes.status, 200);
      assert.ok(initRes.headers.get('mcp-session-id'));
      const initBody = (await initRes.json()) as JsonRpcResponse;
      assert.equal((initBody.result as { protocolVersion: string }).protocolVersion, '2025-03-26');

      const notifRes = await fetch(`${mcpEndpoint}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
      });
      assert.equal(notifRes.status, 202);

      const toolsRes = await fetch(`${mcpEndpoint}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
      });
      const toolsBody = (await toolsRes.json()) as {
        result: { tools: Array<{ name: string }> };
      };
      assert.deepEqual(
        toolsBody.result.tools.map((t) => t.name),
        [
          'lastpass_status',
          'lastpass_login',
          'lastpass_list',
          'lastpass_autofill',
          'lastpass_seal_to_kms',
          'lastpass_egress_fetch',
        ],
      );

      const callMcpTool = async (name: string, args: Record<string, unknown>) => {
        const r = await fetch(`${mcpEndpoint}/mcp`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: Math.floor(Math.random() * 100_000),
            method: 'tools/call',
            params: { name, arguments: args },
          }),
        });
        const raw = await r.text();
        // Global invariant: NO secret may EVER appear in ANY MCP HTTP response!
        for (const forbidden of [
          SECRET_PW,
          Buffer.from(SECRET_PW).toString('base64'),
          encodeURIComponent(SECRET_PW),
          SECRET_TOTP,
          SECRET_NOTE,
          SECRET_COOKIE_VALUE,
        ]) {
          assert.ok(!raw.includes(forbidden), `Secret leaked in ${name} output!`);
        }
        return JSON.parse(raw) as {
          result: { structuredContent?: unknown; isError?: boolean; content: Array<{ text: string }> };
        };
      };

      // C. lastpass_status — verifies cookie NAMES only, KMS health, and Egress status
      const statusOut = await callMcpTool('lastpass_status', {});
      const statusData = statusOut.result.structuredContent as {
        zapBrowser: { lastpassSessionPresent: boolean; cookieNames: string[] };
        kms: { healthy: boolean };
        egress: { configured: boolean };
      };
      assert.equal(statusData.zapBrowser.lastpassSessionPresent, true);
      assert.deepEqual(statusData.zapBrowser.cookieNames, ['LPVID', 'PHPSESSID']);
      assert.equal(statusData.kms.healthy, true);
      assert.equal(statusData.egress.configured, true);

      // D. lastpass_list — verifies metadata returned and passwords/notes/TOTP stripped
      const listOut = await callMcpTool('lastpass_list', { query: 'github' });
      const listData = listOut.result.structuredContent as {
        count: number;
        entries: Array<Record<string, unknown>>;
      };
      assert.equal(listData.count, 1);
      assert.equal(listData.entries[0].username, 'hanzoai');
      assert.equal(listData.entries[0].hasTotp, true);
      assert.equal('password' in listData.entries[0], false);
      assert.equal('note' in listData.entries[0], false);
      assert.equal('totpSecret' in listData.entries[0], false);

      // E. lastpass_autofill — verifies ZAP `hanzo.act` `op: "fill"` receives username, password, and 6-digit TOTP while caller receives ONLY metadata
      const fillOut = await callMcpTool('lastpass_autofill', {
        url: 'https://github.com/login',
        username: 'hanzoai',
        tabId: 42,
      });
      const fillData = fillOut.result.structuredContent as {
        filled: boolean;
        fieldsFilled: string[];
        account: { id: string; username: string };
      };
      assert.equal(fillData.filled, true);
      assert.deepEqual(fillData.fieldsFilled, ['username', 'password', 'totp']);
      assert.equal(fillData.account.username, 'hanzoai');

      const actCalls = zapRouter.recordedCalls.filter((c) => c.method === 'hanzo.act');
      assert.equal(actCalls.length, 3);
      assert.equal(actCalls[0].params.op, 'fill');
      assert.equal(actCalls[0].params.tabId, 42);
      assert.equal(actCalls[0].params.value, 'hanzoai');
      assert.equal(actCalls[1].params.value, SECRET_PW);
      assert.match(String(actCalls[2].params.value), /^\d{6}$/);

      // F. lastpass_seal_to_kms — verifies USERNAME, PASSWORD, URL, TOTP_SECRET sealed via hanzo kms secrets create
      kmsRecordedCalls.length = 0;
      const sealOut = await callMcpTool('lastpass_seal_to_kms', {
        name: 'GitHub Hanzo',
        asOrg: 'hanzo',
      });
      const sealData = sealOut.result.structuredContent as {
        sealedCount: number;
        items: Array<{ slug: string; kmsPath: string; keysSealed: string[] }>;
      };
      assert.equal(sealData.sealedCount, 1);
      assert.equal(sealData.items[0].slug, 'github-hanzo');
      assert.equal(sealData.items[0].kmsPath, 'credentials/github-hanzo');
      assert.deepEqual(sealData.items[0].keysSealed, [
        'USERNAME',
        'PASSWORD',
        'URL',
        'TOTP_SECRET',
      ]);
      assert.equal(kmsRecordedCalls.length, 4);
      assert.ok(kmsRecordedCalls.every((c) => c.file === fakeHanzoBin));

      // G. lastpass_egress_fetch Mode 1: Egress Broker (`POST /v1/fetch`)
      const brokerFetchOut = await callMcpTool('lastpass_egress_fetch', {
        provider: 'digitalocean',
        path: '/v2/droplets',
        method: 'GET',
        iamToken: 'iam_valid_caller_token_123',
      });
      const brokerData = brokerFetchOut.result.structuredContent as {
        mode: string;
        status: number;
        scope: string;
      };
      assert.equal(brokerData.mode, 'egress_broker');
      assert.equal(brokerData.status, 200);
      assert.equal(brokerData.scope, 'user');

      // H. lastpass_egress_fetch Mode 2: In-process custodied fetch with hostile upstream secret echo
      const custodiedOut = await callMcpTool('lastpass_egress_fetch', {
        name: 'GitHub Hanzo',
        targetUrl: `${mockBaseUrl}/echo-secret`,
        method: 'GET',
        authScheme: 'bearer',
      });
      assert.equal(lastUpstreamAuthHeader, `Bearer ${SECRET_PW}`);
      const custodiedData = custodiedOut.result.structuredContent as {
        mode: string;
        status: number;
        headers: Record<string, string>;
        body: Record<string, string>;
      };
      assert.equal(custodiedData.mode, 'custodied_in_process');
      assert.equal(custodiedData.status, 200);
      assert.equal(custodiedData.headers['set-cookie'], '[REDACTED]');
      assert.equal(custodiedData.body.echoRaw, '[REDACTED]');
      assert.equal(custodiedData.body.echoBase64, '[REDACTED]');
      assert.equal(custodiedData.body.echoUrl, '[REDACTED]');
      assert.equal(custodiedData.body.safeData, 'deployment-ready');

      // I. Redirect trap is NOT followed (302 returned as-is, credential never forwarded)
      const redirectOut = await callMcpTool('lastpass_egress_fetch', {
        name: 'GitHub Hanzo',
        targetUrl: `${mockBaseUrl}/redirect-trap`,
        method: 'GET',
      });
      const redirectData = redirectOut.result.structuredContent as { status: number };
      assert.equal(redirectData.status, 302);

      // J. Stdio transport smoke test
      const stdinStream = new PassThrough();
      const stdoutStream = new PassThrough();
      const stdioHandle = mcpServer.startStdio(stdinStream, stdoutStream);
      const linePromise = new Promise<string>((resolve) => {
        stdoutStream.once('data', (chunk: Buffer) => resolve(chunk.toString('utf8')));
      });
      stdinStream.write(
        `${JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'ping' })}\n`,
      );
      const stdioLine = await linePromise;
      assert.equal(JSON.parse(stdioLine).id, 99);
      stdioHandle.close();
    } finally {
      await httpTransport.close();
      await new Promise<void>((resolve) => mockHttpServer.close(() => resolve()));
      await zapRouter.close();
      fs.rmSync(tmpBinDir, { recursive: true, force: true });
    }
  });

  it('scrubs provisioning hash from LastPassEnterpriseClient errors and outputs metadata only', async () => {
    const secretProvHash = 'prov_hash_ultra_sensitive_998877';
    const ent = new LastPassEnterpriseClient({
      endpoint: 'https://enterprise.example/api',
      fetchImpl: async () => {
        throw new Error(`Socket failure while sending ${secretProvHash}`);
      },
    });
    await assert.rejects(
      () => ent.listUsersMetadata('1001', secretProvHash),
      (err: Error) => {
        assert.ok(!err.message.includes(secretProvHash));
        assert.ok(err.message.includes('[REDACTED]'));
        return true;
      },
    );
  });

  it('supports ZAP lastpass.fill browser-vault fallback, lastpass_login via ZAP, LpassCliAdapter JSON parsing, and KMS error scrubbing', async () => {
    const LEAKY_EXT_PW = 'ExtVaultSecretPassword#555';
    const zapRouter = await startMockZapRouter((method) => {
      if (method === 'hanzo.getCookies') {
        return { cookies: [{ name: 'PHPSESSID', value: 'hidden_cookie_val' }] };
      }
      if (method === 'hanzo.open') {
        return { tabId: 77 };
      }
      if (method === 'lastpass.accounts') {
        return {
          accounts: [
            {
              id: '501',
              name: 'NPM Registry',
              username: 'hanzo-bot',
              url: 'https://www.npmjs.com/login',
              group: 'Packages',
              password: LEAKY_EXT_PW,
              note: 'otpauth://totp/NPM:hanzo-bot?secret=JBSWY3DPEHPK3PXP',
            },
          ],
        };
      }
      if (method === 'lastpass.fill') {
        return {
          filled: true,
          fieldsFilled: ['username', 'password'],
          account: {
            id: '501',
            name: 'NPM Registry',
            username: 'hanzo-bot',
            url: 'https://www.npmjs.com/login',
            password: LEAKY_EXT_PW,
          },
        };
      }
      return { ok: true };
    });

    const tmpBinDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lpass-bin-'));
    const fakeBin = path.join(tmpBinDir, 'lpass');
    fs.writeFileSync(fakeBin, '#!/bin/sh\nexit 0\n', { mode: 0o755 });

    try {
      // 1. LpassCliAdapter listMetadata strips password & note while detecting TOTP in note
      const cli = new LpassCliAdapter({
        binPath: fakeBin,
        runner: async (_f, args) => {
          if (args[0] === 'ls') return { stdout: '', stderr: 'unsupported flag', exitCode: 1 };
          return {
            stdout: JSON.stringify([
              {
                id: '888',
                name: 'PyPI',
                fullname: 'Packages/PyPI',
                username: 'hanzoai',
                password: 'pypi_secret_password_000',
                url: 'https://pypi.org',
                group: 'Packages',
                last_modified_gmt: '1730000000',
                note: 'TOTP: JBSWY3DPEHPK3PXP',
              },
            ]),
            stderr: '',
            exitCode: 0,
          };
        },
      });
      const cliMeta = await cli.listMetadata({ query: 'pypi' });
      assert.equal(cliMeta.length, 1);
      assert.equal(cliMeta[0].hasTotp, true);
      assert.ok(!JSON.stringify(cliMeta).includes('pypi_secret_password_000'));
      assert.ok(!JSON.stringify(cliMeta).includes('JBSWY3DPEHPK3PXP'));

      // 2. Server with disconnected lpass falls back cleanly to ZAP browser extension
      const server = createLastPassMcpServer({
        lpass: new LpassCliAdapter({
          binPath: fakeBin,
          runner: async (_f, args) =>
            args[0] === '--version'
              ? { stdout: 'v1.6.2', stderr: '', exitCode: 0 }
              : { stdout: 'Not logged in.', stderr: '', exitCode: 1 },
        }),
        zap: new ZapBrowserClient({ socketPath: zapRouter.socketPath }),
        kmsEgress: new KmsEgressBridge({
          hanzoBinPath: fakeBin,
          runner: async (_f, args) => ({
            stdout: '',
            stderr: `kms write failed for payload ${args.join(' ')}`,
            exitCode: 1,
          }),
        }),
      });

      const loginResp = await server.handleJsonRpc({
        jsonrpc: '2.0',
        id: 10,
        method: 'tools/call',
        params: { name: 'lastpass_login', arguments: { mode: 'browser' } },
      });
      const loginData = (loginResp?.result as { structuredContent: { mode: string; browserUrl: string } })
        .structuredContent;
      assert.equal(loginData.mode, 'browser_zap');
      assert.equal(loginData.browserUrl, 'https://lastpass.com/?ac=1');

      const zapListResp = await server.handleJsonRpc({
        jsonrpc: '2.0',
        id: 11,
        method: 'tools/call',
        params: { name: 'lastpass_list', arguments: { query: 'npm' } },
      });
      const zapListText = JSON.stringify(zapListResp);
      assert.ok(!zapListText.includes(LEAKY_EXT_PW));
      assert.ok(!zapListText.includes('JBSWY3DPEHPK3PXP'));

      const zapFillResp = await server.handleJsonRpc({
        jsonrpc: '2.0',
        id: 12,
        method: 'tools/call',
        params: { name: 'lastpass_autofill', arguments: { url: 'https://www.npmjs.com/login', tabId: 77 } },
      });
      const zapFillText = JSON.stringify(zapFillResp);
      assert.ok(!zapFillText.includes(LEAKY_EXT_PW));
      const zapFillData = (zapFillResp?.result as { structuredContent: { via: string; filled: boolean } })
        .structuredContent;
      assert.equal(zapFillData.via, 'zap_lastpass_fill');
      assert.equal(zapFillData.filled, true);

      // 3. KMS error scrubbing when subprocess echoes `--value <SECRET>` in stderr
      const kmsFailServer = createLastPassMcpServer({
        zap: new ZapBrowserClient({ socketPath: zapRouter.socketPath }),
        kmsEgress: new KmsEgressBridge({
          hanzoBinPath: fakeBin,
          runner: async (_f, args) => ({
            stdout: '',
            stderr: `Error writing secret: ${args.join(' ')}`,
            exitCode: 1,
          }),
        }),
        resolveVaultCredentials: async () => [
          {
            id: '9',
            name: 'TestKmsFail',
            fullname: 'TestKmsFail',
            username: 'admin',
            url: 'https://kms.hanzo.ai',
            group: '',
            lastModifiedGmt: '1',
            hasTotp: false,
            password: 'KMS_STDERR_SECRET_VALUE_999',
            note: '',
          },
        ],
      });

      const failSealResp = await kmsFailServer.handleJsonRpc({
        jsonrpc: '2.0',
        id: 13,
        method: 'tools/call',
        params: { name: 'lastpass_seal_to_kms', arguments: { id: '9' } },
      });
      const failText = JSON.stringify(failSealResp);
      assert.ok(!failText.includes('KMS_STDERR_SECRET_VALUE_999'));
      assert.equal((failSealResp?.result as { isError?: boolean }).isError, true);
    } finally {
      await zapRouter.close();
      fs.rmSync(tmpBinDir, { recursive: true, force: true });
    }
  });
});

