# LLM.md — hanzoai/lastpass-mcp

Native LastPass MCP boundary for browser autofill, Hanzo KMS sealing, and `hanzoai/egress` custodied outbound spend.

## Laws

1. **Never return a credential.** Callers ask for metadata (`lastpass_status`, `lastpass_list`), an in-browser fill (`lastpass_autofill`), a KMS seal (`lastpass_seal_to_kms`), or a custodied HTTP call (`lastpass_egress_fetch`). Passwords, notes, cookies, provisioning hashes, and TOTP seeds/codes must never appear in MCP outputs, logs, errors, disk files, or git.
2. **Every credential lives on one call's stack.** Decrypted vault items (`VaultCredential`) are wrapped with `guardCredential()` (`toJSON` returns stripped `VaultEntryMetadata`) and discarded immediately after the operation completes.
3. **Scrub every outbound surface.** Upstream providers and CLIs sometimes echo rejected keys or partial suffixes. `src/scrub.ts` strips raw, Base64, Basic-Auth Base64, Base64URL, URL-encoded, form-encoded, JSON-escaped, and hex forms — plus 4+ character shared runs on error messages (`ERROR_SCRUB_SPAN = 4`, matching `hanzoai/egress/call.go`).
4. **Sovereign CLI & Zero Shell Interpolation.** Always resolve `~/.local/bin/hanzo` (`resolveHanzoCliPath` explicitly refuses `/usr/bin/hanzo`) and invoke subprocesses (`hanzo`, `lpass`) exclusively via `execFile` with `shell: false`.
5. **Redirects and private IPs are refused on custodied fetches.** `fetchWithCustodiedCredential` sets `redirect: 'manual'`, requires `https://`, blocks RFC1918 / loopback / link-local / cloud-metadata IPs, and forbids caller-supplied `Authorization`, `Cookie`, or `Host` headers.

## Repository Layout

- `c-cli/` — Vendored upstream `lastpass/lastpass-cli` (C99, GPLv2 + OpenSSL exception). Built into `bin/lpass` by `make build-c` when `libcurl`, `openssl`, and `libxml-2.0` headers are installed.
- `src/scrub.ts` — Credential redaction, metadata sanitizer, KMS slugifier, and RFC 6238 TOTP generator (`node:crypto`).
- `src/vault-protocol.ts` — Pure Node/TypeScript LastPass Vault protocol (`iterations.php`, `login.php`, `getaccts.php`, PBKDF2-SHA256 key derivation, AES-256-CBC/GCM/ECB & PKCS#8 RSA-OAEP decryption, binary `LPAV`/`ACCT`/`ACFL`/`SHAR` parser).
- `src/lpass-cli.ts` — Arm's-length subprocess adapter for `lpass`.
- `src/zap-client.ts` — Binary ZAP Unix socket client (`/run/user/$UID/zap/zapd.sock`) for `hanzo.getCookies` (cookie names only), `lastpass.accounts`, `lastpass.fill`, and `hanzo.act` (`op: "fill"`).
- `src/enterprise.ts` — LastPass Enterprise API (`enterpriseapi.php`) metadata adapter.
- `src/kms-egress.ts` — Hanzo KMS sealer (`credentials/<slug>/{USERNAME,PASSWORD,URL,TOTP_SECRET}`) and `hanzoai/egress` `/v1/fetch` + in-process custodied HTTP client.
- `src/index.ts` & `src/cli.ts` — MCP JSON-RPC 2.0 server supporting stdio and Streamable HTTP (`--http --port 3847`, `POST /mcp`, `GET /healthz`).
- `test/lastpass-mcp.test.ts` — Upstream `c-cli` cipher vector tests, PBKDF2/blob round-trips, adversarial secret-echo scrubbing tests, mock ZAP socket tests, and KMS/Egress tests.

## Verification

```bash
make build
npm test
```
