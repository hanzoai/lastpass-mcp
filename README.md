# `@hanzo/lastpass-mcp` (`hanzoai/lastpass-mcp`)

Native LastPass Model Context Protocol (MCP) server, pure Node.js LastPass Vault protocol client, local ZAP browser autofill bridge, and **Hanzo KMS / Hanzo Egress** custody integration.

## Security Law: Never Return a Credential

`@hanzo/lastpass-mcp` enforces the outbound custody law of [`hanzoai/egress`](https://github.com/hanzoai/egress):

- **Callers ask for metadata, a browser fill, a KMS seal, or a custodied call — never a secret.**
- Plaintext passwords, secure notes, session cookies, provisioning hashes, and TOTP seeds/codes **never** cross MCP tool responses, logs, errors, disk files, or git.
- Outbound errors and HTTP responses pass through multi-encoding credential scrubbing (`raw`, `base64`, `basic-auth base64`, `base64url`, `URL-encoded`, `form-encoded`, `JSON-escaped`, `hex`, and shared partial runs).
- All KMS operations invoke `~/.local/bin/hanzo` via `execFile` with `shell: false` (zero shell interpolation; `/usr/bin/hanzo` is explicitly refused).

## Architecture

```text
  MCP Client (Claude / Hanzo Dev / IDE)
           │
           │  stdio OR Streamable HTTP (POST /mcp, GET /healthz)
           ▼
  ┌──────────────────────────────────────────────────────────┐
  │                 @hanzo/lastpass-mcp                      │
  │  • src/scrub.ts          Zero-leak scrubber + RFC 6238   │
  │  • src/vault-protocol.ts Pure Node PBKDF2 + AES-CBC/GCM  │
  │  • src/lpass-cli.ts      Vendored c-cli (bin/lpass)      │
  │  • src/enterprise.ts     LastPass Enterprise API         │
  └────────┬───────────────────────┬─────────────────────────┘
           │                       │
           ▼                       ▼
  ZAP Unix Socket            Hanzo KMS & Hanzo Egress
  (/run/user/$UID/zap)       • ~/.local/bin/hanzo kms secrets create
  • hanzo.getCookies           credentials/<slug>/{USERNAME,PASSWORD,URL,TOTP_SECRET}
    (cookie names ONLY)      • POST ${HANZO_EGRESS_URL}/v1/fetch
  • hanzo.act op:"fill"      • Custodied HTTPS fetch (redirect: manual,
  • lastpass.fill / .accounts  SSRF-guarded, scrubbed response)
```

## Build & Install

```bash
# Compiles vendored upstream lastpass-cli (c-cli -> bin/lpass) when libcurl,
# openssl, and libxml-2.0 headers are installed, plus TypeScript -> dist/
make build

# Run full crypto, scrubbing, ZAP socket, KMS, and Egress test suite
make test

# Link CLI into ~/.local/bin
ln -sf "$(pwd)/dist/cli.js" ~/.local/bin/lastpass-mcp
```

Even without system C `-dev` headers, `@hanzo/lastpass-mcp` runs with zero external C runtime requirements via `src/vault-protocol.ts` (`node:crypto` PBKDF2-SHA256 + AES-256-CBC/GCM/ECB + RSA-OAEP).

## Usage

### Stdio MCP (Default)

```json
{
  "mcpServers": {
    "lastpass": {
      "command": "lastpass-mcp",
      "env": {
        "HANZO_EGRESS_URL": "https://egress.hanzo.ai"
      }
    }
  }
}
```

### Streamable HTTP MCP

```bash
lastpass-mcp --http --port 3847
# POST http://127.0.0.1:3847/mcp
# GET  http://127.0.0.1:3847/healthz
```

## MCP Tools

| Tool | Purpose | Secret Exposure |
|---|---|---|
| `lastpass_status` | Checks `lpass` CLI state, `lastpass.com` session cookie **names** via ZAP, `hanzo kms health`, and `HANZO_EGRESS_URL` | None (cookie names only) |
| `lastpass_login` | Opens `https://lastpass.com/?ac=1` in connected Chrome via ZAP or starts out-of-band `lpass login --trust <email>` | None (out-of-band auth) |
| `lastpass_list` | Searches vault items (`id`, `name`, `fullname`, `username`, `url`, `group`, `lastModifiedGmt`, `hasTotp`) | None (passwords, notes & TOTP stripped) |
| `lastpass_autofill` | Fills `username`, `password`, and RFC 6238 `totp` directly into open browser tab via ZAP (`hanzo.act` `op:"fill"`) | None (`{ filled, account, fieldsFilled }`) |
| `lastpass_seal_to_kms` | Seals matching items into Hanzo KMS at `credentials/<slug>/{USERNAME,PASSWORD,URL,TOTP_SECRET}` | None (writes directly from memory to KMS) |
| `lastpass_egress_fetch` | Calls `POST ${HANZO_EGRESS_URL}/v1/fetch` with IAM token or performs SSRF-guarded custodied HTTPS call | None (all secret encodings scrubbed) |

## License

- `src/`, `test/`: Apache-2.0 (Copyright © 2026 Hanzo AI Inc.)
- `c-cli/`: Vendored upstream [`lastpass/lastpass-cli`](https://github.com/lastpass/lastpass-cli) under GPL-2.0-or-later with OpenSSL exception (see [`NOTICE`](./NOTICE), [`c-cli/COPYING`](./c-cli/COPYING), and [`c-cli/LICENSE.OpenSSL`](./c-cli/LICENSE.OpenSSL)).
