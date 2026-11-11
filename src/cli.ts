#!/usr/bin/env node
import {
  createLastPassMcpServer,
  SERVER_NAME,
  SERVER_VERSION,
} from './index.js';

interface CliFlags {
  http: boolean;
  port: number;
  host: string;
  help: boolean;
  version: boolean;
}

function parseArgs(argv: ReadonlyArray<string>): CliFlags {
  let httpMode = false;
  let port = Number.parseInt(process.env.LASTPASS_MCP_PORT || '3847', 10) || 3847;
  let host = process.env.LASTPASS_MCP_HOST || '127.0.0.1';
  let help = false;
  let version = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--http') {
      httpMode = true;
    } else if (arg === '--port' || arg === '-p') {
      const next = argv[++i];
      const parsed = Number.parseInt(next || '', 10);
      if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65535) {
        throw new Error(`Invalid --port value: ${next}`);
      }
      port = parsed;
    } else if (arg.startsWith('--port=')) {
      const parsed = Number.parseInt(arg.slice('--port='.length), 10);
      if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65535) {
        throw new Error(`Invalid --port value: ${arg}`);
      }
      port = parsed;
    } else if (arg === '--host') {
      host = argv[++i] || host;
    } else if (arg.startsWith('--host=')) {
      host = arg.slice('--host='.length);
    } else if (arg === '--help' || arg === '-h') {
      help = true;
    } else if (arg === '--version' || arg === '-v') {
      version = true;
    }
  }

  return { http: httpMode, port, host, help, version };
}

function printHelp(): void {
  process.stdout.write(
    `${SERVER_NAME} v${SERVER_VERSION}
Native LastPass MCP server & Hanzo Egress / KMS / ZAP browser autofill bridge.

Usage:
  lastpass-mcp                      Start MCP server over stdio
  lastpass-mcp --http --port 3847   Start Streamable HTTP MCP server (POST /mcp, GET /healthz)

Options:
  --http            Enable Streamable HTTP transport instead of stdio
  --port, -p <N>    Port for HTTP transport (default: 3847)
  --host <ADDR>     Bind address for HTTP transport (default: 127.0.0.1)
  --version, -v     Print version and exit
  --help, -h        Show this help text
`,
  );
}

async function main(): Promise<void> {
  const flags = parseArgs(process.argv.slice(2));
  if (flags.help) {
    printHelp();
    return;
  }
  if (flags.version) {
    process.stdout.write(`${SERVER_VERSION}\n`);
    return;
  }

  const server = createLastPassMcpServer();

  if (flags.http) {
    const running = await server.startHttp({ port: flags.port, host: flags.host });
    process.stderr.write(
      `[${SERVER_NAME}] Streamable HTTP listening on http://${running.host}:${running.port}/mcp (health: /healthz)\n`,
    );
    const shutdown = () => {
      void running.close().finally(() => process.exit(0));
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    return;
  }

  server.startStdio(process.stdin, process.stdout);
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`[${SERVER_NAME}] fatal: ${msg}\n`);
  process.exit(1);
});
