import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  extractTotpSecret,
  guardCredential,
  sanitizeAccountMetadata,
  scrubError,
} from './scrub.js';
import type { LpassCliStatus, VaultCredential, VaultEntryMetadata } from './types.js';

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const BUNDLED_LPASS = path.resolve(MODULE_DIR, '..', 'bin', 'lpass');

export interface ExecFileResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export type ExecFileRunner = (
  file: string,
  args: ReadonlyArray<string>,
  opts?: { timeoutMs?: number; env?: NodeJS.ProcessEnv },
) => Promise<ExecFileResult>;

export const defaultExecFileRunner: ExecFileRunner = (file, args, opts) =>
  new Promise((resolve, reject) => {
    execFile(
      file,
      [...args],
      {
        shell: false,
        timeout: opts?.timeoutMs ?? 15_000,
        maxBuffer: 8 * 1024 * 1024,
        env: opts?.env ?? process.env,
      },
      (err, stdout, stderr) => {
        if (err && (err as NodeJS.ErrnoException).code === 'ENOENT') {
          reject(err);
          return;
        }
        const exitCode =
          err && typeof (err as { code?: unknown }).code === 'number'
            ? ((err as { code: number }).code)
            : err
              ? 1
              : 0;
        resolve({
          stdout: String(stdout ?? ''),
          stderr: String(stderr ?? ''),
          exitCode,
        });
      },
    );
  });

function isExecutable(p: string): boolean {
  try {
    fs.accessSync(p, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolves the `lpass` binary strictly without shell lookup:
 *   1. `LPASS_BIN` environment override
 *   2. Bundled `bin/lpass` built from vendored `c-cli/`
 *   3. `~/.local/bin/lpass`
 *   4. Standard PATH entries (`/usr/local/bin/lpass`, `/usr/bin/lpass`, `/opt/homebrew/bin/lpass`)
 */
export function resolveLpassBinary(customPath?: string): string | null {
  const candidates: string[] = [];
  if (customPath) candidates.push(customPath);
  if (process.env.LPASS_BIN) candidates.push(process.env.LPASS_BIN);
  candidates.push(BUNDLED_LPASS);
  candidates.push(path.join(os.homedir(), '.local', 'bin', 'lpass'));

  const pathDirs = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  for (const dir of pathDirs) {
    candidates.push(path.join(dir, 'lpass'));
  }

  for (const bin of candidates) {
    if (bin && isExecutable(bin)) {
      return bin;
    }
  }
  return null;
}

export function matchVaultEntry(
  entry: {
    id: string;
    name: string;
    fullname: string;
    username: string;
    url: string;
    group: string;
  },
  filter: {
    query?: string;
    id?: string;
    name?: string;
    url?: string;
    username?: string;
  },
): boolean {
  if (filter.id && entry.id !== filter.id) {
    return false;
  }
  if (filter.username) {
    const u = filter.username.toLowerCase();
    if (entry.username.toLowerCase() !== u && !entry.username.toLowerCase().includes(u)) {
      return false;
    }
  }
  if (filter.name) {
    const n = filter.name.toLowerCase();
    if (
      entry.name.toLowerCase() !== n &&
      entry.fullname.toLowerCase() !== n &&
      !entry.name.toLowerCase().includes(n) &&
      !entry.fullname.toLowerCase().includes(n)
    ) {
      return false;
    }
  }
  if (filter.url) {
    let targetHost = filter.url.toLowerCase();
    try {
      targetHost = new URL(filter.url).hostname.toLowerCase();
    } catch {
      targetHost = filter.url.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
    }
    const strippedTarget = targetHost.replace(/^www\./, '');
    let entryHost = entry.url.toLowerCase();
    try {
      entryHost = new URL(entry.url).hostname.toLowerCase();
    } catch {
      entryHost = entry.url.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
    }
    const strippedEntry = entryHost.replace(/^www\./, '');
    if (
      !strippedEntry ||
      (strippedEntry !== strippedTarget &&
        !strippedEntry.endsWith(`.${strippedTarget}`) &&
        !strippedTarget.endsWith(`.${strippedEntry}`) &&
        !entry.url.toLowerCase().includes(strippedTarget) &&
        !entry.name.toLowerCase().includes(strippedTarget))
    ) {
      return false;
    }
  }
  if (filter.query) {
    const q = filter.query.toLowerCase();
    const hay = [
      entry.id,
      entry.name,
      entry.fullname,
      entry.username,
      entry.url,
      entry.group,
    ]
      .join(' ')
      .toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

interface RawLpassJsonAccount {
  id?: string;
  name?: string;
  fullname?: string;
  username?: string;
  password?: string;
  last_modified_gmt?: string;
  last_touch?: string;
  share?: string;
  group?: string;
  url?: string;
  note?: string;
  totp?: string;
}

function toCustodiedCredential(raw: RawLpassJsonAccount): VaultCredential | null {
  if (raw.url === 'http://group') return null;
  const totpSecret = extractTotpSecret(raw.totp, raw.note);
  const group = raw.share
    ? raw.group
      ? `${raw.share}/${raw.group}`
      : raw.share
    : raw.group || '';
  const meta = sanitizeAccountMetadata({
    id: raw.id,
    name: raw.name,
    fullname: raw.fullname,
    username: raw.username,
    url: raw.url,
    group,
    lastModifiedGmt: raw.last_modified_gmt,
    hasTotp: Boolean(totpSecret),
  });
  return guardCredential({
    ...meta,
    password: raw.password || '',
    note: raw.note || '',
    totpSecret,
  });
}

export class LpassCliAdapter {
  private readonly customBin?: string;
  private readonly runner: ExecFileRunner;

  constructor(opts?: { binPath?: string; runner?: ExecFileRunner }) {
    this.customBin = opts?.binPath;
    this.runner = opts?.runner ?? defaultExecFileRunner;
  }

  getBinaryPath(): string | null {
    return this.customBin ?? resolveLpassBinary();
  }

  async getStatus(): Promise<LpassCliStatus> {
    const bin = this.getBinaryPath();
    if (!bin) {
      return {
        available: false,
        binPath: null,
        version: null,
        loggedIn: false,
        accountEmail: null,
      };
    }

    let version: string | null = null;
    try {
      const verRes = await this.runner(bin, ['--version'], { timeoutMs: 4_000 });
      version = verRes.stdout.trim() || verRes.stderr.trim() || null;
    } catch {
      return {
        available: false,
        binPath: bin,
        version: null,
        loggedIn: false,
        accountEmail: null,
      };
    }

    try {
      const statusRes = await this.runner(bin, ['status'], { timeoutMs: 5_000 });
      const combined = `${statusRes.stdout}\n${statusRes.stderr}`.trim();
      const match = combined.match(/Logged in as\s+([^\s.]+@[^\s.]+(?:\.[^\s.]+)*)/i);
      const loggedIn = statusRes.exitCode === 0 && !/not logged in/i.test(combined);
      return {
        available: true,
        binPath: bin,
        version,
        loggedIn,
        accountEmail: match ? match[1].replace(/\.$/, '') : null,
      };
    } catch {
      return {
        available: true,
        binPath: bin,
        version,
        loggedIn: false,
        accountEmail: null,
      };
    }
  }

  /**
   * Spawns `lpass login --trust <email>` in detached non-echoing pinentry/OOB
   * mode so the user can authenticate out-of-band without exposing any master
   * password to the MCP channel.
   */
  async initiateOutOfBandLogin(email: string): Promise<{ started: boolean; detail: string }> {
    const trimmed = email.trim();
    if (!trimmed || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
      throw new Error('A valid email address is required for lpass login');
    }
    const bin = this.getBinaryPath();
    if (!bin) {
      return {
        started: false,
        detail: 'lpass binary is not installed; use browser ZAP sign-in instead',
      };
    }

    const child = spawn(bin, ['login', '--trust', '--color=never', trimmed], {
      shell: false,
      detached: true,
      stdio: 'ignore',
    });
    child.unref();

    return {
      started: true,
      detail: `Initiated out-of-band 'lpass login --trust' for ${trimmed} (pinentry / push approval)`,
    };
  }

  /**
   * Resolves decrypted vault credentials strictly inside process memory.
   * Supports both `lpass show -j --expand-multi -G .*` (upstream C CLI) and
   * `lpass ls --json` if provided by a wrapper binary.
   */
  async loadCredentialsInMemory(): Promise<VaultCredential[]> {
    const bin = this.getBinaryPath();
    if (!bin) {
      throw new Error('lpass binary not found');
    }

    // Try `lpass ls --json` first if supported, else standard `lpass show -j --expand-multi -G .*`
    const lsJson = await this.runner(bin, ['ls', '--sync=no', '--json'], { timeoutMs: 10_000 });
    if (lsJson.exitCode === 0 && lsJson.stdout.trim().startsWith('[')) {
      const parsed = JSON.parse(lsJson.stdout) as RawLpassJsonAccount[];
      return parsed.map(toCustodiedCredential).filter((x): x is VaultCredential => x !== null);
    }

    const showJson = await this.runner(
      bin,
      ['show', '--sync=auto', '--expand-multi', '-j', '-G', '.*'],
      { timeoutMs: 15_000 },
    );
    if (showJson.exitCode !== 0) {
      if (/could not find specified account/i.test(showJson.stderr)) {
        return [];
      }
      throw scrubError(new Error(showJson.stderr.trim() || 'lpass show failed'));
    }

    const trimmed = showJson.stdout.trim();
    if (!trimmed) return [];
    const parsed = JSON.parse(trimmed) as RawLpassJsonAccount[];
    return parsed.map(toCustodiedCredential).filter((x): x is VaultCredential => x !== null);
  }

  /**
   * Lists vault entry metadata ONLY — strictly strips passwords, notes, and TOTP seeds.
   */
  async listMetadata(filter?: {
    query?: string;
    url?: string;
    name?: string;
    username?: string;
  }): Promise<VaultEntryMetadata[]> {
    const creds = await this.loadCredentialsInMemory();
    return creds
      .filter((c) => (filter ? matchVaultEntry(c, filter) : true))
      .map((c) => sanitizeAccountMetadata(c));
  }

  /**
   * Resolves a single matching VaultCredential in memory for autofill, KMS
   * sealing, or custodied outbound fetch. Never expose return value to callers!
   */
  async resolveOneInMemory(selector: {
    id?: string;
    url?: string;
    name?: string;
    username?: string;
  }): Promise<VaultCredential | null> {
    const bin = this.getBinaryPath();
    if (!bin) return null;

    if (selector.id) {
      const byId = await this.runner(bin, ['show', '--sync=auto', '-j', selector.id], {
        timeoutMs: 10_000,
      });
      if (byId.exitCode === 0 && byId.stdout.trim().startsWith('[')) {
        const arr = JSON.parse(byId.stdout) as RawLpassJsonAccount[];
        if (arr.length > 0) {
          return toCustodiedCredential(arr[0]);
        }
      }
    }

    const all = await this.loadCredentialsInMemory();
    const matches = all.filter((c) => matchVaultEntry(c, selector));
    if (matches.length === 0) return null;
    // Prefer exact username match when username filter was specified
    if (selector.username) {
      const exactUser = matches.find(
        (m) => m.username.toLowerCase() === selector.username!.toLowerCase(),
      );
      if (exactUser) return exactUser;
    }
    return matches[0];
  }
}
