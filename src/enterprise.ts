import { scrubError } from './scrub.js';

export interface EnterpriseUserSummary {
  uid: string;
  username: string;
  fullname: string;
  disabled: boolean;
  admin: boolean;
  groups: string[];
  mfaEnabled: boolean;
}

export interface EnterpriseSharedFolderSummary {
  id: string;
  sharedFolderName: string;
  deleted: boolean;
  userCount: number;
}

export interface EnterpriseClientOptions {
  endpoint?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/**
 * LastPass Enterprise API (`enterpriseapi.php`) adapter for administrative
 * directory and shared-folder posture checks.
 *
 * Security rules:
 *   - Provisioning hash (`provhash`) is spent only on the call stack and
 *     scrubbed from all errors.
 *   - Never exposes vault passwords, TOTP seeds, or provisioning keys.
 */
export class LastPassEnterpriseClient {
  private readonly endpoint: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: EnterpriseClientOptions = {}) {
    this.endpoint =
      opts.endpoint ||
      process.env.LASTPASS_ENTERPRISE_URL ||
      'https://lastpass.com/enterpriseapi.php';
    this.fetchImpl = opts.fetchImpl || globalThis.fetch;
    this.timeoutMs = opts.timeoutMs ?? 15_000;
  }

  private async postCommand(
    cid: string,
    provhash: string,
    cmd: string,
    data: Record<string, unknown> = {},
  ): Promise<unknown> {
    try {
      const res = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          cid,
          provhash,
          cmd,
          data,
        }),
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!res.ok) {
        throw new Error(`LastPass Enterprise API '${cmd}' returned HTTP ${res.status}`);
      }
      return await res.json();
    } catch (err) {
      throw scrubError(err, [provhash]);
    }
  }

  async listUsersMetadata(cid: string, provhash: string): Promise<EnterpriseUserSummary[]> {
    const raw = (await this.postCommand(cid, provhash, 'getuserdata')) as {
      Users?: Record<string, Record<string, unknown>>;
    } | null;

    const usersObj = raw?.Users && typeof raw.Users === 'object' ? raw.Users : {};
    return Object.entries(usersObj).map(([uid, u]) => ({
      uid,
      username: typeof u.username === 'string' ? u.username : '',
      fullname: typeof u.fullname === 'string' ? u.fullname : '',
      disabled: Boolean(u.disabled),
      admin: Boolean(u.admin),
      groups: Array.isArray(u.groups)
        ? u.groups.filter((g): g is string => typeof g === 'string')
        : [],
      mfaEnabled: Boolean(u.duousername || u.multifactor),
    }));
  }

  async listSharedFoldersMetadata(
    cid: string,
    provhash: string,
  ): Promise<EnterpriseSharedFolderSummary[]> {
    const raw = (await this.postCommand(cid, provhash, 'getsfdata')) as
      | Record<string, Record<string, unknown>>
      | null;

    if (!raw || typeof raw !== 'object') return [];
    return Object.entries(raw).map(([id, sf]) => ({
      id,
      sharedFolderName:
        typeof sf.sharedfoldername === 'string' ? sf.sharedfoldername : '',
      deleted: Boolean(sf.deleted),
      userCount: Array.isArray(sf.users) ? sf.users.length : 0,
    }));
  }
}
