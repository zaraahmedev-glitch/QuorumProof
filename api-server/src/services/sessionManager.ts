/**
 * Session Manager Service — Issue #1300, #1365
 *
 * Manages JWT-based sessions with expiry, refresh tokens, and revocation.
 * Session and revocation state is persisted via DurableLog so revocations are
 * immediately visible across all instances in a load-balanced deployment.
 *
 * Design decisions:
 *  - Access tokens expire in 1 hour (configurable via SESSION_ACCESS_TTL_SECONDS).
 *  - Refresh tokens expire in 7 days (configurable via SESSION_REFRESH_TTL_SECONDS).
 *  - Sessions are tracked via DurableLog (durable JSONL) for multi-instance safety.
 *  - JWT signing uses HMAC-SHA256 with a secret from JWT_SECRET env var.
 *  - No external JWT library is needed — we implement compact JWT signing here
 *    using Node's built-in `crypto` module.
 *  - mfaVerified flag in the access token payload signals that the user completed
 *    MFA during login, enabling the requireMfa middleware to gate admin endpoints.
 */

import crypto from 'crypto';
import path from 'path';
import { DurableLog } from './durableLog.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const ACCESS_TTL_SECONDS = parseInt(process.env.SESSION_ACCESS_TTL_SECONDS ?? '3600', 10);   // 1 hour
const REFRESH_TTL_SECONDS = parseInt(process.env.SESSION_REFRESH_TTL_SECONDS ?? '604800', 10); // 7 days

export function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    // Warn loudly in development; in production this should be a hard error.
    console.warn('[SessionManager] JWT_SECRET is not set — using ephemeral secret. Set JWT_SECRET in production!');
    // Generate a random ephemeral secret for this process (sessions won't survive restarts)
    return crypto.randomBytes(64).toString('hex');
  }
  return secret;
}

// Lazily resolved so tests can set process.env.JWT_SECRET before importing
let _jwtSecret: string | undefined;
function jwtSecret(): string {
  if (!_jwtSecret) _jwtSecret = getJwtSecret();
  return _jwtSecret;
}

// ---------------------------------------------------------------------------
// Minimal JWT implementation (HS256)
// ---------------------------------------------------------------------------
function base64UrlEncode(data: string | Buffer): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlDecode(encoded: string): Buffer {
  const padded = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (padded.length % 4)) % 4;
  return Buffer.from(padded + '='.repeat(padding), 'base64');
}

export interface JwtPayload {
  sub: string;         // userId
  jti: string;         // session ID (unique per token)
  iat: number;         // issued at (unix seconds)
  exp: number;         // expires at (unix seconds)
  type: 'access' | 'refresh';
  mfaVerified: boolean;
  role?: string;
}

export function signJwt(payload: JwtPayload): string {
  const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${header}.${body}`;
  const sig = crypto.createHmac('sha256', jwtSecret()).update(signingInput).digest();
  return `${signingInput}.${base64UrlEncode(sig)}`;
}

export function verifyJwt(token: string): JwtPayload | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [header, body, signature] = parts;
  const signingInput = `${header}.${body}`;
  const expectedSig = crypto.createHmac('sha256', jwtSecret()).update(signingInput).digest();
  const actualSig = base64UrlDecode(signature);

  if (expectedSig.length !== actualSig.length) return null;
  if (!crypto.timingSafeEqual(expectedSig, actualSig)) return null;

  let payload: JwtPayload;
  try {
    payload = JSON.parse(base64UrlDecode(body).toString('utf8')) as JwtPayload;
  } catch {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) return null; // token expired

  return payload;
}

// ---------------------------------------------------------------------------
// Session storage
// ---------------------------------------------------------------------------
export interface Session {
  sessionId: string;     // matches JTI in the access token
  userId: string;
  refreshTokenHash: string; // SHA256 of refresh token
  createdAt: string;
  accessExpiresAt: string;
  refreshExpiresAt: string;
  mfaVerified: boolean;
  role: string;
  revokedAt?: string;
  active: boolean;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;     // seconds until access token expires
  tokenType: 'Bearer';
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------
export interface SessionManagerOptions {
  dataDir?: string;
}

export class SessionManager {
  readonly dataDir: string;
  private readonly sessions: DurableLog<Session>;

  constructor(options: SessionManagerOptions = {}) {
    const dataDir = options.dataDir ?? process.env.SESSION_STORE_DATA_DIR ?? path.join(process.cwd(), '.data', 'sessions');
    this.dataDir = dataDir;
    this.sessions = new DurableLog<Session>(path.join(dataDir, 'sessions.jsonl'));
  }

  /**
   * Create a new session and return a token pair.
   * Call this after successful primary authentication (and MFA if enabled).
   */
  createSession(userId: string, options: { mfaVerified?: boolean; role?: string } = {}): TokenPair {
    const sessionId = crypto.randomBytes(16).toString('hex');
    const now = Math.floor(Date.now() / 1000);
    const mfaVerified = options.mfaVerified ?? false;
    const role = options.role ?? 'user';

    // Build access token
    const accessPayload: JwtPayload = {
      sub: userId,
      jti: sessionId,
      iat: now,
      exp: now + ACCESS_TTL_SECONDS,
      type: 'access',
      mfaVerified,
      role,
    };

    // Build refresh token (longer TTL, separate jti)
    const refreshId = crypto.randomBytes(16).toString('hex');
    const refreshPayload: JwtPayload = {
      sub: userId,
      jti: refreshId,
      iat: now,
      exp: now + REFRESH_TTL_SECONDS,
      type: 'refresh',
      mfaVerified,
      role,
    };

    const accessToken = signJwt(accessPayload);
    const refreshToken = signJwt(refreshPayload);
    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    const session: Session = {
      sessionId,
      userId,
      refreshTokenHash,
      createdAt: new Date().toISOString(),
      accessExpiresAt: new Date((now + ACCESS_TTL_SECONDS) * 1000).toISOString(),
      refreshExpiresAt: new Date((now + REFRESH_TTL_SECONDS) * 1000).toISOString(),
      mfaVerified,
      role,
      active: true,
    };

    this.sessions.set(sessionId, session);

    return {
      accessToken,
      refreshToken,
      expiresIn: ACCESS_TTL_SECONDS,
      tokenType: 'Bearer',
    };
  }

  /**
   * Refresh an expired (or soon-to-expire) access token using a valid refresh token.
   * Issues a new access token and rotates the refresh token.
   */
  refreshSession(refreshToken: string): TokenPair | null {
    const payload = verifyJwt(refreshToken);
    if (!payload || payload.type !== 'refresh') return null;

    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    // Find session by userId + refreshTokenHash
    let existingSession: Session | undefined;
    for (const session of this.sessions.values()) {
      if (
        session.userId === payload.sub &&
        session.refreshTokenHash === tokenHash &&
        session.active
      ) {
        existingSession = session;
        break;
      }
    }

    if (!existingSession) return null;

    // Revoke old session (token rotation — prevents refresh token reuse)
    existingSession.active = false;
    existingSession.revokedAt = new Date().toISOString();
    this.sessions.set(existingSession.sessionId, existingSession);

    // Issue a new session — pass mfaVerified, role, and preserveMfaVerified flag
    return this.createSession(payload.sub, {
      mfaVerified: existingSession.mfaVerified,
      role: existingSession.role,
    });
  }

  /**
   * Validate an access token and return its payload.
   * Returns null if the token is invalid, expired, or the session has been revoked.
   */
  validateAccessToken(accessToken: string): JwtPayload | null {
    const payload = verifyJwt(accessToken);
    if (!payload || payload.type !== 'access') return null;

    const session = this.sessions.get(payload.jti);
    if (!session || !session.active) return null; // session revoked

    return payload;
  }

  /**
   * Revoke a specific session by session ID.
   */
  revokeSession(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;

    session.active = false;
    session.revokedAt = new Date().toISOString();
    this.sessions.set(sessionId, session);
    return true;
  }

  /**
   * Revoke all active sessions for a user (e.g., on password change).
   */
  revokeAllSessions(userId: string): number {
    let count = 0;
    const now = new Date().toISOString();
    for (const session of this.sessions.values()) {
      if (session.userId === userId && session.active) {
        session.active = false;
        session.revokedAt = now;
        this.sessions.set(session.sessionId, session);
        count++;
      }
    }
    return count;
  }

  /**
   * List all active sessions for a user.
   */
  listSessions(userId: string): Omit<Session, 'refreshTokenHash'>[] {
    const result: Omit<Session, 'refreshTokenHash'>[] = [];
    for (const session of this.sessions.values()) {
      if (session.userId === userId) {
        const { refreshTokenHash: _dropped, ...safe } = session;
        result.push(safe);
      }
    }
    return result.sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  /**
   * Purge expired/revoked sessions to prevent unbounded memory growth.
   * Safe to call periodically in a background job.
   */
  purgeExpiredSessions(): number {
    const now = new Date().toISOString();
    let count = 0;
    for (const [id, session] of this.sessions.entries()) {
      if (!session.active || session.refreshExpiresAt < now) {
        this.sessions.delete(id);
        count++;
      }
    }
    return count;
  }

  /** For testing only. */
  _resetForTest(): void {
    for (const key of this.sessions.keys()) {
      this.sessions.delete(key);
    }
    _jwtSecret = undefined;
  }

  /** Expose for tests. */
  get _store(): DurableLog<Session> {
    return this.sessions;
  }
}

let defaultSessionManager: SessionManager | undefined;

export function getDefaultSessionManager(): SessionManager {
  if (!defaultSessionManager) defaultSessionManager = new SessionManager();
  return defaultSessionManager;
}

export function _resetDefaultSessionManagerForTest(): void {
  defaultSessionManager = undefined;
}

export function _setDefaultSessionManagerForTest(mgr: SessionManager | undefined): void {
  defaultSessionManager = mgr;
}
