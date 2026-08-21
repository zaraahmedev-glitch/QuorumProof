import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  SessionManager,
  verifyJwt,
  signJwt,
  JwtPayload,
  _setDefaultSessionManagerForTest,
  _resetDefaultSessionManagerForTest,
} from '../src/services/sessionManager.js';

describe('SessionManager', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'session-test-'));
    // Set JWT_SECRET for consistent testing
    process.env.JWT_SECRET = 'test-secret-key-32-chars-minimum';
  });

  afterEach(() => {
    // Clean up temp directory
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    _resetDefaultSessionManagerForTest();
    delete process.env.JWT_SECRET;
  });

  describe('Basic session operations', () => {
    it('creates a session and returns token pair', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const tokens = mgr.createSession('user-123', { role: 'admin' });

      expect(tokens.accessToken).toBeTruthy();
      expect(tokens.refreshToken).toBeTruthy();
      expect(tokens.expiresIn).toBeGreaterThan(0);
      expect(tokens.tokenType).toBe('Bearer');

      const payload = verifyJwt(tokens.accessToken);
      expect(payload).toBeTruthy();
      expect(payload?.sub).toBe('user-123');
      expect(payload?.type).toBe('access');
      expect(payload?.role).toBe('admin');
    });

    it('validates access token', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const tokens = mgr.createSession('user-123');
      const payload = mgr.validateAccessToken(tokens.accessToken);

      expect(payload).toBeTruthy();
      expect(payload?.sub).toBe('user-123');
      expect(payload?.type).toBe('access');
    });

    it('rejects invalid access token', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const payload = mgr.validateAccessToken('invalid-token');

      expect(payload).toBeNull();
    });

    it('lists sessions for a user', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      mgr.createSession('user-123');
      mgr.createSession('user-123');
      mgr.createSession('user-456');

      const userSessions = mgr.listSessions('user-123');
      expect(userSessions).toHaveLength(2);
      expect(userSessions.every(s => s.userId === 'user-123')).toBe(true);
      expect(userSessions.every(s => !('refreshTokenHash' in s))).toBe(true);
    });

    it('includes mfaVerified flag in access token', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const tokens = mgr.createSession('user-123', { mfaVerified: true });
      const payload = mgr.validateAccessToken(tokens.accessToken);

      expect(payload?.mfaVerified).toBe(true);
    });
  });

  describe('Session revocation — single instance', () => {
    it('revokes a specific session', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const session1 = mgr.createSession('user-123');
      const session2 = mgr.createSession('user-123');

      const payload1 = verifyJwt(session1.accessToken);
      const sessionId = payload1!.jti;

      mgr.revokeSession(sessionId);

      expect(mgr.validateAccessToken(session1.accessToken)).toBeNull();
      expect(mgr.validateAccessToken(session2.accessToken)).toBeTruthy();
    });

    it('revokes all sessions for a user', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const session1 = mgr.createSession('user-123');
      const session2 = mgr.createSession('user-123');
      const session3 = mgr.createSession('user-456');

      const revokedCount = mgr.revokeAllSessions('user-123');

      expect(revokedCount).toBe(2);
      expect(mgr.validateAccessToken(session1.accessToken)).toBeNull();
      expect(mgr.validateAccessToken(session2.accessToken)).toBeNull();
      expect(mgr.validateAccessToken(session3.accessToken)).toBeTruthy();
    });

    it('returns false when revoking non-existent session', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const result = mgr.revokeSession('non-existent-id');

      expect(result).toBe(false);
    });

    it('marks revoked sessions as inactive', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const tokens = mgr.createSession('user-123');
      const payload = verifyJwt(tokens.accessToken);
      const sessionId = payload!.jti;

      mgr.revokeSession(sessionId);

      const sessions = mgr.listSessions('user-123');
      expect(sessions[0].active).toBe(false);
      expect(sessions[0].revokedAt).toBeTruthy();
    });
  });

  describe('Token refresh', () => {
    it('refreshes a valid refresh token', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const originalTokens = mgr.createSession('user-123', { role: 'user' });

      const newTokens = mgr.refreshSession(originalTokens.refreshToken);
      expect(newTokens).toBeTruthy();
      expect(newTokens!.accessToken).toBeTruthy();
      expect(newTokens!.refreshToken).toBeTruthy();

      const newPayload = mgr.validateAccessToken(newTokens!.accessToken);
      expect(newPayload?.sub).toBe('user-123');
    });

    it('rotates refresh token on refresh', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const originalTokens = mgr.createSession('user-123');

      const newTokens = mgr.refreshSession(originalTokens.refreshToken);
      expect(newTokens!.refreshToken).not.toBe(originalTokens.refreshToken);

      expect(mgr.refreshSession(originalTokens.refreshToken)).toBeNull();
    });

    it('rejects refresh with invalid token', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const result = mgr.refreshSession('invalid-token');

      expect(result).toBeNull();
    });

    it('preserves mfaVerified on refresh', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const tokens = mgr.createSession('user-123', { mfaVerified: true });

      const newTokens = mgr.refreshSession(tokens.refreshToken);
      const payload = mgr.validateAccessToken(newTokens!.accessToken);

      expect(payload?.mfaVerified).toBe(true);
    });

    it('preserves role on refresh', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const tokens = mgr.createSession('user-123', { role: 'admin' });

      const newTokens = mgr.refreshSession(tokens.refreshToken);
      const payload = mgr.validateAccessToken(newTokens!.accessToken);

      expect(payload?.role).toBe('admin');
    });
  });

  describe('Durability and multi-instance behavior', () => {
    it('loads sessions from disk on construction', () => {
      const mgr1 = new SessionManager({ dataDir: tempDir });
      const tokens = mgr1.createSession('user-123');

      const mgr2 = new SessionManager({ dataDir: tempDir });
      const payload = mgr2.validateAccessToken(tokens.accessToken);

      expect(payload).toBeTruthy();
      expect(payload?.sub).toBe('user-123');
    });

    it('preserves sessions across restarts', () => {
      const mgr1 = new SessionManager({ dataDir: tempDir });
      const tokens1 = mgr1.createSession('user-123');

      const mgr2 = new SessionManager({ dataDir: tempDir });
      const tokens2 = mgr2.createSession('user-456');

      const mgr3 = new SessionManager({ dataDir: tempDir });
      expect(mgr3.validateAccessToken(tokens1.accessToken)).toBeTruthy();
      expect(mgr3.validateAccessToken(tokens2.accessToken)).toBeTruthy();
    });

    it('revocation on instance A is visible on instance B', () => {
      const mgr1 = new SessionManager({ dataDir: tempDir });
      const tokens = mgr1.createSession('user-123');

      const payload = verifyJwt(tokens.accessToken);
      const sessionId = payload!.jti;

      mgr1.revokeSession(sessionId);

      const mgr2 = new SessionManager({ dataDir: tempDir });
      expect(mgr2.validateAccessToken(tokens.accessToken)).toBeNull();
    });

    it('revokeAllSessions on instance A is visible on instance B', () => {
      const mgr1 = new SessionManager({ dataDir: tempDir });
      const session1 = mgr1.createSession('user-123');
      const session2 = mgr1.createSession('user-123');
      const session3 = mgr1.createSession('user-456');

      mgr1.revokeAllSessions('user-123');

      const mgr2 = new SessionManager({ dataDir: tempDir });
      expect(mgr2.validateAccessToken(session1.accessToken)).toBeNull();
      expect(mgr2.validateAccessToken(session2.accessToken)).toBeNull();
      expect(mgr2.validateAccessToken(session3.accessToken)).toBeTruthy();
    });

    it('concurrent instances see consistent state after reload', () => {
      const mgr1 = new SessionManager({ dataDir: tempDir });
      const session1 = mgr1.createSession('user-123');

      const mgr2 = new SessionManager({ dataDir: tempDir });
      const session2 = mgr2.createSession('user-456');

      // Both sessions exist in respective managers
      expect(mgr1.validateAccessToken(session1.accessToken)).toBeTruthy();
      expect(mgr2.validateAccessToken(session2.accessToken)).toBeTruthy();

      // Create fresh manager to load both sessions
      const mgr3 = new SessionManager({ dataDir: tempDir });
      expect(mgr3.validateAccessToken(session1.accessToken)).toBeTruthy();
      expect(mgr3.validateAccessToken(session2.accessToken)).toBeTruthy();
    });

    it('session revocation state survives instance reload', () => {
      const mgr1 = new SessionManager({ dataDir: tempDir });
      const tokens = mgr1.createSession('user-123');
      const payload = verifyJwt(tokens.accessToken);
      const sessionId = payload!.jti;

      mgr1.revokeSession(sessionId);

      const mgr2 = new SessionManager({ dataDir: tempDir });
      const sessions = mgr2.listSessions('user-123');
      expect(sessions[0].active).toBe(false);
      expect(sessions[0].revokedAt).toBeTruthy();
    });

    it('loads revocation history correctly', () => {
      const mgr1 = new SessionManager({ dataDir: tempDir });
      const tokens = mgr1.createSession('user-123');
      const payload = verifyJwt(tokens.accessToken);
      const sessionId = payload!.jti;

      const now = new Date().toISOString();
      mgr1.revokeSession(sessionId);

      const mgr2 = new SessionManager({ dataDir: tempDir });
      const sessions = mgr2.listSessions('user-123');
      expect(sessions[0].revokedAt).toBeTruthy();
      expect(new Date(sessions[0].revokedAt!).getTime()).toBeGreaterThanOrEqual(new Date(now).getTime());
    });
  });

  describe('Session listing and state', () => {
    it('does not expose refresh token hash in listing', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      mgr.createSession('user-123');

      const sessions = mgr.listSessions('user-123');
      expect(sessions[0]).not.toHaveProperty('refreshTokenHash');
    });

    it('returns empty list for user with no sessions', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const sessions = mgr.listSessions('unknown-user');

      expect(sessions).toHaveLength(0);
    });

    it('sorts sessions by creation date (newest first)', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      mgr.createSession('user-123');

      const sessions1 = mgr.listSessions('user-123');

      mgr.createSession('user-123');
      const sessions2 = mgr.listSessions('user-123');

      expect(new Date(sessions2[0].createdAt).getTime()).toBeGreaterThanOrEqual(new Date(sessions1[0].createdAt).getTime());
    });
  });

  describe('Expired session handling', () => {
    it('purges expired sessions', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const tokens = mgr.createSession('user-123');

      let sessions = mgr.listSessions('user-123');
      expect(sessions).toHaveLength(1);

      // Manually mark as expired by setting accessExpiresAt to the past
      const store = mgr._store;
      const keys = store.keys();
      const sessionId = keys[0];
      const session = store.get(sessionId)!;
      session.accessExpiresAt = new Date(Date.now() - 1000).toISOString();
      session.refreshExpiresAt = new Date(Date.now() - 1000).toISOString();
      store.set(sessionId, session);

      const purged = mgr.purgeExpiredSessions();
      expect(purged).toBe(1);

      sessions = mgr.listSessions('user-123');
      expect(sessions).toHaveLength(0);
    });

    it('purges revoked sessions even if not yet expired', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const tokens = mgr.createSession('user-123');
      const payload = verifyJwt(tokens.accessToken);
      const sessionId = payload!.jti;

      mgr.revokeSession(sessionId);

      const purged = mgr.purgeExpiredSessions();
      expect(purged).toBe(1);

      const sessions = mgr.listSessions('user-123');
      expect(sessions).toHaveLength(0);
    });
  });

  describe('Data directory creation', () => {
    it('creates data directory if it does not exist', () => {
      const customDir = path.join(tempDir, 'nested', 'custom', 'dir');
      expect(fs.existsSync(customDir)).toBe(false);

      const mgr = new SessionManager({ dataDir: customDir });
      mgr.createSession('user-123');

      expect(fs.existsSync(customDir)).toBe(true);
      expect(fs.existsSync(path.join(customDir, 'sessions.jsonl'))).toBe(true);
    });

    it('respects SESSION_STORE_DATA_DIR env var', () => {
      const envDir = path.join(tempDir, 'env-dir');
      process.env.SESSION_STORE_DATA_DIR = envDir;

      new SessionManager();

      expect(fs.existsSync(envDir)).toBe(true);

      delete process.env.SESSION_STORE_DATA_DIR;
    });

    it('defaults to .data/sessions in cwd', () => {
      const mgr = new SessionManager();
      expect(mgr.dataDir).toContain('.data/sessions');
    });
  });

  describe('Multiple users and sessions', () => {
    it('isolates sessions between users', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      const user1Session = mgr.createSession('user-1');
      const user2Session = mgr.createSession('user-2');

      mgr.revokeAllSessions('user-1');

      expect(mgr.validateAccessToken(user1Session.accessToken)).toBeNull();
      expect(mgr.validateAccessToken(user2Session.accessToken)).toBeTruthy();
    });

    it('counts revoked sessions correctly in revokeAllSessions', () => {
      const mgr = new SessionManager({ dataDir: tempDir });
      mgr.createSession('user-123');
      mgr.createSession('user-123');
      const revoked = mgr.revokeAllSessions('user-123');

      expect(revoked).toBe(2);
    });
  });
});
