import { describe, it, expect, beforeEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import express from 'express';
import request from 'supertest';
import webhooksRouter from '../src/routes/webhooks.js';
import {
  _configureForTest,
  _drainForTest,
  deleteWebhook,
  dispatchWebhookEvent,
  getDeliveryLog,
  listDeadLetters,
  registerWebhook,
  replayDeadLetter,
} from '../src/services/webhooks.js';
import { WebhookStore } from '../src/services/webhookStore.js';
import { WebhookCircuitBreaker, type CircuitBreakerConfig } from '../src/services/webhookCircuitBreaker.js';

const app = express();
app.use(express.json());
app.use('/api/webhooks', webhooksRouter);

/** Point the module-level webhook service at a fresh temp-dir-backed store/breaker — real isolation, real durability. */
function freshService(opts: { maxRetries?: number; retryDelaysMs?: number[]; breakerConfig?: Partial<CircuitBreakerConfig> } = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'webhooks-test-'));
  const store = new WebhookStore({ dataDir });
  const breaker = new WebhookCircuitBreaker({ dataDir, config: opts.breakerConfig });
  const service = _configureForTest({
    store,
    breaker,
    maxRetries: opts.maxRetries ?? 3,
    retryDelaysMs: opts.retryDelaysMs ?? [0, 0, 0],
  });
  return { dataDir, store, breaker, service };
}

beforeEach(() => {
  vi.restoreAllMocks();
  freshService();
});

// ── Registration ─────────────────────────────────────────────────────────────

describe('POST /api/webhooks', () => {
  it('registers a webhook and returns 201', async () => {
    const res = await request(app)
      .post('/api/webhooks')
      .send({ url: 'https://example.com/hook', events: ['credential_issued'] });

    expect(res.status).toBe(201);
    expect(res.body.id).toBeDefined();
    expect(res.body.url).toBe('https://example.com/hook');
    expect(res.body.events).toEqual(['credential_issued']);
  });

  it('returns 400 when url is missing', async () => {
    const res = await request(app)
      .post('/api/webhooks')
      .send({ events: ['credential_issued'] });
    expect(res.status).toBe(400);
  });

  it('returns 400 when events array is empty', async () => {
    const res = await request(app)
      .post('/api/webhooks')
      .send({ url: 'https://example.com/hook', events: [] });
    expect(res.status).toBe(400);
  });

  it('returns 400 for invalid event name', async () => {
    const res = await request(app)
      .post('/api/webhooks')
      .send({ url: 'https://example.com/hook', events: ['credential_teleported'] });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid events/);
  });
});

// ── Listing ───────────────────────────────────────────────────────────────────

describe('GET /api/webhooks', () => {
  it('returns empty list initially', async () => {
    const res = await request(app).get('/api/webhooks');
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual([]);
  });

  it('returns registered webhooks', async () => {
    await request(app)
      .post('/api/webhooks')
      .send({ url: 'https://a.com', events: ['credential_revoked'] });

    const res = await request(app).get('/api/webhooks');
    expect(res.body.data).toHaveLength(1);
    expect(res.body.data[0].url).toBe('https://a.com');
  });
});

// ── Get by ID ─────────────────────────────────────────────────────────────────

describe('GET /api/webhooks/:id', () => {
  it('returns the webhook by id', async () => {
    const created = await request(app)
      .post('/api/webhooks')
      .send({ url: 'https://b.com', events: ['credential_attested'] });

    const res = await request(app).get(`/api/webhooks/${created.body.id}`);
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(created.body.id);
  });

  it('returns 404 for unknown id', async () => {
    const res = await request(app).get('/api/webhooks/wh_999');
    expect(res.status).toBe(404);
  });
});

// ── Deletion ──────────────────────────────────────────────────────────────────

describe('DELETE /api/webhooks/:id', () => {
  it('deletes a webhook and returns 204', async () => {
    const created = await request(app)
      .post('/api/webhooks')
      .send({ url: 'https://c.com', events: ['credential_issued'] });

    const del = await request(app).delete(`/api/webhooks/${created.body.id}`);
    expect(del.status).toBe(204);

    const get = await request(app).get(`/api/webhooks/${created.body.id}`);
    expect(get.status).toBe(404);
  });

  it('returns 404 when deleting unknown id', async () => {
    const res = await request(app).delete('/api/webhooks/wh_999');
    expect(res.status).toBe(404);
  });
});

// ── Delivery log ──────────────────────────────────────────────────────────────

describe('GET /api/webhooks/deliveries/log', () => {
  it('returns delivery log', async () => {
    const res = await request(app).get('/api/webhooks/deliveries/log');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
  });
});

// ── Dispatch ──────────────────────────────────────────────────────────────────

describe('dispatchWebhookEvent', () => {
  it('calls fetch for matching webhooks', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://hook.test', ['credential_issued']);

    dispatchWebhookEvent({
      event: 'credential_issued',
      credential_id: 42,
      issuer: 'GABC',
      timestamp: '2026-01-01T00:00:00.000Z',
    });
    await _drainForTest();

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe('https://hook.test');
    expect(opts.method).toBe('POST');
    const body = JSON.parse(opts.body);
    expect(body.event).toBe('credential_issued');
    expect(body.credential_id).toBe(42);
  });

  it('does not call fetch for non-matching events', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://hook.test', ['credential_revoked']);

    dispatchWebhookEvent({
      event: 'credential_issued',
      credential_id: 1,
      timestamp: '2026-01-01T00:00:00.000Z',
    });
    await _drainForTest();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('dead-letters a delivery after exhausting retries', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('connection refused'));
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://bad.host', ['credential_attested']);

    dispatchWebhookEvent({
      event: 'credential_attested',
      credential_id: 7,
      timestamp: '2026-01-01T00:00:00.000Z',
    });
    await _drainForTest();

    const log = getDeliveryLog();
    expect(log).toHaveLength(1);
    expect(log[0].status).toBe('dead_letter');
    expect(log[0].attempts).toBe(4); // 1 initial + 3 retries
    expect(log[0].error).toContain('connection refused');
  });

  it('includes HMAC signature header when secret is set', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://secure.hook', ['credential_issued'], 'mysecret');

    dispatchWebhookEvent({
      event: 'credential_issued',
      credential_id: 1,
      timestamp: '2026-01-01T00:00:00.000Z',
    });
    await _drainForTest();

    const [, opts] = fetchMock.mock.calls[0];
    expect(opts.headers['X-QuorumProof-Signature']).toMatch(/^sha256=[a-f0-9]{64}$/);
  });
});

// ── Dead-letter queue + replay ─────────────────────────────────────────────────

describe('dead-letter queue', () => {
  it('lists dead-lettered deliveries via GET /api/webhooks/dead-letters', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('nope'));
    vi.stubGlobal('fetch', fetchMock);

    const reg = registerWebhook('https://bad.host', ['credential_issued']);
    dispatchWebhookEvent({ event: 'credential_issued', credential_id: 1, timestamp: 't' });
    await _drainForTest();

    expect(listDeadLetters()).toHaveLength(1);

    const res = await request(app).get('/api/webhooks/dead-letters');
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(1);
    expect(res.body.data[0].webhookId).toBe(reg.id);
  });

  it('replays a dead-lettered delivery via POST /api/webhooks/dead-letters/:id/replay', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('nope'));
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://bad.host', ['credential_issued']);
    dispatchWebhookEvent({ event: 'credential_issued', credential_id: 1, timestamp: 't' });
    await _drainForTest();

    const dead = getDeliveryLog()[0];
    expect(dead.status).toBe('dead_letter');

    fetchMock.mockResolvedValue({ ok: true });
    const replayRes = await request(app).post(`/api/webhooks/dead-letters/${dead.id}/replay`);
    expect(replayRes.status).toBe(202);
    await _drainForTest();

    const updated = getDeliveryLog().find(d => d.id === dead.id);
    expect(updated?.status).toBe('success');
  });

  it('returns 404 replaying an unknown delivery id', async () => {
    const res = await request(app).post('/api/webhooks/dead-letters/dlv_999/replay');
    expect(res.status).toBe(404);
  });

  it('returns 404 replaying a delivery that is not dead-lettered', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);
    registerWebhook('https://hook.test', ['credential_issued']);
    dispatchWebhookEvent({ event: 'credential_issued', credential_id: 1, timestamp: 't' });
    await _drainForTest();

    const delivered = getDeliveryLog()[0];
    expect(delivered.status).toBe('success');

    const res = await request(app).post(`/api/webhooks/dead-letters/${delivered.id}/replay`);
    expect(res.status).toBe(404);
  });
});

// ── Idempotent redelivery ───────────────────────────────────────────────────────

describe('idempotent redelivery', () => {
  it('sends the same X-QuorumProof-Delivery-Id header on every retry attempt', async () => {
    let calls = 0;
    const fetchMock = vi.fn().mockImplementation(async () => {
      calls++;
      if (calls < 3) throw new Error('flaky');
      return { ok: true };
    });
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://hook.test', ['credential_issued']);
    dispatchWebhookEvent({ event: 'credential_issued', credential_id: 1, timestamp: 't' });
    await _drainForTest();

    expect(fetchMock).toHaveBeenCalledTimes(3);
    const ids = fetchMock.mock.calls.map(([, opts]: [string, { headers: Record<string, string> }]) => opts.headers['X-QuorumProof-Delivery-Id']);
    expect(new Set(ids).size).toBe(1);
    expect(ids[0]).toMatch(/^dlv_/);
  });

  it('preserves the idempotency key across a dead-letter replay', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('down'));
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://hook.test', ['credential_issued']);
    dispatchWebhookEvent({ event: 'credential_issued', credential_id: 1, timestamp: 't' });
    await _drainForTest();

    const dead = getDeliveryLog()[0];
    const firstAttemptIds = fetchMock.mock.calls.map(([, opts]: [string, { headers: Record<string, string> }]) => opts.headers['X-QuorumProof-Delivery-Id']);

    fetchMock.mockClear();
    fetchMock.mockResolvedValue({ ok: true });
    replayDeadLetter(dead.id);
    await _drainForTest();

    const replayIds = fetchMock.mock.calls.map(([, opts]: [string, { headers: Record<string, string> }]) => opts.headers['X-QuorumProof-Delivery-Id']);
    expect(new Set([...firstAttemptIds, ...replayIds]).size).toBe(1);
    expect(replayIds[0]).toBe(dead.id);
  });
});

// ── Per-credential ordering under retry ─────────────────────────────────────────

describe('per-credential delivery ordering', () => {
  it('does not deliver a later event for the same credential until the earlier one reaches a terminal state', async () => {
    const order: string[] = [];
    const fetchMock = vi.fn().mockImplementation(async (_url: string, opts: { body: string }) => {
      const body = JSON.parse(opts.body);
      order.push(body.event);
      if (body.event === 'credential_issued' && order.filter(e => e === 'credential_issued').length < 2) {
        throw new Error('transient');
      }
      return { ok: true };
    });
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://hook.test', ['credential_issued', 'credential_attested']);

    dispatchWebhookEvent({ event: 'credential_issued', credential_id: 42, timestamp: 't1' });
    dispatchWebhookEvent({ event: 'credential_attested', credential_id: 42, timestamp: 't2' });

    await _drainForTest();

    expect(order).toEqual(['credential_issued', 'credential_issued', 'credential_attested']);
  });

  it('does not block events for a different credential behind a slow delivery', async () => {
    const order: number[] = [];
    const fetchMock = vi.fn().mockImplementation(async (_url: string, opts: { body: string }) => {
      const body = JSON.parse(opts.body);
      if (body.credential_id === 1) {
        await new Promise(r => setTimeout(r, 30));
      }
      order.push(body.credential_id);
      return { ok: true };
    });
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://hook.test', ['credential_issued']);
    dispatchWebhookEvent({ event: 'credential_issued', credential_id: 1, timestamp: 't1' });
    dispatchWebhookEvent({ event: 'credential_issued', credential_id: 2, timestamp: 't2' });

    await _drainForTest();
    expect(order[0]).toBe(2);
  });
});

// ── Circuit breaker: unit ───────────────────────────────────────────────────────

describe('WebhookCircuitBreaker', () => {
  let dataDir: string;
  let breaker: WebhookCircuitBreaker;

  beforeEach(() => {
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cb-test-'));
    breaker = new WebhookCircuitBreaker({ dataDir, config: { failureThreshold: 3, resetTimeoutMs: 30, autoRecover: true } });
  });

  it('starts closed', () => {
    expect(breaker.getState('ep1')).toBe('closed');
  });

  it('trips open once consecutive failures reach the threshold', () => {
    breaker.recordFailure('ep1', 'e1');
    breaker.recordFailure('ep1', 'e2');
    expect(breaker.getState('ep1')).toBe('closed');

    breaker.recordFailure('ep1', 'e3');
    expect(breaker.getState('ep1')).toBe('open');
    expect(breaker.getActivation('ep1')?.reason).toBe('e3');
  });

  it('stays open before the reset timeout elapses', () => {
    for (let i = 0; i < 3; i++) breaker.recordFailure('ep1', 'fail');
    expect(breaker.getStateWithRecovery('ep1')).toBe('open');
  });

  it('auto-recovers to closed after the reset timeout elapses (half-open trial)', async () => {
    for (let i = 0; i < 3; i++) breaker.recordFailure('ep1', 'fail');
    expect(breaker.getState('ep1')).toBe('open');

    await new Promise(r => setTimeout(r, 60));
    expect(breaker.getStateWithRecovery('ep1')).toBe('closed');
  });

  it('does not auto-recover when autoRecover is disabled', async () => {
    const manualDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cb-test-manual-'));
    const manual = new WebhookCircuitBreaker({ dataDir: manualDataDir, config: { failureThreshold: 1, resetTimeoutMs: 10, autoRecover: false } });
    manual.recordFailure('ep1', 'fail');
    expect(manual.getState('ep1')).toBe('open');

    await new Promise(r => setTimeout(r, 30));
    expect(manual.getStateWithRecovery('ep1')).toBe('open');
  });

  it('resume() manually closes the breaker and clears the activation', () => {
    for (let i = 0; i < 3; i++) breaker.recordFailure('ep1', 'fail');
    breaker.resume('ep1');
    expect(breaker.getState('ep1')).toBe('closed');
    expect(breaker.getActivation('ep1')).toBeUndefined();
  });

  it('recordSuccess resets the consecutive-failure count', () => {
    breaker.recordFailure('ep1', 'fail');
    breaker.recordFailure('ep1', 'fail');
    breaker.recordSuccess('ep1');
    breaker.recordFailure('ep1', 'fail');
    breaker.recordFailure('ep1', 'fail');
    expect(breaker.getState('ep1')).toBe('closed');
  });

  it('tracks each endpoint independently', () => {
    for (let i = 0; i < 3; i++) breaker.recordFailure('ep1', 'fail');
    expect(breaker.getState('ep1')).toBe('open');
    expect(breaker.getState('ep2')).toBe('closed');
  });

  it('persists trip state across a simulated restart', () => {
    for (let i = 0; i < 3; i++) breaker.recordFailure('ep1', 'fail');
    const restarted = new WebhookCircuitBreaker({ dataDir, config: { failureThreshold: 3, resetTimeoutMs: 30, autoRecover: true } });
    expect(restarted.getState('ep1')).toBe('open');
  });
});

// ── Circuit breaker: integrated with delivery ───────────────────────────────────

describe('circuit breaker integration with delivery', () => {
  it('stops calling a tripped endpoint mid-delivery, then resumes after recovery', async () => {
    freshService({
      maxRetries: 5,
      retryDelaysMs: [0, 0, 0, 0, 0],
      breakerConfig: { failureThreshold: 2, resetTimeoutMs: 20, autoRecover: true },
    });

    const fetchMock = vi.fn().mockRejectedValue(new Error('endpoint down'));
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://flaky.host', ['credential_issued']);
    dispatchWebhookEvent({ event: 'credential_issued', credential_id: 1, timestamp: 't1' });
    await _drainForTest();

    // Only the first 2 attempts reach the network before the breaker trips; the
    // remaining retry budget is consumed failing fast without a fetch call.
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const record = getDeliveryLog()[0];
    expect(record.status).toBe('dead_letter');
    expect(record.attempts).toBe(6); // 1 initial + 5 retries
    expect(record.error).toMatch(/circuit breaker open/);

    // After the reset timeout, the next delivery gets a half-open trial call.
    await new Promise(r => setTimeout(r, 60));
    fetchMock.mockResolvedValue({ ok: true });
    dispatchWebhookEvent({ event: 'credential_issued', credential_id: 2, timestamp: 't2' });
    await _drainForTest();

    const secondRecord = getDeliveryLog().find(d => d.credentialId === 2);
    expect(secondRecord?.status).toBe('success');
  });
});

// ── Integration: broadcastEvent wiring ──────────────────────────────────────────

describe('webhook integration with broadcastEvent', () => {
  it('fires webhook on credential_issued event via broadcastEvent', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://example.com/hook', ['credential_issued']);

    const { broadcastEvent } = await import('../src/index.js');
    broadcastEvent({
      type: 'credential_issued',
      credential_id: 42,
      issuer: 'GABC123',
      holder: 'GXYZ789',
      timestamp: new Date().toISOString(),
    });
    await _drainForTest();

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe('https://example.com/hook');
    const body = JSON.parse(opts.body);
    expect(body.event).toBe('credential_issued');
    expect(body.credential_id).toBe(42);
  });

  it('does not fire webhook for credential_revoked when registered for credential_issued', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://example.com/hook', ['credential_issued']);

    const { broadcastEvent } = await import('../src/index.js');
    broadcastEvent({
      type: 'credential_revoked',
      credential_id: 42,
      issuer: 'GABC123',
      timestamp: new Date().toISOString(),
    });
    await _drainForTest();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('stops firing webhooks after deletion', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);

    const reg = registerWebhook('https://example.com/hook', ['credential_revoked']);

    const { broadcastEvent } = await import('../src/index.js');
    broadcastEvent({
      type: 'credential_revoked',
      credential_id: 1,
      timestamp: new Date().toISOString(),
    });
    await _drainForTest();

    expect(fetchMock).toHaveBeenCalledOnce();
    fetchMock.mockClear();

    const deleted = deleteWebhook(reg.id);
    expect(deleted).toBe(true);

    broadcastEvent({
      type: 'credential_revoked',
      credential_id: 2,
      timestamp: new Date().toISOString(),
    });
    await _drainForTest();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fires webhook on credential_attested event', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://example.com/hook', ['credential_attested']);

    const { broadcastEvent } = await import('../src/index.js');
    broadcastEvent({
      type: 'credential_attested',
      credential_id: 99,
      attestor: 'GATT456',
      timestamp: new Date().toISOString(),
    });
    await _drainForTest();

    expect(fetchMock).toHaveBeenCalledOnce();
    const [, opts] = fetchMock.mock.calls[0];
    const body = JSON.parse(opts.body);
    expect(body.event).toBe('credential_attested');
    expect(body.credential_id).toBe(99);
    expect(body.attestor).toBe('GATT456');
  });

  it('does not fire webhook for events not registered', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://example.com/hook', ['credential_issued']);

    const { broadcastEvent } = await import('../src/index.js');
    broadcastEvent({
      type: 'credential_attested',
      credential_id: 1,
      timestamp: new Date().toISOString(),
    });
    await _drainForTest();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('still broadcasts to WS clients even when webhook dispatch fails', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('endpoint down'));
    vi.stubGlobal('fetch', fetchMock);

    registerWebhook('https://dead.endpoint', ['credential_issued']);

    const { broadcastEvent } = await import('../src/index.js');
    const result = broadcastEvent({
      type: 'credential_issued',
      credential_id: 123,
      timestamp: new Date().toISOString(),
    });

    // broadcastEvent returns the WS recipient count — should work regardless of webhook failure
    expect(typeof result).toBe('number');

    await _drainForTest();

    // Webhook delivery should have failed
    const log = getDeliveryLog();
    expect(log).toHaveLength(1);
    expect(log[0].status).toBe('dead_letter');
  });
});

// ── Restart durability ──────────────────────────────────────────────────────────

describe('restart durability', () => {
  it('resumes an in-flight delivery from its last recorded attempt after a simulated process restart', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'webhooks-restart-'));
    const store1 = new WebhookStore({ dataDir });

    const reg = store1.registerWebhook('https://recovers.test', ['credential_issued']);
    const delivery = store1.createDelivery(reg.id, 55, 'credential_issued', {
      event: 'credential_issued',
      credential_id: 55,
      timestamp: '2026-01-01T00:00:00.000Z',
    });
    // Simulate a crash mid-retry: one attempt already recorded to disk, process dies before the next.
    delivery.attempts = 1;
    delivery.lastAttemptAt = '2026-01-01T00:00:01.000Z';
    delivery.error = 'ECONNRESET';
    store1.saveDelivery(delivery);

    // "Restart": brand-new store/breaker instances reading the same data directory.
    const store2 = new WebhookStore({ dataDir });
    const breaker2 = new WebhookCircuitBreaker({ dataDir });

    expect(store2.getWebhook(reg.id)).toBeDefined();
    const recovered = store2.getDelivery(delivery.id);
    expect(recovered?.status).toBe('pending');
    expect(recovered?.attempts).toBe(1);

    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);

    const service2 = _configureForTest({ store: store2, breaker: breaker2, maxRetries: 3, retryDelaysMs: [0, 0, 0] });
    await service2._drain();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, opts] = fetchMock.mock.calls[0];
    expect(opts.headers['X-QuorumProof-Delivery-Id']).toBe(delivery.id);

    const final = getDeliveryLog().find(d => d.id === delivery.id);
    expect(final?.status).toBe('success');
    expect(final?.attempts).toBe(2); // resumed from 1, needed exactly one more attempt
  });

  it('registrations survive a restart independent of delivery state', () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'webhooks-restart-reg-'));
    const store1 = new WebhookStore({ dataDir });
    const reg = store1.registerWebhook('https://a.test', ['credential_revoked'], 'shh');

    const store2 = new WebhookStore({ dataDir });
    const reloaded = store2.getWebhook(reg.id);
    expect(reloaded).toEqual(reg);
  });
});
