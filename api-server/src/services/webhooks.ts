/**
 * Webhook Service — Issue #926
 * Registers, stores, and delivers webhook events with durable, ordered,
 * circuit-breaker-gated retry.
 *
 * Supported events: credential_issued, credential_attested, credential_revoked
 *
 * Delivery guarantee: **at-least-once, with a stable idempotency key** — NOT
 * exactly-once. Every delivery attempt (including all retries and any DLQ
 * replay) for a given logical delivery carries the same value in the
 * `X-QuorumProof-Delivery-Id` header. A receiver that has already processed
 * a delivery id can safely discard a repeat without reprocessing side
 * effects. Duplicates can still happen — e.g. the endpoint accepts and
 * processes the request but the response is lost before this service sees
 * it, so a retry is sent for what was actually a successful delivery — the
 * idempotency key exists precisely so receivers can absorb that case rather
 * than this service trying (and failing) to guarantee it never occurs.
 *
 * Ordering guarantee: deliveries for the same (webhook, credential_id) pair
 * are strictly ordered, including across retries — the next event for that
 * pair is not attempted until the current one reaches a terminal state
 * (success or dead-lettered). Ordering across *different* credentials, or
 * once a delivery has been dead-lettered and a later one for the same
 * credential proceeds past it, is not guaranteed; a dead-lettered delivery
 * requires explicit replay (see replayDeadLetter) and replay is not
 * re-inserted at its original position in the sequence.
 */
import { WebhookStore, type WebhookEvent, type WebhookRegistration, type WebhookPayload, type DeliveryRecord } from './webhookStore.js';
import { WebhookCircuitBreaker } from './webhookCircuitBreaker.js';

export type { WebhookEvent, WebhookRegistration, WebhookPayload, DeliveryRecord };

const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_DELAYS_MS = [1_000, 5_000, 15_000];

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export interface WebhookServiceOptions {
  store?: WebhookStore;
  breaker?: WebhookCircuitBreaker;
  maxRetries?: number;
  retryDelaysMs?: number[];
}

export class WebhookService {
  readonly store: WebhookStore;
  readonly breaker: WebhookCircuitBreaker;
  private readonly maxRetries: number;
  private readonly retryDelaysMs: number[];
  /** One promise chain per (webhookId, credentialId) — enforces strict per-credential ordering. */
  private readonly chains = new Map<string, Promise<void>>();

  constructor(options: WebhookServiceOptions = {}) {
    this.store = options.store ?? new WebhookStore();
    this.breaker = options.breaker ?? new WebhookCircuitBreaker();
    this.maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.retryDelaysMs = options.retryDelaysMs ?? DEFAULT_RETRY_DELAYS_MS;
    this.recoverPendingDeliveries();
  }

  /** Rebuild in-memory ordering chains from durable pending deliveries — runs the "restart recovery" path at construction. */
  private recoverPendingDeliveries(): void {
    for (const [orderKey, records] of this.store.listPendingByOrderKey()) {
      let chain = Promise.resolve();
      for (const record of records) {
        chain = chain.then(() => this.processDelivery(record));
      }
      this.chains.set(orderKey, chain.catch(() => {}));
    }
  }

  private enqueue(record: DeliveryRecord): void {
    const prior = this.chains.get(record.orderKey) ?? Promise.resolve();
    const next = prior.then(() => this.processDelivery(record)).catch(() => {});
    this.chains.set(record.orderKey, next);
  }

  registerWebhook(url: string, events: WebhookEvent[], secret?: string): WebhookRegistration {
    return this.store.registerWebhook(url, events, secret);
  }

  listWebhooks(): WebhookRegistration[] {
    return this.store.listWebhooks();
  }

  getWebhook(id: string): WebhookRegistration | undefined {
    return this.store.getWebhook(id);
  }

  deleteWebhook(id: string): boolean {
    return this.store.deleteWebhook(id);
  }

  getDeliveryLog(): DeliveryRecord[] {
    return this.store.listDeliveries();
  }

  listDeadLetters(): DeliveryRecord[] {
    return this.store.listDeadLetters();
  }

  /** Called after broadcastEvent — durably enqueues delivery to every webhook subscribed to the event. */
  dispatchWebhookEvent(payload: WebhookPayload): void {
    const event = payload.event as WebhookEvent;
    for (const reg of this.store.listWebhooks()) {
      if (!reg.events.includes(event)) continue;
      const record = this.store.createDelivery(reg.id, payload.credential_id, payload.event, payload);
      this.enqueue(record);
    }
  }

  /** Re-inject a dead-lettered delivery for another attempt, keeping its idempotency key but resetting attempts. */
  replayDeadLetter(id: string): DeliveryRecord | undefined {
    const record = this.store.getDelivery(id);
    if (!record || record.status !== 'dead_letter') return undefined;

    record.status = 'pending';
    record.attempts = 0;
    record.error = undefined;
    record.completedAt = undefined;
    this.store.saveDelivery(record);
    this.enqueue(record);
    return record;
  }

  private async processDelivery(queuedRecord: DeliveryRecord): Promise<void> {
    // Re-read from the store: a prior chain link (or a restart-recovery replay) may already have
    // resolved this delivery, or its attempt count may have advanced since it was queued.
    const record = this.store.getDelivery(queuedRecord.id) ?? queuedRecord;
    if (record.status !== 'pending') return;

    const reg = this.store.getWebhook(record.webhookId);
    if (!reg) {
      record.status = 'dead_letter';
      record.error = 'webhook registration no longer exists';
      record.completedAt = new Date().toISOString();
      this.store.saveDelivery(record);
      console.error(`[webhook] delivery ${record.id} dead-lettered: webhook registration no longer exists`);
      return;
    }

    const body = JSON.stringify(record.payload);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-QuorumProof-Delivery-Id': record.id,
    };
    if (reg.secret) {
      const { createHmac } = await import('crypto');
      headers['X-QuorumProof-Signature'] = `sha256=${createHmac('sha256', reg.secret).update(body).digest('hex')}`;
    }

    for (let attempt = record.attempts; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        await sleep(this.retryDelaysMs[attempt - 1]);
      }

      record.attempts = attempt + 1;
      record.lastAttemptAt = new Date().toISOString();

      if (this.breaker.getStateWithRecovery(reg.id) === 'open') {
        record.error = 'circuit breaker open for this endpoint';
        this.store.saveDelivery(record);
        continue;
      }

      try {
        const res = await fetch(reg.url, { method: 'POST', headers, body });
        if (res.ok) {
          record.status = 'success';
          record.completedAt = new Date().toISOString();
          this.store.saveDelivery(record);
          this.breaker.recordSuccess(reg.id);
          return;
        }
        record.error = `HTTP ${res.status}`;
        this.breaker.recordFailure(reg.id, record.error);
      } catch (err: unknown) {
        record.error = err instanceof Error ? err.message : String(err);
        this.breaker.recordFailure(reg.id, record.error);
      }
      this.store.saveDelivery(record);
    }

    record.status = 'dead_letter';
    record.completedAt = new Date().toISOString();
    this.store.saveDelivery(record);
    console.error(`[webhook] delivery ${record.id} dead-lettered after ${record.attempts} attempts: ${record.error}`);
  }

  /** Wait for all currently-queued deliveries to reach a terminal state — test helper. */
  async _drain(): Promise<void> {
    let prev = -1;
    // Draining can itself enqueue more chain links (retries) after the snapshot below is
    // awaited, so keep draining until the chain count stabilizes.
    while (this.chains.size !== prev) {
      prev = this.chains.size;
      await Promise.allSettled(Array.from(this.chains.values()));
    }
  }
}

let service = new WebhookService();

export function registerWebhook(url: string, events: WebhookEvent[], secret?: string): WebhookRegistration {
  return service.registerWebhook(url, events, secret);
}

export function listWebhooks(): WebhookRegistration[] {
  return service.listWebhooks();
}

export function getWebhook(id: string): WebhookRegistration | undefined {
  return service.getWebhook(id);
}

export function deleteWebhook(id: string): boolean {
  return service.deleteWebhook(id);
}

export function getDeliveryLog(): DeliveryRecord[] {
  return service.getDeliveryLog();
}

export function listDeadLetters(): DeliveryRecord[] {
  return service.listDeadLetters();
}

export function replayDeadLetter(id: string): DeliveryRecord | undefined {
  return service.replayDeadLetter(id);
}

export function dispatchWebhookEvent(payload: WebhookPayload): void {
  service.dispatchWebhookEvent(payload);
}

/** Test-only: point the module-level service at fresh (typically temp-dir-backed) store/breaker instances. */
export function _configureForTest(options: WebhookServiceOptions): WebhookService {
  service = new WebhookService(options);
  return service;
}

/** Test-only: await all in-flight deliveries on the current service. */
export function _drainForTest(): Promise<void> {
  return service._drain();
}

/** Test-only: access the live service instance directly (e.g. to read store/breaker for restart-simulation tests). */
export function _getServiceForTest(): WebhookService {
  return service;
}
