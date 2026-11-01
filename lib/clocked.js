// Minimal server-side Clocked client.
// Follows https://clocked.rezolve.ai/docs/authentication and /docs/errors:
//  - Bearer key from the environment (never sent to the browser, never logged)
//  - one fresh UUID Idempotency-Key per logical request, REUSED on retries
//  - bounded exponential backoff on 429 / 5xx / network errors
//  - stop retrying when the service says retryAsNew
const crypto = require('crypto');

const BASE = process.env.CLOCKED_BASE_URL || 'https://clocked.rezolve.ai/clocked';
const TIMEOUT_MS = 110_000; // gateway allows up to 110 s per model request
const MAX_ATTEMPTS = 3;

class ClockedError extends Error {
  constructor(message, status, extra = {}) {
    super(message);
    this.status = status;
    Object.assign(this, extra);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function call(endpoint, payload) {
  const key = process.env.CLOCKED_API_KEY;
  if (!key) throw new ClockedError('CLOCKED_API_KEY is not set on the server', 500);

  const idempotencyKey = crypto.randomUUID(); // one logical request = one key
  const body = JSON.stringify(payload);
  let lastErr;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const started = Date.now();
    try {
      const res = await fetch(`${BASE}/${endpoint}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${key}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': idempotencyKey,
        },
        body,
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      const meta = {
        endpoint,
        credits: Number(res.headers.get('x-clocked-credits') || 0),
        modelMs: Number(res.headers.get('x-clocked-model-ms') || 0),
        roundTripMs: Date.now() - started,
        attempts: attempt,
        replay: res.headers.get('x-clocked-transport') === 'replay',
      };
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { data = { error: text.slice(0, 300) }; }

      if (res.ok) return { data, meta };

      const retryable = res.status === 429 || res.status >= 500;
      lastErr = new ClockedError(data.error || `HTTP ${res.status}`, res.status, { meta, retryAsNew: !!data.retryAsNew });
      if (!retryable || data.retryAsNew) throw lastErr;
    } catch (err) {
      if (err instanceof ClockedError && (err.status < 500 && err.status !== 429)) throw err;
      if (err instanceof ClockedError && err.retryAsNew) throw err;
      lastErr = err instanceof ClockedError ? err : new ClockedError(`Network error: ${err.message}`, 0);
    }
    if (attempt < MAX_ATTEMPTS) await sleep(400 * 2 ** (attempt - 1) + Math.random() * 200);
  }
  throw lastErr;
}

module.exports = { call, ClockedError };
