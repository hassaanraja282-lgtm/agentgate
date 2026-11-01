// AgentGate server. All Clocked calls happen here; the browser never sees the API key.
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { scan } = require('./lib/gate');
const samples = require('./lib/samples');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const MAX_CHARS = Number(process.env.MAX_CHARS || 12000);
const DAILY_CREDIT_CAP = Number(process.env.DAILY_CREDIT_CAP || 4000); // protects the demo's credits
const PER_IP_PER_10MIN = Number(process.env.PER_IP_PER_10MIN || 12);
const KINDS = ['email', 'webpage', 'ticket', 'chat', 'script', 'document'];

// Small in-memory cache: identical input → identical result, no second bill.
const cache = new Map();
const CACHE_MAX = 200;
// Usage guards for the public demo
let day = new Date().toISOString().slice(0, 10), creditsToday = 0;
const hits = new Map();

function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
  if (arr.length >= PER_IP_PER_10MIN) return true;
  arr.push(now); hits.set(ip, arr);
  return false;
}

app.get('/api/samples', (_req, res) => res.json(samples));

app.get('/api/health', (_req, res) =>
  res.json({ ok: true, keyConfigured: !!process.env.CLOCKED_API_KEY, creditsToday, dailyCap: DAILY_CREDIT_CAP })
);

app.post('/api/scan', async (req, res) => {
  const text = typeof req.body.text === 'string' ? req.body.text : '';
  const kind = KINDS.includes(req.body.kind) ? req.body.kind : 'email';
  const task = typeof req.body.task === 'string' ? req.body.task.trim() : '';
  if (!text.trim()) return res.status(400).json({ error: 'Paste some content to scan.' });
  if (Array.from(text).length > MAX_CHARS) return res.status(413).json({ error: `Demo limit is ${MAX_CHARS} characters.` });

  const key = crypto.createHash('sha256').update(`${kind}\n${task}\n${text}`).digest('hex');
  if (cache.has(key)) return res.json({ ...cache.get(key), cached: true });

  const today = new Date().toISOString().slice(0, 10);
  if (today !== day) { day = today; creditsToday = 0; }
  if (creditsToday >= DAILY_CREDIT_CAP)
    return res.status(429).json({ error: 'The public demo has used its daily credit budget. Try a built-in sample (cached) or run it locally.' });
  if (rateLimited(req.ip)) return res.status(429).json({ error: 'Too many scans from your network. Please wait a few minutes.' });

  try {
    const result = await scan({ text, kind, task });
    creditsToday += result.credits;
    if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value);
    cache.set(key, result);
    // Log only metadata, never content, findings or headers.
    console.log(`[scan] kind=${kind} chars=${text.length} verdict=${result.verdict} credits=${result.credits} ms=${result.elapsedMs}`);
    res.json(result);
  } catch (err) {
    console.error('[scan] failed:', err.message);
    res.status(502).json({ error: 'Scan failed unexpectedly. Nothing was allowed.' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`AgentGate listening on :${port}`));
