// AgentGate front end. Talks only to our own server (/api/*); no Clocked key in the browser.
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const pct = (x) => (x == null ? '–' : `${Math.round(x * 100)}%`);
const COLORS = { allow: 'var(--allow)', review: 'var(--review)', block: 'var(--block)' };
const VERDICT_COPY = {
  allow: 'Safe to hand to the agent',
  review: 'Hold for a human before the agent acts',
  block: 'Do not let the agent read or run this',
};
let samples = [];
let lastResult = null;

async function loadSamples() {
  samples = await (await fetch('/api/samples')).json();
  $('#samples').innerHTML = samples
    .map((s) => `<button class="sample" data-id="${s.id}" title="${esc(s.title)}">${esc(s.title)}</button>`)
    .join('');
  document.querySelectorAll('.sample').forEach((b) => b.addEventListener('click', () => pick(b.dataset.id)));
}

function pick(id) {
  const s = samples.find((x) => x.id === id);
  if (!s) return;
  $('#text').value = s.text;
  $('#kind').value = s.kind;
  $('#task').value = s.task;
  document.querySelectorAll('.sample').forEach((b) => b.classList.toggle('on', b.dataset.id === id));
  updateChars();
}

function updateChars() { $('#chars').textContent = `${Array.from($('#text').value).length.toLocaleString()} characters`; }

function setProgress(phase, hasScript) {
  const p = $('#progress');
  p.classList.remove('hidden');
  p.querySelectorAll('.step').forEach((el) => {
    el.className = 'step';
    const s = el.dataset.s;
    const phase1 = ['pii', 'injection', 'script'].includes(s);
    if (phase === 1 && phase1) el.classList.add('run');
    if (phase === 'done') el.classList.add('done');
    if (s === 'script' && hasScript === false) el.classList.add('skip');
  });
}

async function run() {
  const text = $('#text').value;
  if (!text.trim()) { $('#text').focus(); return; }
  $('#run').disabled = true; $('#run').textContent = 'Checking…';
  $('#error').classList.add('hidden');
  $('#results').classList.add('hidden');
  setProgress(1);
  const t = setTimeout(() => {
    document.querySelectorAll('.step').forEach((el) => {
      el.classList.toggle('run', ['decide', 'fill'].includes(el.dataset.s));
      if (['pii', 'injection', 'script'].includes(el.dataset.s)) el.classList.add('done');
    });
  }, 900);
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, kind: $('#kind').value, task: $('#task').value }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    lastResult = { ...data, text };
    clearTimeout(t);
    setProgress('done', data.inspect.length > 0);
    render(lastResult);
  } catch (e) {
    clearTimeout(t);
    $('#progress').classList.add('hidden');
    $('#error').textContent = `${e.message} The content was not passed to any agent.`;
    $('#error').classList.remove('hidden');
  } finally {
    $('#run').disabled = false; $('#run').textContent = 'Run pre-flight check';
  }
}

// ---------- rendering ----------
function render(r) {
  renderVerdict(r);
  renderAnnotated(r.text, r.spans);
  renderProtect(r.protect);
  renderGuard(r.guard);
  renderInspect(r.inspect);
  renderAudit(r);
  renderTrace(r);
  $('#results').classList.remove('hidden');
  $('#verdict').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderVerdict(r) {
  const v = r.verdict;
  const el = $('#verdict');
  el.className = `card verdict ${v}`;
  const probs = r.probabilities || {};
  const bars = ['allow', 'review', 'block']
    .map((k) => `<span>${k}</span><div class="bar"><i style="width:${(probs[k] || 0) * 100}%;background:${COLORS[k]}"></i></div><span>${pct(probs[k])}</span>`)
    .join('');
  const d = r.decide;
  const concerns = d ? d.concerns.selected : [];
  const act = d ? d.agent_may_act : null;
  el.innerHTML = `
    <div class="badge">${v.toUpperCase()}<small>${r.decidedBy === 'clocked-decide' ? 'Clocked Decide' : 'fallback rules'}</small></div>
    <div class="vbody">
      <h3>${VERDICT_COPY[v]}</h3>
      ${r.probabilities ? `<div class="bars">${bars}</div>` : '<div class="note">Decide was unavailable, so a conservative rule set chose this verdict.</div>'}
      <div class="chips">${concerns.length ? concerns.map((c) => `<span class="chip">${esc(c.replace(/_/g, ' '))} · ${pct(d.concerns.probabilities[c])}</span>`).join('') : '<span class="chip">no concerns raised</span>'}</div>
      ${act ? `<div class="note"><b>Agent may act without asking you:</b> ${act.decision ? 'yes' : 'no'} (${pct(act.noul)} yes)</div>` : ''}
      ${(r.floor || []).map((f) => `<div class="note">⚠ ${esc(f)}</div>`).join('')}
    </div>`;
}

function renderAnnotated(text, spans) {
  const cps = Array.from(text);
  const marks = cps.map(() => ({ kinds: new Set(), labels: new Set() }));
  for (const s of spans) {
    for (let i = Math.max(0, s.start); i < Math.min(cps.length, s.end); i++) {
      marks[i].kinds.add(s.kind);
      marks[i].labels.add(`${s.kind === 'pii' ? 'Protect' : s.kind === 'injection' ? 'Guard' : 'Inspect'}: ${s.label}`);
    }
  }
  let html = '', i = 0;
  while (i < cps.length) {
    const key = [...marks[i].kinds].sort().join(' ');
    let j = i;
    while (j < cps.length && [...marks[j].kinds].sort().join(' ') === key) j++;
    const chunk = esc(cps.slice(i, j).join(''));
    html += key ? `<mark class="hl ${key}" title="${esc([...marks[i].labels].join(' · '))}">${chunk}</mark>` : chunk;
    i = j;
  }
  $('#annotated').innerHTML = html;
}

function renderProtect(p) {
  const el = $('#det-pii');
  if (p.error) { el.innerHTML = head('Protect', '/pii') + `<span class="tag mid">check failed</span><p class="muted">${esc(p.error)}</p>`; return; }
  const n = p.entities.length;
  const counts = Object.entries(p.counts || {}).map(([k, v]) => `<span class="chip">${esc(k.replace(/_/g, ' '))} × ${v}</span>`).join('');
  el.innerHTML = head('Protect', '/pii') + `
    <div class="big">${n}</div><div>${n === 1 ? 'piece' : 'pieces'} of personal data masked ${n ? '<span class="tag mid">masked</span>' : '<span class="tag ok">none found</span>'}</div>
    <div class="chips">${counts}</div>
    <div class="masked" id="maskedText">${esc(p.masked)}</div>
    <button class="ghost" id="copyMasked">Copy masked copy for the agent</button>`;
  $('#copyMasked').onclick = async () => { await navigator.clipboard.writeText(p.masked); $('#copyMasked').textContent = 'Copied ✓'; };
}

function renderGuard(g) {
  const el = $('#det-inj');
  if (g.error) { el.innerHTML = head('Guard', '/injection') + `<span class="tag mid">check failed</span><p class="muted">${esc(g.error)}</p>`; return; }
  const bad = g.verdict === 'injection';
  const top = Object.entries(g.categories || {}).sort((a, b) => b[1] - a[1]).slice(0, 3);
  el.innerHTML = head('Guard', '/injection') + `
    <div class="big">${pct(g.injection)}</div><div>chance this is prompt injection <span class="tag ${bad ? 'bad' : 'ok'}">${esc(g.verdict)}</span></div>
    <dl class="kv" style="margin-top:8px"><dt>Category</dt><dd>${esc(g.category)}</dd><dt>Severity</dt><dd>${esc(g.severity || '–')}</dd></dl>
    <div class="bars" style="grid-template-columns:1fr 70px 44px">${top.map(([k, v]) => `<span>${esc(k)}</span><div class="bar"><i style="width:${v * 100}%;background:${k === 'benign' ? 'var(--allow)' : 'var(--inj-ink)'}"></i></div><span>${pct(v)}</span>`).join('')}</div>
    ${(g.evidence || []).length ? '<b style="font-size:13px">Evidence</b>' + g.evidence.slice(0, 4).map((e) => `<div class="quote">${esc(e.quote)}</div>`).join('') : '<p class="muted">No passages flagged.</p>'}`;
}

function renderInspect(list) {
  const el = $('#det-scr');
  if (!list.length) {
    el.innerHTML = head('Inspect', '/script') + `<div class="big">–</div><div>No script or command lines found <span class="tag off">skipped</span></div><p class="muted">Inspect only runs when there is code to read, so no credits are spent on plain text.</p>`;
    return;
  }
  el.innerHTML = head('Inspect', '/script') + list.map((s) => {
    if (s.error) return `<span class="tag mid">check failed</span><p class="muted">${esc(s.error)}</p>`;
    const bad = s.verdict !== 'benign';
    return `<div class="big">${pct(s.malicious)}</div><div>chance the script is malicious <span class="tag ${bad ? 'bad' : 'ok'}">${esc(s.verdict)}</span></div>
      <dl class="kv" style="margin-top:8px"><dt>Behaviour</dt><dd>${esc(s.category)}</dd><dt>Severity</dt><dd>${esc(s.severity || '–')}</dd><dt>Suspicious</dt><dd>${pct(s.suspicious)}</dd></dl>
      ${(s.evidence || []).length ? '<b style="font-size:13px">Risky lines</b>' + s.evidence.slice(0, 6).map((e) => `<div class="quote s">${esc(e.line)}</div>`).join('') : '<p class="muted">No risky lines flagged. The code was read, never executed.</p>'}`;
  }).join('<hr>');
}

function renderAudit(r) {
  const el = $('#audit');
  const f = r.fill;
  if (!f || f.error) {
    el.innerHTML = `<h2>Audit record <span class="ep muted">/fill</span></h2><p class="muted">${esc(f ? f.error : 'unavailable')}</p>`;
  } else {
    const acts = f.requested_actions?.value || [];
    el.innerHTML = `<div class="card-h"><h2>Audit record <span class="det"><span class="ep">/fill</span></span></h2><button class="ghost" id="dl">Download JSON</button></div>
      <dl class="kv">
        <dt>Content type</dt><dd>${esc(f.content_type?.value)} <span class="muted">(${pct(f.content_type?.confidence)})</span></dd>
        <dt>Summary</dt><dd>${esc(f.summary?.value)}</dd>
        <dt>Requested actions</dt><dd>${acts.length ? `<ul style="margin:0;padding-left:16px">${acts.map((a) => `<li>${esc(a)}</li>`).join('')}</ul>` : '<span class="muted">none</span>'}</dd>
        <dt>Pressure to act</dt><dd>${esc(f.pressure?.value)}</dd>
        <dt>Links / downloads</dt><dd>${f.has_links_or_downloads?.value ? 'yes' : 'no'}</dd>
        <dt>Content hash</dt><dd><code>${r.audit.content_sha256.slice(0, 16)}…</code></dd>
      </dl>`;
  }
  const dl = $('#dl');
  if (dl) dl.onclick = () => {
    const blob = new Blob([JSON.stringify(r.audit, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `agentgate-audit-${r.audit.content_sha256.slice(0, 8)}.json`;
    a.click();
  };
}

function renderTrace(r) {
  const rows = r.calls.map((c) => `<tr><td><code>/${c.endpoint === 'pii' ? 'pii' : c.endpoint}</code></td><td>${c.ok ? '✓' : `✗ <span class="muted">${esc(c.error || '')}</span>`}</td><td class="num">${c.modelMs || '–'}</td><td class="num">${c.credits}</td></tr>`).join('');
  $('#trace').innerHTML = `<h2>Pipeline trace</h2>
    <table><thead><tr><th>Clocked call</th><th>Status</th><th class="num">model ms</th><th class="num">credits</th></tr></thead><tbody>${rows}</tbody>
    <tfoot><tr><th colspan="3">Total ${r.cached ? '<span class="muted">(cached result, nothing billed again)</span>' : ''}</th><th class="num">${r.credits}</th></tr></tfoot></table>
    <p class="muted" style="font-size:12px">Wall-clock ${(r.elapsedMs / 1000).toFixed(1)} s. Protect, Guard and Inspect run in parallel; Decide and Fill run in parallel on the masked text.</p>`;
}

const head = (name, ep) => `<h2>${name} <span class="ep">${ep}</span></h2>`;

$('#run').addEventListener('click', run);
$('#text').addEventListener('input', updateChars);
$('#text').addEventListener('keydown', (e) => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run(); });
loadSamples().then(() => pick('invoice-email'));
