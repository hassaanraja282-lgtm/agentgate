// Runs every built-in sample through the real pipeline and checks the verdicts.
// Usage: CLOCKED_API_KEY=... npm run smoke     (about 150 credits for all five)
// Fail-closed check without spending credits:  CLOCKED_BASE_URL=http://127.0.0.1:9 npm run smoke -- --offline
const { scan } = require('../lib/gate');
const samples = require('../lib/samples');

const EXPECT = {
  'invoice-email': ['block'],
  webpage: ['block'],
  'ticket-pii': ['allow', 'review'], // personal data only; refund request may need a human
  'setup-script': ['block'],
  'it-ticket-safe': ['allow'],
};

(async () => {
  const offline = process.argv.includes('--offline');
  let failed = 0, credits = 0;
  for (const s of samples) {
    const r = await scan(s);
    credits += r.credits;
    const want = offline ? ['review', 'block'] : EXPECT[s.id];
    const ok = want.includes(r.verdict);
    if (!ok) failed++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${s.id.padEnd(15)} verdict=${r.verdict.padEnd(6)} by=${r.decidedBy.padEnd(14)} credits=${r.credits}` +
      (r.floor.length ? `  note: ${r.floor.join(' ')}` : ''));
  }
  console.log(`\n${samples.length - failed}/${samples.length} passed · ${credits} credits`);
  process.exit(failed ? 1 : 0);
})();
