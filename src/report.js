// Markdown report + questionnaire evidence drafts.

const sevIcon = { high: '🔴 High', medium: '🟠 Medium', low: '🟡 Low', info: '🔵 Info' };

function questionnaire(r) {
  const f = (t) => r.findings.filter(x => x.type === t);
  const s = r.signals;
  const subs = [...new Set(r.subprocessors.map(x => x.vendor))];
  const stored = Object.values(r.inventory).filter(v => v.stored.length).map(v => v.label);
  const row = (q, cat, status, answer) => ({ q, cat, status, answer });
  return [
    row('What personal data do you collect and store?', 'code', stored.length ? '✅ evidence' : '❓ review',
      stored.length ? `Code stores: ${stored.join('; ')}. See data map.` : 'No stored personal data detected by scan; confirm manually.'),
    row('Do you encrypt personal data at rest?', 'code', s.encryption && !f('unencrypted_sensitive').some(x => x.severity === 'high') ? '⚠️ partial' : '❌ gap',
      s.encryption ? 'Encryption primitives found in code; confirm field coverage + DB/disk encryption (cloud provider).' : 'No app-level encryption found. Add field encryption for sensitive data; confirm DB/disk encryption with cloud provider.'),
    row('How are passwords stored?', 'code', f('unhashed_password').length ? '❌ gap' : (s.passwordHashing ? '✅ evidence' : '❓ review'),
      s.passwordHashing ? 'Hashed with a password-hashing library (bcrypt/argon2/scrypt/pbkdf2) found in code.' : 'No hashing library found. If you use a managed auth provider, cite it instead.'),
    row('Do you log or expose personal data in logs?', 'code', f('pii_in_logs').length ? '❌ gap' : '✅ evidence',
      f('pii_in_logs').length ? `${f('pii_in_logs').length} log lines include personal data. Fix before answering "no".` : 'No personal data found in log statements.'),
    row('List your sub-processors.', 'policy', subs.length ? '✅ evidence' : '❓ review',
      subs.length ? subs.join(', ') + '. Plus your cloud host. Each needs a DPA.' : 'None detected in code; list hosting/email/payment providers manually.'),
    row('Do you have a data retention & deletion policy?', 'code + policy', f('no_retention').length ? '❌ gap' : '⚠️ partial',
      f('no_retention').length ? 'No deletion/retention logic in code. Needs a deletion path + retention schedule + written policy.' : `Deletion logic found (${s.erasureLogic.slice(0, 3).join(', ')}). Pair with a written retention schedule.`),
    row('How do you obtain and record user consent?', 'code + policy', f('no_consent').length ? '❌ gap' : (s.consentHandling ? '⚠️ partial' : '❓ review'),
      s.consentHandling ? 'Consent handling exists in code; confirm it records notice version + timestamp and supports withdrawal.' : 'No consent handling found.'),
    row('Can you detect and report a breach within 72 hours?', 'ops', s.monitoring ? '⚠️ partial' : '❌ gap',
      s.monitoring ? 'Logging/monitoring present. Still need: incident runbook, on-call owner, log retention ≥1 year.' : 'No monitoring found. Needs logging, alerting and an incident runbook.'),
    row('Where is data stored / is it transferred outside the country?', 'ops', r.findings.some(x => x.type === 'cross_border') ? '⚠️ partial' : '❓ review',
      (r.findings.find(x => x.type === 'cross_border') || {}).detail || 'Confirm hosting region with your cloud console.'),
    row('Do you have SOC 2 / ISO 27001?', 'certification', '❓ human', 'Not answerable from code. State current status / timeline honestly.'),
    row('Do you run background checks, security training, access reviews?', 'ops', '❓ human', 'Not answerable from code. Answer from HR/ops records.'),
  ];
}

function toMarkdown(r) {
  const c = { high: 0, medium: 0, low: 0, info: 0 };
  r.findings.forEach(f => c[f.severity]++);
  const out = [];
  out.push(`# trustdiff report`);
  out.push(`\n> Evidence for review, **not** a compliance certification. GDPR/DPDP references are pointers for your counsel, not legal advice.\n`);
  out.push(`**Scanned:** \`${r.root}\` · ${r.stats.files} files · ${r.stats.lines.toLocaleString()} lines · ${r.scannedAt.slice(0, 10)} · frameworks: ${r.frameworks.join(', ').toUpperCase()}\n`);
  out.push(`| 🔴 High | 🟠 Medium | 🟡 Low | 🔵 Info | Data categories | Sub-processors |\n|---|---|---|---|---|---|\n| ${c.high} | ${c.medium} | ${c.low} | ${c.info} | ${Object.keys(r.inventory).length} | ${new Set(r.subprocessors.map(s => s.vendor)).size} |\n`);

  out.push(`## 1. Personal-data map\n`);
  out.push(`| Category | Stored in | Seen in (files) | Example fields |\n|---|---|---|---|`);
  for (const v of Object.values(r.inventory).sort((a, b) => b.stored.length - a.stored.length))
    out.push(`| ${v.label} | ${v.stored.length ? v.stored.slice(0, 3).map(x => '`' + x + '`').join(', ') + (v.stored.length > 3 ? ` +${v.stored.length - 3}` : '') : '—'} | ${v.seenIn} | ${v.fields.slice(0, 5).map(x => '`' + x + '`').join(', ')} |`);

  out.push(`\n## 2. Sub-processor register (draft)\n`);
  if (!r.subprocessors.length) out.push('_None detected in code._');
  else {
    out.push(`| Vendor | Purpose | Likely region | Package | DPA signed? |\n|---|---|---|---|---|`);
    const seen = new Set();
    for (const s of r.subprocessors) { if (seen.has(s.vendor)) continue; seen.add(s.vendor); out.push(`| ${s.vendor} | ${s.purpose} | ${s.region} | \`${s.package}\` | ☐ |`); }
  }

  out.push(`\n## 3. Findings\n`);
  r.findings.forEach((f, i) => {
    out.push(`### ${i + 1}. ${sevIcon[f.severity]} · ${f.title}`);
    out.push(`- **Where:** \`${f.where}\`  ·  **Fix type:** ${f.category}`);
    if (f.detail) out.push(`- **Detail:** ${f.detail.replace(/\|/g, '\\|')}`);
    out.push(`- **Fix:** ${f.fix}`);
    if (f.refs.gdpr || f.refs.dpdp) out.push(`- **Refs:** ${r.frameworks.includes('gdpr') && f.refs.gdpr ? 'GDPR ' + f.refs.gdpr : ''}${r.frameworks.includes('gdpr') && r.frameworks.includes('dpdp') ? ' · ' : ''}${r.frameworks.includes('dpdp') && f.refs.dpdp ? 'DPDP ' + f.refs.dpdp : ''}`);
    out.push('');
  });

  out.push(`## 4. Questionnaire evidence (draft answers)\n`);
  out.push(`| Question | Type | Status | Draft answer |\n|---|---|---|---|`);
  for (const q of questionnaire(r)) out.push(`| ${q.q} | ${q.cat} | ${q.status} | ${q.answer.replace(/\|/g, '\\|')} |`);

  out.push(`\n---\n_Generated by trustdiff v${r.version}. Heuristic scan: expect false positives/negatives; a human must review before anything goes to a customer._`);
  return out.join('\n');
}

module.exports = { toMarkdown, questionnaire };
