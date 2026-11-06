#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { scan } = require('../src/scan');
const { toMarkdown } = require('../src/report');

const tty = process.stdout.isTTY;
const k = (code) => (s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = k(31), yel = k(33), blu = k(36), dim = k(2), bold = k(1), grn = k(32);

const HELP = `
${bold('trustdiff')}: map personal data in your code and flag GDPR / DPDP gaps.

Usage:
  trustdiff scan [path] [options]

Options:
  --frameworks gdpr,dpdp   Frameworks to map findings to (default: gdpr,dpdp)
  --out <file>             Markdown report path (default: trustdiff-report.md)
  --json <file>            Also write JSON results
  --ci                     Exit 1 if any high-severity finding
  -h, --help               Show help

Never reads .env files. Everything runs locally; nothing is uploaded.
`;

function args(argv) {
  const a = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    if (x === '-h' || x === '--help') a.help = true;
    else if (x === '--ci') a.ci = true;
    else if (x.startsWith('--')) { a[x.slice(2)] = argv[i + 1]; i++; }
    else a._.push(x);
  }
  return a;
}

const a = args(process.argv.slice(2));
if (a.help || a._[0] !== 'scan') { console.log(HELP); process.exit(a.help ? 0 : 1); }

const target = a._[1] || '.';
if (!fs.existsSync(target)) { console.error(red(`Path not found: ${target}`)); process.exit(1); }
const frameworks = (a.frameworks || 'gdpr,dpdp').split(',').map(s => s.trim().toLowerCase());

console.log(`\n${bold('trustdiff scan')} ${dim('--frameworks ' + frameworks.join(','))}`);
console.log(dim('Indexing repository · mapping personal-data flows'));
const t0 = Date.now();
const r = scan(target, { frameworks });

const c = { high: 0, medium: 0, low: 0, info: 0 };
r.findings.forEach(f => (c[f.severity] = (c[f.severity] || 0) + 1));
console.log(`${grn('✔')} ${r.stats.files} files · ${Object.keys(r.inventory).length} personal-data categories · ${new Set(r.subprocessors.map(s => s.vendor)).size} sub-processors ${dim(`(${Date.now() - t0}ms)`)}\n`);

for (const f of r.findings.slice(0, 12)) {
  const tag = f.severity === 'high' ? red('HIGH  ') : f.severity === 'medium' ? yel('MEDIUM') : f.severity === 'low' ? dim('LOW   ') : blu('INFO  ');
  console.log(`  ${tag} ${f.title}`);
  console.log(`         ${dim(f.where.length > 90 ? f.where.slice(0, 90) + '…' : f.where)}`);
}
if (r.findings.length > 12) console.log(dim(`  … ${r.findings.length - 12} more in the report`));

const out = a.out || 'trustdiff-report.md';
fs.writeFileSync(out, toMarkdown(r));
if (a.json) fs.writeFileSync(a.json, JSON.stringify(r, null, 2));
console.log(`\n${bold(red(c.high + ' high'))} · ${yel(c.medium + ' medium')} · ${dim(c.low + ' low')} · ${blu(c.info + ' info')}`);
console.log(`Report → ${bold(out)}${a.json ? '  ·  JSON → ' + bold(a.json) : ''}`);
console.log(dim('Evidence for review, not a compliance certification.\n'));

if (a.ci && c.high) process.exit(1);
