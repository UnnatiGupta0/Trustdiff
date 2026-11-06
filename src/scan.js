const fs = require('fs');
const path = require('path');
const { PII, SENSITIVE, SDKS, SECRETS, REFS } = require('./rules');

const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.prisma', '.sql', '.graphql', '.gql', '.vue', '.svelte', '.yaml', '.yml', '.json', '.toml', '.tf']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'out', 'coverage', 'venv', '.venv', 'env', '__pycache__', '.turbo', '.vercel', 'vendor', '.cache', 'target']);
const MAX_BYTES = 1024 * 1024;

const LOG_RE = /(console\.(log|info|debug|warn|error|trace)|\blogger\.\w+\(|\blog\.(info|debug|warn|error)\(|\bprint\(|\blogging\.\w+\(|\bpino\(|\bwinston\.)/;
const RAW_OBJ_RE = /(req\.body|req\.query|request\.json|request\.data|request\.POST|JSON\.stringify\(\s*(user|customer|profile|payload|body)|\(\s*(user|customer|profile)\s*\))/;
const THIRD_PARTY_CALL_RE = /(\b(openai|anthropic|client\.messages|completions|genai|mixpanel|analytics|posthog|amplitude|segment|clevertap|moengage|intercom|Sentry|LogRocket|FullStory|gtag|fbq|dataLayer)\b[\w.]*\s*\(|\.(identify|track|people\.set|setUser|setUserProperties|capture)\s*\()/;
const STORAGE_PATH_RE = /(model|schema|entity|entities|migration|prisma|database|\bdb\b|repositor|table|\.sql$|types?\.ts$|dto)/i;
const STORAGE_LINE_RE = /(\bmodel\s+\w+\s*\{|new\s+Schema\(|CREATE\s+TABLE|\bColumn\(|models\.\w+Field|mapped_column|@Column|\bdefine\(|\.create\(|\.insert|\.save\(|\.upsert|INSERT\s+INTO)/i;

const ERASURE_RE = /(delete[A-Z_]?\w*(user|account|customer|profile)|(user|account|customer|profile)\w*\.(delete|destroy|remove)|deleteMany|\.destroy\(|anonymi[sz]e|\bpurge|retention|expireAfterSeconds|\bttl\b|data[_-]?erasure|right[_-]?to[_-]?(be[_-]?)?forget|\berase)/i;
const HASH_RE = /(bcrypt|argon2|scrypt|pbkdf2|passlib|hashpw|make_password|password_hash|hashSync|hash\(\s*password)/i;
const ENCRYPT_RE = /(createCipheriv|\bencrypt\(|fernet|cryptography|\bkms\b|KMSClient|pgcrypto|aes-256|AES\.|sodium|libsodium|@aws-crypto|vault|field[_-]?encryption|encrypted\s*:)/i;
const CONSENT_RE = /(consent|opt[_-]?in|optOut|opt_out|cookie[_-]?banner|cookieconsent|doNotTrack|trackingAllowed|gdpr|onetrust|cookiebot)/i;
const MONITOR_RE = /(winston|pino|bunyan|morgan|\blogging\b|@sentry|sentry_sdk|dd-trace|datadog|newrelic|cloudwatch|opentelemetry|loki|logtail|betterstack)/i;
const REGION_RE = /\b(us|eu|ap|sa|ca|me|af)-(east|west|central|south|north|southeast|northeast|northwest|southwest)-\d\b/g;

function codePart(line) {
  const keep = (inner, re) => ' ' + [...inner.matchAll(re)].map(x => x[1]).join(' ') + ' ';
  return line
    .replace(/`([^`]*)`/g, (m, inner) => keep(inner, /\$\{([^}]*)\}/g))
    .replace(/\bf(["'])(.*?)\1/g, (m, q, inner) => keep(inner, /\{([^}]*)\}/g))
    .replace(/(["'])(?:\\.|(?!\1).)*\1/g, ' ')
    .replace(/(\/\/|#).*$/, '')
    .replace(/^\s*(\*|\/\*).*$/, '');
}

function splitParts(id) {
  return id.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2').toLowerCase().split(/[_\-]+/).filter(Boolean);
}

function classify(identifier) {
  if (identifier.length < 2 || identifier.length > 48) return null;
  const parts = splitParts(identifier);
  const full = parts.join('');
  for (const c of PII) if (c.test(parts, full)) return c.id;
  return null;
}

function walk(dir, root, out) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.name.startsWith('.env')) continue; // never read env/secret files
    const full = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) walk(full, root, out); continue; }
    if (!e.isFile()) continue;
    const ext = path.extname(e.name).toLowerCase();
    const base = e.name.toLowerCase();
    if (!CODE_EXT.has(ext) && base !== 'requirements.txt' && base !== 'pipfile') continue;
    if (base === 'package-lock.json' || base === 'yarn.lock' || base === 'pnpm-lock.yaml') continue;
    try { if (fs.statSync(full).size > MAX_BYTES) continue; } catch { continue; }
    out.push(path.relative(root, full));
  }
}

function mask(s) { return s.length <= 8 ? '****' : s.slice(0, 4) + '…' + s.slice(-2) + ` (${s.length} chars)`; }

function scan(root, opts = {}) {
  root = path.resolve(root);
  const files = [];
  walk(root, root, files);

  const inventory = {}; // cat -> { stored:Set(file), seen:Set(file), fields:Set }
  const findings = [];
  const sdks = {}; // pkg -> {vendor,purpose,region,files:Set}
  const regions = new Set();
  const repo = { erasure: [], hash: false, encrypt: false, consent: false, monitor: false };
  let lines = 0;

  const add = (f) => findings.push(f);

  for (const rel of files) {
    let text;
    try { text = fs.readFileSync(path.join(root, rel), 'utf8'); } catch { continue; }
    if (text.includes('\u0000')) continue;
    const isTest = /(^|\/)(test|tests|__tests__|spec|fixtures?|mocks?|e2e|cypress|playwright|seeds?|app-tests)(\/|$)|\.(test|spec|e2e)\.\w+$|(^|\/)(e2e|seed)[-_.]/i.test(rel);
    const isClient = /(^|\/)(client|frontend|web|public|components|pages|ui)\//i.test(rel) || /\.(tsx|jsx|vue|svelte)$/.test(rel);
    const isScript = /(^|\/)scripts?\//i.test(rel) || /(^|\/)(view-db|seed|backfill|migrate)[-\w]*\.\w+$/i.test(rel);
    const storageFile = !isClient && STORAGE_PATH_RE.test(rel);
    const fileLines = text.split(/\r?\n/);
    lines += fileLines.length;

    // dependency manifests
    if (path.basename(rel) === 'package.json') {
      try {
        const pj = JSON.parse(text);
        for (const dep of Object.keys({ ...pj.dependencies, ...pj.devDependencies })) {
          if (SDKS[dep]) { const [vendor, purpose, region] = SDKS[dep]; (sdks[dep] ||= { vendor, purpose, region, files: new Set() }).files.add(rel); }
        }
      } catch {}
      continue;
    }
    if (/requirements\.txt$|pipfile$/i.test(rel)) {
      for (const l of fileLines) { const dep = l.trim().split(/[=<>~\[ ]/)[0].toLowerCase(); if (SDKS[dep]) { const [vendor, purpose, region] = SDKS[dep]; (sdks[dep] ||= { vendor, purpose, region, files: new Set() }).files.add(rel); } }
      continue;
    }

    if (ERASURE_RE.test(text)) repo.erasure.push(rel);
    if (HASH_RE.test(text)) repo.hash = true;
    if (ENCRYPT_RE.test(text)) repo.encrypt = true;
    if (CONSENT_RE.test(text)) repo.consent = true;
    if (MONITOR_RE.test(text)) repo.monitor = true;
    for (const m of text.matchAll(REGION_RE)) regions.add(`${m[0]} (${rel})`);

    let inModelBlock = false;
    fileLines.forEach((line, i) => {
      const ln = i + 1;
      const where = `${rel}:${ln}`;
      if (line.length > 2000) return;
      if (!isClient && STORAGE_LINE_RE.test(line)) inModelBlock = true;
      if (/^\s*\}\s*$/.test(line) && inModelBlock && rel.endsWith('.prisma')) inModelBlock = false;

      // imports of SDKs inside code
      const imp = line.match(/(?:from\s+['"]|require\(\s*['"]|import\s+['"]|^\s*import\s+([\w.]+)|^\s*from\s+([\w.]+)\s+import)([^'"\s)]*)/);
      if (imp) {
        const pkg = (imp[3] || imp[1] || imp[2] || '').replace(/['"]/g, '');
        const key = Object.keys(SDKS).find(k => SDKS[k] && (pkg === k || pkg.startsWith(k + '/')));
        if (key) { const [vendor, purpose, region] = SDKS[key]; (sdks[key] ||= { vendor, purpose, region, files: new Set() }).files.add(rel); }
      }

      // secrets (skip obvious env reads)
      if (!/process\.env|os\.environ|getenv|import\.meta\.env/.test(line)) {
        for (const s of SECRETS) {
          const m = line.match(s.re);
          if (m) {
            if (s.name === 'Hardcoded secret' && /(xxx|your[_-]|example|placeholder|changeme|<|\$\{)/i.test(m[0])) continue;
            if (s.name === 'DB URL with password' && /:\$\{?[A-Za-z_]|:\$\(|:%[A-Za-z_]|:<|:\*+@|:(password|pass|pwd|secret|changeme)@/i.test(m[0])) continue;
            const local = s.name === 'DB URL with password' && (/@(localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|mysql|mongo|mongodb|redis|database)[:\/]/i.test(line));
            if (local) { add({ type: 'secret', severity: 'low', where, title: 'Local/dev DB password in code', detail: `Value: ${mask(m[0])}`, fix: 'Fine for local dev only. Make sure production uses a different password from a secret manager.', category: 'code' }); break; }
            add({ type: 'secret', severity: isTest ? 'medium' : 'high', where, title: `${s.name} committed in code`, detail: `Value: ${mask(m[0])}`, fix: 'Rotate the credential now, move it to a secret manager / env var, and purge it from git history.', category: 'code' });
            break;
          }
        }
      }

      // PII identifiers on this line
      const code = codePart(line);
      const ids = new Set(code.match(/[A-Za-z_][A-Za-z0-9_]*/g) || []);
      const cats = new Set();
      for (const id of ids) { const c = classify(id); if (c) { cats.add(c); (inventory[c] ||= { stored: new Set(), seen: new Set(), fields: new Set() }).fields.add(id); inventory[c].seen.add(rel); } }
      if (cats.size && !isClient && !isTest && (storageFile || inModelBlock || STORAGE_LINE_RE.test(line))) for (const c of cats) inventory[c].stored.add(rel);

      // PII in logs
      if (LOG_RE.test(line) && !isTest) {
        const piiCats = [...cats].filter(c => c !== 'name');
        if (piiCats.length || RAW_OBJ_RE.test(code)) {
          const what = piiCats.length ? piiCats.map(c => PII.find(p => p.id === c).label).join(', ') : 'raw request/user object';
          let sev = piiCats.some(c => c === 'credential' || SENSITIVE.has(c)) ? 'high' : 'medium';
          if (isScript) sev = sev === 'high' ? 'medium' : 'low';
          add({ type: 'pii_in_logs', severity: sev, where, title: `Personal data written to logs (${what})`, detail: line.trim().slice(0, 140), fix: 'Remove the field from the log line or mask it (e.g. a***@x.com); add a log redaction filter.', category: 'code' });
        }
      }

      // PII sent to third-party SDK calls
      if (THIRD_PARTY_CALL_RE.test(line) && cats.size && !isTest) {
        const what = [...cats].map(c => PII.find(p => p.id === c).label).join(', ');
        add({ type: 'pii_to_third_party', severity: [...cats].some(c => SENSITIVE.has(c) || c === 'credential') ? 'high' : 'medium', where, title: `Personal data sent to a third-party SDK (${what})`, detail: line.trim().slice(0, 140), fix: 'Send a pseudonymous ID instead of raw identifiers; list this vendor as a sub-processor with a DPA; gate it behind consent.', category: 'code' });
      }
    });
  }

  // ---- repo-level findings ----
  const storedCats = Object.entries(inventory).filter(([, v]) => v.stored.size).map(([k]) => k);
  const label = (c) => PII.find(p => p.id === c).label;

  if (storedCats.length && !repo.erasure.length)
    add({ type: 'no_retention', severity: 'high', where: '(repo)', title: 'No deletion / retention logic found for stored personal data', detail: `Stored: ${storedCats.map(label).join(', ')}`, fix: 'Add an account/data deletion path (incl. backups), a retention period per data type, and a scheduled purge job. DPDP also needs a 48h notice before erasure.', category: 'code' });

  if (inventory.credential?.stored.size && !repo.hash)
    add({ type: 'unhashed_password', severity: 'high', where: [...inventory.credential.stored].join(', '), title: 'Passwords appear to be stored with no hashing library in the repo', detail: 'No bcrypt/argon2/scrypt/pbkdf2 usage found.', fix: 'Hash passwords with argon2id or bcrypt; never store or log plaintext.', category: 'code' });

  const sensStored = storedCats.filter(c => SENSITIVE.has(c));
  if (sensStored.length)
    add({ type: 'unencrypted_sensitive', severity: repo.encrypt ? 'medium' : 'high', where: sensStored.flatMap(c => [...inventory[c].stored]).filter((v, i, a) => a.indexOf(v) === i).join(', '), title: `Sensitive data stored${repo.encrypt ? ', verify field-level encryption' : ' with no encryption found in code'} (${sensStored.map(label).join(', ')})`, detail: repo.encrypt ? 'Encryption primitives exist in the repo; confirm they cover these fields.' : 'No encryption/KMS usage found.', fix: 'Encrypt these fields at rest (app-level or KMS), mask them in UIs/exports, and limit access.', category: 'code' });

  if (storedCats.includes('special'))
    add({ type: 'special', severity: 'medium', where: [...inventory.special.stored].join(', '), title: 'Special-category data collected (gender/religion/caste/ethnicity)', detail: 'Collect only if strictly needed for the purpose.', fix: 'Remove if not essential; otherwise document the purpose and lawful basis.', category: 'policy' });

  if ((storedCats.includes('children') || storedCats.includes('dob')))
    add({ type: 'children', severity: 'medium', where: [...(inventory.children?.stored || inventory.dob.stored)].join(', '), title: 'Age / minor markers stored, check children\'s-data handling', detail: 'DPDP treats under-18s as children.', fix: 'If any users can be under 18: add age-gating + verifiable parental consent; no tracking/targeted ads for minors.', category: 'ops' });

  const sdkList = Object.values(sdks);
  const trackingSdk = sdkList.some(s => /analytics|recording|engagement|RUM/i.test(s.purpose));
  if (trackingSdk && !repo.consent)
    add({ type: 'no_consent', severity: 'medium', where: '(repo)', title: 'Analytics/tracking SDKs present but no consent handling found', detail: sdkList.filter(s => /analytics|recording|engagement|RUM/i.test(s.purpose)).map(s => s.vendor).filter((v, i, a) => a.indexOf(v) === i).join(', '), fix: 'Load tracking only after consent; record consent (who, when, what notice version) and honour withdrawal.', category: 'code' });

  if (!repo.monitor)
    add({ type: 'no_monitoring', severity: 'medium', where: '(repo)', title: 'No structured logging / monitoring found', detail: 'You can\'t report a breach in 72h if you can\'t detect it.', fix: 'Add structured logs + error monitoring + access logs, retained ≥1 year (DPDP Rule 6), and alerting.', category: 'ops' });

  if (sdkList.length) {
    const foreign = sdkList.filter(s => !/^IN$/.test(s.region));
    add({ type: 'subprocessor', severity: 'info', where: '(repo)', title: `${[...new Set(sdkList.map(s => s.vendor))].length} likely sub-processors detected`, detail: [...new Set(sdkList.map(s => s.vendor))].join(', '), fix: 'Put each in your sub-processor register with a signed DPA; disclose them to customers.', category: 'policy' });
    if (foreign.length || regions.size)
      add({ type: 'cross_border', severity: 'info', where: '(repo)', title: 'Personal data likely leaves India', detail: [...new Set(foreign.map(s => `${s.vendor} (${s.region})`)), ...[...regions].slice(0, 5)].join(', '), fix: 'Document transfer destinations; check against any DPDP restricted-country list and your customers\' data-residency terms.', category: 'policy' });
  }

  for (const f of findings) f.refs = REFS[f.type] || {};
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  return {
    tool: 'trustdiff', version: '1.0.0', scannedAt: new Date().toISOString(), root,
    frameworks: opts.frameworks || ['gdpr', 'dpdp'],
    stats: { files: files.length, lines },
    inventory: Object.fromEntries(Object.entries(inventory).map(([k, v]) => [k, { label: label(k), stored: [...v.stored], seenIn: v.seen.size, fields: [...v.fields].slice(0, 12) }])),
    subprocessors: Object.entries(sdks).map(([pkg, s]) => ({ package: pkg, vendor: s.vendor, purpose: s.purpose, region: s.region, files: [...s.files] })),
    signals: { erasureLogic: repo.erasure.slice(0, 10), passwordHashing: repo.hash, encryption: repo.encrypt, consentHandling: repo.consent, monitoring: repo.monitor },
    findings,
  };
}

module.exports = { scan, classify, splitParts };
