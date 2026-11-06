# trustdiff

Map personal data in your codebase and flag GDPR / DPDP gaps, in one command. Runs locally, zero dependencies, never reads `.env` files, uploads nothing.

```bash
npx trustdiff-cli scan . --frameworks gdpr,dpdp
# or, from this folder:
node bin/trustdiff.js scan /path/to/repo --out report.md --json report.json
```

## What it finds (v0.1)
- **Personal-data map**: email, phone, name, address, DOB, Aadhaar/PAN/passport, bank/UPI/card, health, location, credentials, device IDs, biometric, special categories, minors. Shows where each is *stored* vs just referenced.
- **Personal data in logs**: `console.log`, `logger.*`, `logging.*`, `print` lines with PII or raw `req.body`.
- **Personal data sent to third parties**: Mixpanel/Segment/PostHog/Sentry/LLM calls carrying raw identifiers.
- **Sub-processor register**: analytics, monitoring, email, SMS, payments, LLMs, cloud (from package.json / requirements.txt / imports).
- **Committed secrets**: AWS, Stripe, Razorpay, OpenAI/Anthropic, GitHub, Slack, Google, DB URLs, private keys (masked in report).
- **Repo-level gaps**: no deletion/retention logic, unhashed passwords, unencrypted sensitive fields, tracking without consent, no monitoring (72h breach readiness), children's data, cross-border transfers.
- **Questionnaire evidence**: draft answers to common security-questionnaire questions, each tagged code / ops / policy / certification.

Each finding maps to GDPR articles and DPDP Act sections / Rules 2025.

## Flags
`--frameworks gdpr,dpdp` · `--out <file.md>` · `--json <file>` · `--ci` (exit 1 on any high finding)

## Demo
`npm run demo` scans `examples/sample-app` (planted issues) → `examples/sample-report.md`.

## Example output
```
✔ 1046 files · 11 personal-data categories · 6 sub-processors
  MEDIUM Personal data written to logs (Email)      server/mail/mailer.ts:269
  MEDIUM Sensitive data stored, verify field-level encryption (PAN, bank, salary)
  LOW    Local/dev DB password in code              docker-compose.yml:5
```
Full sample: [`examples/sample-report.md`](examples/sample-report.md)

## Need a questionnaire answered?
We run 72-hour security questionnaire + DPDP readiness sprints for Indian SaaS teams. Contact: unnati.guptaaaaa@gmail.com

## Limits (be honest with customers)
Heuristic static scan for JS/TS/Python/Prisma/SQL. Expect false positives and misses. It produces **evidence for review**, not a compliance certification, and its references are not legal advice. Ops, policy and certification questions still need a human.
