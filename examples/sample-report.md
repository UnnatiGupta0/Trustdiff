# trustdiff report

> Evidence for review, **not** a compliance certification. GDPR/DPDP references are pointers for your counsel, not legal advice.

**Scanned:** `/home/claude/trustdiff/examples/sample-app` · 4 files · 50 lines · 2026-11-06 · frameworks: GDPR, DPDP

| 🔴 High | 🟠 Medium | 🟡 Low | 🔵 Info | Data categories | Sub-processors |
|---|---|---|---|---|---|
| 6 | 6 | 0 | 2 | 9 | 5 |

## 1. Personal-data map

| Category | Stored in | Seen in (files) | Example fields |
|---|---|---|---|
| Government ID (Aadhaar/PAN/passport/SSN) | `prisma/schema.prisma`, `src/kyc.py`, `src/server.js` | 3 | `aadhaarNumber`, `panNumber`, `pan_number`, `aadhaar_number` |
| Email | `prisma/schema.prisma`, `src/server.js` | 3 | `email` |
| Phone | `prisma/schema.prisma`, `src/server.js` | 2 | `phoneNumber`, `phone` |
| Credentials (password/OTP) | `prisma/schema.prisma`, `src/server.js` | 2 | `password` |
| Name | `prisma/schema.prisma` | 1 | `fullName` |
| Date of birth / age | `prisma/schema.prisma` | 1 | `dateOfBirth` |
| Special category (gender/religion/caste/ethnicity) | `prisma/schema.prisma` | 1 | `gender` |
| Postal address | `prisma/schema.prisma` | 1 | `address` |
| Financial (bank/card/UPI/salary) | `prisma/schema.prisma` | 1 | `bankAccountNumber`, `ifscCode`, `upiId` |

## 2. Sub-processor register (draft)

| Vendor | Purpose | Likely region | Package | DPA signed? |
|---|---|---|---|---|
| Mixpanel | Product analytics | US/EU | `mixpanel` | ☐ |
| Sentry | Error monitoring | US/EU | `@sentry/node` | ☐ |
| SendGrid | Email | US | `@sendgrid/mail` | ☐ |
| Razorpay | Payments | IN | `razorpay` | ☐ |
| OpenAI | LLM processing | US | `openai` | ☐ |

## 3. Findings

### 1. 🔴 High · Personal data written to logs (Government ID (Aadhaar/PAN/passport/SSN), Email)
- **Where:** `src/kyc.py:5`  ·  **Fix type:** code
- **Detail:** logging.info(f"KYC for {user.pan_number} {user.email}")
- **Fix:** Remove the field from the log line or mask it (e.g. a***@x.com); add a log redaction filter.
- **Refs:** GDPR Art. 5(1)(c), Art. 32 · DPDP s.8(5) + Rule 6 (reasonable security safeguards)

### 2. 🔴 High · Personal data sent to a third-party SDK (Government ID (Aadhaar/PAN/passport/SSN))
- **Where:** `src/kyc.py:6`  ·  **Fix type:** code
- **Detail:** return openai.chat.completions.create(model="gpt-4o", messages=[{"role":"user","content": user.aadhaar_number}])
- **Fix:** Send a pseudonymous ID instead of raw identifiers; list this vendor as a sub-processor with a DPA; gate it behind consent.
- **Refs:** GDPR Art. 28 (processors), Art. 44 (transfers) · DPDP s.8(2) + Rule 6 (processor under contract)

### 3. 🔴 High · Hardcoded secret committed in code
- **Where:** `src/server.js:6`  ·  **Fix type:** code
- **Detail:** Value: JWT_…2" (43 chars)
- **Fix:** Rotate the credential now, move it to a secret manager / env var, and purge it from git history.
- **Refs:** GDPR Art. 32 · DPDP s.8(5) + Rule 6

### 4. 🔴 High · No deletion / retention logic found for stored personal data
- **Where:** `(repo)`  ·  **Fix type:** code
- **Detail:** Stored: Email, Phone, Name, Credentials (password/OTP), Date of birth / age, Government ID (Aadhaar/PAN/passport/SSN), Special category (gender/religion/caste/ethnicity), Postal address, Financial (bank/card/UPI/salary)
- **Fix:** Add an account/data deletion path (incl. backups), a retention period per data type, and a scheduled purge job. DPDP also needs a 48h notice before erasure.
- **Refs:** GDPR Art. 5(1)(e), Art. 17 · DPDP s.8(7) + Rule 8 (erasure; 48h prior notice)

### 5. 🔴 High · Passwords appear to be stored with no hashing library in the repo
- **Where:** `prisma/schema.prisma, src/server.js`  ·  **Fix type:** code
- **Detail:** No bcrypt/argon2/scrypt/pbkdf2 usage found.
- **Fix:** Hash passwords with argon2id or bcrypt; never store or log plaintext.
- **Refs:** GDPR Art. 32(1)(a) · DPDP Rule 6 (encryption/obfuscation/masking)

### 6. 🔴 High · Sensitive data stored with no encryption found in code (Government ID (Aadhaar/PAN/passport/SSN), Special category (gender/religion/caste/ethnicity), Financial (bank/card/UPI/salary))
- **Where:** `prisma/schema.prisma, src/kyc.py, src/server.js`  ·  **Fix type:** code
- **Detail:** No encryption/KMS usage found.
- **Fix:** Encrypt these fields at rest (app-level or KMS), mask them in UIs/exports, and limit access.
- **Refs:** GDPR Art. 9, Art. 32(1)(a) · DPDP Rule 6 (encryption/obfuscation/masking)

### 7. 🟠 Medium · Personal data written to logs (raw request/user object)
- **Where:** `src/server.js:11`  ·  **Fix type:** code
- **Detail:** console.log('signup payload', req.body);
- **Fix:** Remove the field from the log line or mask it (e.g. a***@x.com); add a log redaction filter.
- **Refs:** GDPR Art. 5(1)(c), Art. 32 · DPDP s.8(5) + Rule 6 (reasonable security safeguards)

### 8. 🟠 Medium · Personal data sent to a third-party SDK (Email, Phone)
- **Where:** `src/server.js:14`  ·  **Fix type:** code
- **Detail:** mixpanel.people.set(user.id, { $email: email, phone: phoneNumber });
- **Fix:** Send a pseudonymous ID instead of raw identifiers; list this vendor as a sub-processor with a DPA; gate it behind consent.
- **Refs:** GDPR Art. 28 (processors), Art. 44 (transfers) · DPDP s.8(2) + Rule 6 (processor under contract)

### 9. 🟠 Medium · Personal data written to logs (Email, Phone)
- **Where:** `src/server.js:15`  ·  **Fix type:** code
- **Detail:** console.log(`new user ${email} ${phoneNumber}`);
- **Fix:** Remove the field from the log line or mask it (e.g. a***@x.com); add a log redaction filter.
- **Refs:** GDPR Art. 5(1)(c), Art. 32 · DPDP s.8(5) + Rule 6 (reasonable security safeguards)

### 10. 🟠 Medium · Special-category data collected (gender/religion/caste/ethnicity)
- **Where:** `prisma/schema.prisma`  ·  **Fix type:** policy
- **Detail:** Collect only if strictly needed for the purpose.
- **Fix:** Remove if not essential; otherwise document the purpose and lawful basis.
- **Refs:** GDPR Art. 9 (special categories) · DPDP s.8(5) (higher-risk data, safeguard accordingly)

### 11. 🟠 Medium · Age / minor markers stored, check children's-data handling
- **Where:** `prisma/schema.prisma`  ·  **Fix type:** ops
- **Detail:** DPDP treats under-18s as children.
- **Fix:** If any users can be under 18: add age-gating + verifiable parental consent; no tracking/targeted ads for minors.
- **Refs:** GDPR Art. 8 · DPDP s.9 + Rule 10 (verifiable parental consent)

### 12. 🟠 Medium · Analytics/tracking SDKs present but no consent handling found
- **Where:** `(repo)`  ·  **Fix type:** code
- **Detail:** Mixpanel
- **Fix:** Load tracking only after consent; record consent (who, when, what notice version) and honour withdrawal.
- **Refs:** GDPR Art. 6, Art. 7 (+ ePrivacy) · DPDP s.6 (consent), s.5 (notice)

### 13. 🔵 Info · 5 likely sub-processors detected
- **Where:** `(repo)`  ·  **Fix type:** policy
- **Detail:** Mixpanel, Sentry, SendGrid, Razorpay, OpenAI
- **Fix:** Put each in your sub-processor register with a signed DPA; disclose them to customers.
- **Refs:** GDPR Art. 28 · DPDP s.8(2) (processor only under valid contract)

### 14. 🔵 Info · Personal data likely leaves India
- **Where:** `(repo)`  ·  **Fix type:** policy
- **Detail:** Mixpanel (US/EU), Sentry (US/EU), SendGrid (US), OpenAI (US), us-east-1 (src/server.js)
- **Fix:** Document transfer destinations; check against any DPDP restricted-country list and your customers' data-residency terms.
- **Refs:** GDPR Ch. V (Art. 44-49) · DPDP s.16 (+ Rule 15)

## 4. Questionnaire evidence (draft answers)

| Question | Type | Status | Draft answer |
|---|---|---|---|
| What personal data do you collect and store? | code | ✅ evidence | Code stores: Email; Phone; Name; Credentials (password/OTP); Date of birth / age; Government ID (Aadhaar/PAN/passport/SSN); Special category (gender/religion/caste/ethnicity); Postal address; Financial (bank/card/UPI/salary). See data map. |
| Do you encrypt personal data at rest? | code | ❌ gap | No app-level encryption found. Add field encryption for sensitive data; confirm DB/disk encryption with cloud provider. |
| How are passwords stored? | code | ❌ gap | No hashing library found. If you use a managed auth provider, cite it instead. |
| Do you log or expose personal data in logs? | code | ❌ gap | 3 log lines include personal data. Fix before answering "no". |
| List your sub-processors. | policy | ✅ evidence | Mixpanel, Sentry, SendGrid, Razorpay, OpenAI. Plus your cloud host. Each needs a DPA. |
| Do you have a data retention & deletion policy? | code + policy | ❌ gap | No deletion/retention logic in code. Needs a deletion path + retention schedule + written policy. |
| How do you obtain and record user consent? | code + policy | ❌ gap | No consent handling found. |
| Can you detect and report a breach within 72 hours? | ops | ⚠️ partial | Logging/monitoring present. Still need: incident runbook, on-call owner, log retention ≥1 year. |
| Where is data stored / is it transferred outside the country? | ops | ⚠️ partial | Mixpanel (US/EU), Sentry (US/EU), SendGrid (US), OpenAI (US), us-east-1 (src/server.js) |
| Do you have SOC 2 / ISO 27001? | certification | ❓ human | Not answerable from code. State current status / timeline honestly. |
| Do you run background checks, security training, access reviews? | ops | ❓ human | Not answerable from code. Answer from HR/ops records. |

---
_Generated by trustdiff v1.0.0. Heuristic scan: expect false positives/negatives; a human must review before anything goes to a customer._