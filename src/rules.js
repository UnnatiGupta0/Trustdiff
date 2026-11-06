// Detection rules + framework mappings. References are pointers for human review, not legal advice.

// Short keywords must match a whole identifier part; long ones may match as substrings.
const has = (p, f, words) => words.some(w => (w.length <= 5 ? (p.includes(w) || f === w) : f.includes(w)));

// Personal-data categories. Matched against identifier *parts* (camelCase / snake_case split).
const PII = [
  { id: 'email', label: 'Email', test: (p, f) => p.includes('email') || f === 'mail' || f === 'emailid' },
  { id: 'phone', label: 'Phone', test: (p, f) => ['phone', 'mobile', 'msisdn', 'whatsapp'].some(w => p.includes(w)) || ['tel', 'telephone', 'contactno', 'contactnumber'].includes(f) },
  { id: 'name', label: 'Name', test: (p, f) => ['firstname', 'lastname', 'fullname', 'middlename', 'surname', 'displayname', 'legalname'].includes(f) },
  { id: 'address', label: 'Postal address', test: (p, f) => (p.includes('address') && !['ip', 'mac', 'email', 'wallet', 'contract'].some(w => p.includes(w))) || has(p, f, ['street', 'pincode', 'zipcode', 'postcode', 'postalcode']) },
  { id: 'dob', label: 'Date of birth / age', test: (p, f) => ['dob', 'dateofbirth', 'birthdate', 'birthday', 'age'].includes(f) || (p.includes('birth') && p.includes('date')) },
  { id: 'govid', label: 'Government ID (Aadhaar/PAN/passport/SSN)', test: (p, f) => has(p, f, ['aadhaar', 'aadhar', 'uidai', 'passport', 'ssn', 'voterid', 'nationalid', 'drivinglicense', 'drivinglicence', 'licenseno']) || (p.includes('pan') && (p.length === 1 || p.some(w => ['number', 'no', 'card', 'num', 'id'].includes(w)))) },
  { id: 'financial', label: 'Financial (bank/card/UPI/salary)', test: (p, f) => has(p, f, ['bankaccount', 'accountnumber', 'accountno', 'ifsc', 'iban', 'cardnumber', 'cvv', 'upiid', 'vpa', 'salary', 'income', 'ctc']) || (p.includes('upi') && p.length <= 2) },
  { id: 'health', label: 'Health data', test: (p, f) => !/healthz|healthcheck|health_?check|healthy|unhealthy/.test(f) && !p.includes('check') && has(p, f, ['health', 'medical', 'diagnosis', 'bloodgroup', 'disability', 'prescription', 'allergy', 'symptom']) },
  { id: 'location', label: 'Precise location', test: (p, f) => ['latitude', 'longitude', 'geolocation', 'gps', 'geo', 'lat', 'lng'].includes(f) || p.includes('latitude') || p.includes('longitude') || p.includes('geolocation') },
  { id: 'credential', label: 'Credentials (password/OTP)', test: (p, f) => ['password', 'passwd', 'otp', 'pwd'].includes(f) || p.includes('password') },
  { id: 'device', label: 'Online/device IDs (IP, device, IMEI)', test: (p, f) => ['ipaddress', 'deviceid', 'imei', 'fcmtoken', 'advertisingid', 'idfa', 'gaid', 'useragent', 'clientip'].includes(f) },
  { id: 'biometric', label: 'Biometric', test: (p, f) => has(p, f, ['fingerprint', 'faceid', 'biometric', 'selfie', 'facescan']) },
  { id: 'special', label: 'Special category (gender/religion/caste/ethnicity)', test: (p, f) => ['gender', 'religion', 'caste', 'ethnicity', 'sexualorientation', 'politicalview'].includes(f) },
  { id: 'children', label: "Children's data markers", test: (p, f) => ['guardian', 'parentconsent', 'isminor', 'parentemail', 'guardianname', 'parentname'].includes(f) },
];

const SENSITIVE = new Set(['govid', 'financial', 'health', 'biometric', 'special']);

// Third-party SDKs that typically receive personal data (sub-processors).
const SDKS = {
  mixpanel: ['Mixpanel', 'Product analytics', 'US/EU'], 'mixpanel-browser': ['Mixpanel', 'Product analytics', 'US/EU'],
  '@segment/analytics-next': ['Segment', 'Analytics/CDP', 'US/EU'], 'analytics-node': ['Segment', 'Analytics/CDP', 'US/EU'], '@segment/analytics-node': ['Segment', 'Analytics/CDP', 'US/EU'],
  '@amplitude/analytics-browser': ['Amplitude', 'Product analytics', 'US/EU'], 'amplitude-js': ['Amplitude', 'Product analytics', 'US/EU'],
  'posthog-js': ['PostHog', 'Product analytics', 'US/EU'], 'posthog-node': ['PostHog', 'Product analytics', 'US/EU'], posthog: ['PostHog', 'Product analytics', 'US/EU'],
  '@sentry/node': ['Sentry', 'Error monitoring', 'US/EU'], '@sentry/react': ['Sentry', 'Error monitoring', 'US/EU'], '@sentry/nextjs': ['Sentry', 'Error monitoring', 'US/EU'], '@sentry/browser': ['Sentry', 'Error monitoring', 'US/EU'], 'sentry-sdk': ['Sentry', 'Error monitoring', 'US/EU'],
  'react-ga4': ['Google Analytics', 'Web analytics', 'US'], 'react-ga': ['Google Analytics', 'Web analytics', 'US'], '@next/third-parties': ['Google (GA/GTM)', 'Web analytics', 'US'],
  hotjar: ['Hotjar', 'Session recording', 'EU'], '@hotjar/browser': ['Hotjar', 'Session recording', 'EU'],
  logrocket: ['LogRocket', 'Session recording', 'US'], '@fullstory/browser': ['FullStory', 'Session recording', 'US'],
  '@intercom/messenger-js-sdk': ['Intercom', 'Support chat', 'US/EU'], 'react-use-intercom': ['Intercom', 'Support chat', 'US/EU'],
  'clevertap-web-sdk': ['CleverTap', 'Engagement', 'IN/US'], 'clevertap-react-native': ['CleverTap', 'Engagement', 'IN/US'], '@moengage/web-sdk': ['MoEngage', 'Engagement', 'IN/EU/US'],
  'dd-trace': ['Datadog', 'APM/logging', 'US/EU'], '@datadog/browser-rum': ['Datadog', 'RUM', 'US/EU'], newrelic: ['New Relic', 'APM', 'US/EU'],
  stripe: ['Stripe', 'Payments', 'US'], razorpay: ['Razorpay', 'Payments', 'IN'], cashfree: ['Cashfree', 'Payments', 'IN'],
  twilio: ['Twilio', 'SMS/voice', 'US'], '@sendgrid/mail': ['SendGrid', 'Email', 'US'], nodemailer: ['SMTP provider', 'Email', 'varies'], resend: ['Resend', 'Email', 'US'], postmark: ['Postmark', 'Email', 'US'], msg91: ['MSG91', 'SMS', 'IN'],
  'firebase': ['Google Firebase', 'Backend/analytics', 'US'], 'firebase-admin': ['Google Firebase', 'Backend', 'US'], '@react-native-firebase/analytics': ['Firebase Analytics', 'Analytics', 'US'],
  openai: ['OpenAI', 'LLM processing', 'US'], '@anthropic-ai/sdk': ['Anthropic', 'LLM processing', 'US'], anthropic: ['Anthropic', 'LLM processing', 'US'], '@google/generative-ai': ['Google Gemini', 'LLM processing', 'US'],
  '@aws-sdk/client-s3': ['AWS S3', 'Storage', 'region-dependent'], 'aws-sdk': ['AWS', 'Cloud', 'region-dependent'], boto3: ['AWS', 'Cloud', 'region-dependent'],
  '@supabase/supabase-js': ['Supabase', 'Database/auth', 'region-dependent'], '@clerk/nextjs': ['Clerk', 'Auth', 'US'], 'auth0': ['Auth0', 'Auth', 'US/EU'],
  'mongoose': null, // DB driver, not a processor by itself
};

const SECRETS = [
  { name: 'AWS access key', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'Stripe live secret key', re: /sk_live_[0-9a-zA-Z]{16,}/ },
  { name: 'Razorpay live key', re: /rzp_live_[A-Za-z0-9]{10,}/ },
  { name: 'Private key', re: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { name: 'Anthropic API key', re: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: 'OpenAI API key', re: /sk-(proj-)?[A-Za-z0-9]{20,}/ },
  { name: 'GitHub token', re: /gh[pousr]_[A-Za-z0-9]{36,}/ },
  { name: 'Slack token', re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { name: 'Google API key', re: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'DB URL with password', re: /(postgres(ql)?|mysql|mongodb(\+srv)?|redis):\/\/[^:\s'"\/]+:[^@\s'"]+@/ },
  { name: 'Hardcoded secret', re: /\b(api[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|jwt[_-]?secret)\b\s*[:=]\s*['"][^'"\s]{12,}['"]/i },
];

// Framework references per finding type.
const REFS = {
  inventory: { gdpr: 'Art. 30 (records of processing)', dpdp: 's.5 + Rule 3 (notice must itemise data)' },
  pii_in_logs: { gdpr: 'Art. 5(1)(c), Art. 32', dpdp: 's.8(5) + Rule 6 (reasonable security safeguards)' },
  pii_to_third_party: { gdpr: 'Art. 28 (processors), Art. 44 (transfers)', dpdp: 's.8(2) + Rule 6 (processor under contract)' },
  subprocessor: { gdpr: 'Art. 28', dpdp: 's.8(2) (processor only under valid contract)' },
  secret: { gdpr: 'Art. 32', dpdp: 's.8(5) + Rule 6' },
  no_retention: { gdpr: 'Art. 5(1)(e), Art. 17', dpdp: 's.8(7) + Rule 8 (erasure; 48h prior notice)' },
  unhashed_password: { gdpr: 'Art. 32(1)(a)', dpdp: 'Rule 6 (encryption/obfuscation/masking)' },
  unencrypted_sensitive: { gdpr: 'Art. 9, Art. 32(1)(a)', dpdp: 'Rule 6 (encryption/obfuscation/masking)' },
  no_consent: { gdpr: 'Art. 6, Art. 7 (+ ePrivacy)', dpdp: 's.6 (consent), s.5 (notice)' },
  no_monitoring: { gdpr: 'Art. 33 (72h breach notice)', dpdp: 'Rule 6 (logs kept 1 yr) + Rule 7 (72h breach report)' },
  children: { gdpr: 'Art. 8', dpdp: 's.9 + Rule 10 (verifiable parental consent)' },
  cross_border: { gdpr: 'Ch. V (Art. 44-49)', dpdp: 's.16 (+ Rule 15)' },
  special: { gdpr: 'Art. 9 (special categories)', dpdp: 's.8(5) (higher-risk data, safeguard accordingly)' },
};

module.exports = { PII, SENSITIVE, SDKS, SECRETS, REFS };
