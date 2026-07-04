# Security Policy

## Reporting

Do not open a public issue containing real passwords, 2FA seeds, recovery codes, encrypted vault exports, Cloudflare tokens, or deployment credentials.

For private forks, rotate any secret that was accidentally committed before making the repository public.

## Important Limits

- Vault contents are encrypted in the browser before upload.
- The Worker stores user records, session data, and encrypted vault data.
- The raw login password is not sent to the Worker; the browser sends an authentication secret derived from the email and password with PBKDF2.
- New accounts store a Worker-side HMAC-SHA256 authentication verifier keyed by `AUTH_PEPPER` or `SESSION_SECRET`.
- Legacy salted SHA-256 and PBKDF2 v2 verifiers are upgraded after a successful login.
- The authentication secret can still act as a login credential if exposed in transit or by a compromised client.
- Public registration is disabled by default and controlled by the configured administrator email. Administrators can issue single-use invite links.
- Vault writes and password changes use revision checks to reduce accidental multi-device overwrites, but Cloudflare KV is still not a strongly consistent compare-and-swap store.
- Basic KV-backed rate limits protect registration, login, vault reads/writes, and admin settings, but KV rate limits are not a replacement for Cloudflare WAF or Turnstile.
- A compromised browser, malicious extension, modified deployment, or exposed Cloudflare account can still put vault data at risk.
- Keep offline recovery codes for critical accounts.
