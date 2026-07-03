# Security Policy

## Reporting

Do not open a public issue containing real passwords, 2FA seeds, recovery codes, encrypted vault exports, Cloudflare tokens, or deployment credentials.

For private forks, rotate any secret that was accidentally committed before making the repository public.

## Important Limits

- Vault contents are encrypted in the browser before upload.
- The Worker stores user records, session data, and encrypted vault data.
- The raw login password is not sent to the Worker; the browser sends an authentication secret derived from the email and password.
- The authentication secret can still act as a login credential if exposed in transit or by a compromised client.
- A compromised browser, malicious extension, modified deployment, or exposed Cloudflare account can still put vault data at risk.
- Keep offline recovery codes for critical accounts.
