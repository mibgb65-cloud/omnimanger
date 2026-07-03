# Security Policy

## Reporting

Do not open a public issue containing real passwords, 2FA seeds, recovery codes, encrypted vault exports, Cloudflare tokens, or deployment credentials.

For private forks, rotate any secret that was accidentally committed before making the repository public.

## Important Limits

- Vault contents are encrypted in the browser before upload.
- The Worker stores encrypted vault data and a SHA-256 hash of the per-vault sync token.
- The Worker sees the sync token while handling authenticated requests.
- A compromised browser, malicious extension, modified deployment, or exposed Cloudflare account can still put vault data at risk.
- Keep offline recovery codes for critical accounts.
