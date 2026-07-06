# Security Notes

omnimanger is designed as a zero-knowledge vault for personal account recovery data. The server stores encrypted vault envelopes, session data, invite metadata, and login verification material. It should not receive plaintext account passwords, TOTP seeds, recovery codes, or notes.

## What The Server Stores

- User email, user id, role, timestamps, and password verifier metadata.
- A session cookie signed with `SESSION_SECRET`.
- Encrypted vault envelopes under the `VAULT` KV binding.
- Admin invite metadata and audit events.

The encrypted vault envelope contains ciphertext produced in the browser. The server cannot decrypt it without the user's master password-derived key.

## What Stays In The Browser

- Master password.
- Derived vault encryption key.
- Plaintext account entries.
- Plaintext passwords, TOTP seeds, recovery codes, and notes.

The browser derives keys locally, decrypts locally, and sends only encrypted vault envelopes to the Worker.

## Required Cloudflare Configuration

- `VAULT`: Cloudflare KV namespace binding.
- `SESSION_SECRET`: at least 32 characters. Used to sign session cookies.
- `ADMIN_EMAIL`: the first administrator email. This user can register while public registration is closed.
- `AUTH_PEPPER`: optional but recommended, at least 32 characters when set. Used for server-side login verifier hardening.

Do not commit environment values to Git. Use Cloudflare Worker secrets or environment variable configuration.

## Rotation Guidance

- Rotate exposed Cloudflare API tokens immediately in the Cloudflare dashboard.
- Rotate `SESSION_SECRET` when session signing material may have leaked. Existing sessions will become invalid.
- Rotate `AUTH_PEPPER` carefully: existing login verifiers depend on it. Plan a migration or require users to reset/recreate login secrets.
- Keep encrypted backup files before major migrations.

## Admin And Registration Model

- Public registration is disabled by default unless an administrator enables it.
- The configured `ADMIN_EMAIL` can register without an invite.
- Non-admin users need either open registration or a valid one-time invite.
- Invites expire and are marked used or revoked in the admin index.

## Backup Guidance

- Exported backups are encrypted vault envelopes.
- Store backups somewhere private and durable.
- Verify a backup before relying on it.
- Keep at least one recent offline copy before importing or replacing vault data.

## Threat Model Limits

This project reduces server-side exposure, but it cannot protect against every condition:

- A compromised browser, extension, or device can see plaintext after unlock.
- Malicious code deployed to the Worker can alter future frontend behavior.
- Weak master passwords can still be guessed offline if an attacker obtains encrypted vault data.
- Lost master passwords cannot be recovered by the server.

Use strong master passwords, keep devices clean, and review deployments before publishing.
