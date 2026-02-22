# OWASP Baseline Notes

## Injection

- Treat all user-controlled input as untrusted.
- Use parameterized queries for SQL access.
- Avoid shell execution with concatenated input.

## Authentication

- Enforce authentication and authorization server-side.
- Do not trust role claims without signature and expiration validation.
- Prefer short-lived tokens with revocation controls.

## Logging

- Avoid logging raw credentials, session tokens, request bodies, or sensitive headers.
- Redact or hash sensitive identifiers before log emission.
- Keep debug logging disabled by default in production.

## Cryptography

- Use modern password hashing (Argon2, scrypt, bcrypt).
- Avoid MD5/SHA1 for password storage.
- Avoid static IVs and insecure modes like ECB.
