# Security Notes

VERITY is a prototype and should not be treated as production-grade security infrastructure.

## What the prototype does

- verifies nonce freshness and replay attempts
- validates a cryptographic signature before allowing a request
- checks credential status before accepting traffic
- limits repeated requests with rate moderation
- keeps the private signing key on the device
- gates the Admin panel APIs behind a password-issued, expiring signed session
- keeps enrollment answer keys on the server and checks elapsed time server-side

## What it does not guarantee

- safety against a determined attacker with a stolen credential
- perfect fraud resistance under hostile automation
- privacy guarantees for all scenarios
- production hardening for public internet exposure

## Recommended hardening

1. run PostgreSQL behind a managed service
2. enable TLS and strict CORS policies
3. replace the prototype Admin password (`password`) and session secret with strong values stored in a secret manager
4. add server-side logs with structured privacy-aware fields
5. enforce request signing verification with strict timestamp windows

The default Admin password is intentionally `password` for this local demonstration only. It is not suitable for a deployed or internet-accessible instance.
