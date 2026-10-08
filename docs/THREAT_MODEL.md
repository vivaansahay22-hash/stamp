# Threat Model

## Threat: automated bot

- Attack method: repeated scripted requests from one credential.
- What VERITY does: risk score increases with burst and frequency signals.
- Remaining limitation: a sophisticated bot can still hide behind normal patterns for a while.

## Threat: credential farming

- Attack method: creating many credentials for abuse.
- What VERITY does: the enrollment assessment imposes a meaningful cost before issuing credentials.
- Remaining limitation: workers or outsourcing can reduce that cost.

## Threat: replay attacks

- Attack method: resubmitting an old signature with a reused nonce.
- What VERITY does: nonce records and expiry windows block stale signatures.
- Remaining limitation: all cryptographic verification relies on correct implementation.

## Threat: stolen credential

- Attack method: extractor or compromise of a browser credential.
- What VERITY does: the system can rotate credentials and detect suspicious reuse.
- Remaining limitation: stolen credentials still pose risk until they are revoked or rotated.

## Threat: distributed attacks

- Attack method: many credentials generating small bursts from different sources.
- What VERITY does: network-level aggregation and rate thresholds help detect suspicious clusters.
- Remaining limitation: benign distributed traffic may be flagged without enough context.

## Threat: outsourced enrollment

- Attack method: paying a human or labor market to complete the assessment.
- What VERITY does: it raises the cost of mass credential creation.
- Remaining limitation: it is not a guaranteed barrier against organized abuse.

## Threat: low-and-slow attacks

- Attack method: low frequency attempts to evade burst detection.
- What VERITY does: the risk engine considers frequency, failures, and abuse patterns.
- Remaining limitation: slow attacks resemble normal usage and may be harder to detect.

## Threat: malicious participating website

- Attack method: a site misreports or abuses policy signals.
- What VERITY does: the system separates site identity and keeps user credentials pseudonymous.
- Remaining limitation: a site can still misbehave within its own product context.

## Threat: database compromise

- Attack method: extraction of credential metadata or verification records.
- What VERITY does: only pseudonymous identifiers and public keys are stored, not private keys.
- Remaining limitation: data leakage remains a serious concern and must be mitigated by infrastructure controls.

## Threat: denial-of-service

- Attack method: repeated requests designed to overwhelm the API.
- What VERITY does: rate limiting, request validation, and structured logging help absorb load.
- Remaining limitation: a distributed denial-of-service can still affect availability.
