# Security Policy

## Supported versions

Aegis-KMS is pre-alpha. Until 0.1.0 is released, no version is supported for
security patches.

Once 0.1.0 ships, the latest two minor releases will receive security patches.

## Reporting a vulnerability

Please report vulnerabilities privately via GitHub Security Advisories:

  https://github.com/aegis-kms/aegis-kms/security/advisories/new


We will acknowledge receipt within 3 business days and aim to issue a fix or
mitigation within 30 days for high-severity issues.

## Scope

In scope:

- Cryptographic flaws in `aegis-crypto`.
- Authentication or authorization bypass in `aegis-iam`.
- KMIP or HTTP protocol parsing flaws.
- Improper handling of agent credential scope or TTL.
- Audit log tampering or omission.

Out of scope:

- Issues in third-party dependencies without a reproducible impact on
  Aegis-KMS behavior.
- DoS via unbounded client resource consumption when rate limiting is
  explicitly disabled.
- Issues in `aegis-agent-ai` recommendations — these are advisory; no
  cryptographic decision is taken solely on an AI recommendation.
