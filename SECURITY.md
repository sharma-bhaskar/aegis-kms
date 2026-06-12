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

## Deploy-time configuration

The shipped Docker images and Compose files do not contain any default
credentials. The deploy-time decisions below are the operator's
responsibility and Aegis-KMS will fail fast at boot rather than fall back to
a weak default.

### Required environment variables

| Variable | When required | Notes |
| --- | --- | --- |
| `POSTGRES_PASSWORD` | Always when running `deploy/docker/docker-compose.yml` | Compose substitutes this into both the Postgres container and the `AEGIS_JDBC_PASSWORD` of `aegis-server`. Generate with `openssl rand -base64 24`; do **not** check the value into source control. |
| `AEGIS_JDBC_PASSWORD` | When `aegis-server` is configured with `AEGIS_JOURNAL_KIND=postgres` outside the bundled compose file | Same value the Postgres role expects. |
| `AEGIS_AUTH_HMAC_SECRET` | When `AEGIS_AUTH_KIND=hmac` | Must be ≥ 32 bytes. Generate with `openssl rand -base64 48`. |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION` | When the AWS KMS root-of-trust is configured | Prefer instance-role credentials over long-lived access keys. The KMS adapter only needs `kms:Encrypt`, `kms:Decrypt`, `kms:Sign`, `kms:Verify`, `kms:GenerateDataKey`, and `kms:EnableKeyRotation` against the configured CMK. |

### Authentication mode

`AEGIS_AUTH_KIND=dev` accepts the `X-Aegis-User` header verbatim and is
intended for local workstation use only. Any deployment reachable from a
network you do not fully control must use `AEGIS_AUTH_KIND=hmac` (HS256
JWT) or `AEGIS_AUTH_KIND=oidc` (OIDC / JWKS verification with RS256/ES256,
shipped in v0.2.0).

### Production preflight

At boot, Aegis cross-checks the bind address against every dev-grade setting
(`AEGIS_AUTH_KIND=dev`, `AEGIS_POLICY_KIND=dev`, `AEGIS_CRYPTO_KIND=in-memory`,
`AEGIS_JOURNAL_KIND=in-memory`). Loopback binds always pass. On a
network-reachable bind, the default mode (`AEGIS_SECURITY_PREFLIGHT=warn`)
prints one unmissable banner listing each finding; production deployments
should set `AEGIS_SECURITY_PREFLIGHT=enforce`, which refuses to boot instead
(#99) — a crashed pod is cheaper than an open KMS.

### TLS termination

Aegis-KMS does not yet ship its own TLS listener. Production deployments
should terminate TLS at a fronting reverse proxy (Envoy, NGINX, Traefik,
ALB) and forward to `aegis-server` over the internal network. Native TLS +
mTLS support lands with the KMIP plane in v0.4.0 (PR K1).

### Reverting the default

Reintroducing a default password in `docker-compose.yml` regresses #51 and
will be rejected at review time. The compose file uses the `${VAR:?error}`
shell-substitution form deliberately so misconfiguration is loud.
