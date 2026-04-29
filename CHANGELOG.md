# Changelog

All notable changes to Aegis will be documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

_(empty)_

## 0.1.0 — 2026-04-29

The first tagged release. Pre-alpha — interfaces will change before 1.0.

### What ships

**Library tier (no Pekko, embeddable in any JVM app):**

- `aegis-core` — `KeyService[F[_]]` algebra, typed domain ADTs (`Principal`, `KeyId`, `KeySpec`,
  `OperationResult`, `KeyEvent`), in-memory reference implementation, circe codecs for `KeyEvent`.
- `aegis-iam` — `RoleBasedPolicyEngine` (allowlist with recursive parent-check that blocks agent-scope
  escalation), `AuthorizingKeyService` decorator, JWT bearer auth (`JwtVerifier` / `JwtIssuer` —
  HMAC-SHA256), `PrincipalResolver` SPI (dev / jwt).
- `aegis-audit` — `AuditingKeyService` decorator that writes one `AuditRecord` per call (including
  denied/failed), `InMemoryAuditSink` and `StdoutAuditSink` reference impls.
- `aegis-persistence` — `EventJournal` SPI with two implementations: `InMemoryEventJournal` (dev) and
  `PostgresEventJournal` (Doobie/Hikari) with idempotent schema bootstrap.
- `aegis-crypto` — `RootOfTrust` SPI plus `AwsKmsRootOfTrust` adapter for layered-mode deployments fronting
  an existing AWS KMS CMK.
- `aegis-sdk-scala` / `aegis-sdk-java` — skeleton clients (REST surface; further polish in 0.2.0).

**Server tier (Pekko-based):**

- `aegis-http` — Tapir + pekko-http REST endpoints for `POST/GET/POST-activate/DELETE /v1/keys`.
- `aegis-server` — boot wiring tying it all together: REST routes → audit fan-out (StdoutAuditSink +
  W1 anomaly detector) → authorization → Pekko `KeyOpsActor` (single-actor key state) → durable
  `EventJournal`. Configurable journal (`in-memory` | `postgres`) and auth (`dev` | `hmac`) via HOCON.
- `aegis-agent-ai` — W1 anomaly detector MVP (`BaselineDetector` with scope + rate-spike heuristics),
  `AgentRecommendation` events, `RecommendationSink` SPI + in-memory impl, `TappedAuditSink`.
- `aegis-cli` — `aegis` admin CLI with `version`, `login`, `keys create/get/activate/destroy`. Stubs
  printing "not yet wired up" for `agent issue`, `audit tail`, `advisor scan` (back-ends in 0.2.0).

### Operator-facing knobs

- `aegis.persistence.journal.kind` — `"in-memory"` (default) or `"postgres"` (env: `AEGIS_JOURNAL_KIND`).
- `aegis.persistence.journal.postgres.{jdbc-url, username, password, pool-size}` — env-overridable.
- `aegis.auth.kind` — `"dev"` (default) or `"hmac"`.
- `aegis.auth.hmac.secret` — required when `kind=hmac`; ≥32 bytes (env: `AEGIS_AUTH_HMAC_SECRET`).
- `aegis.http.{host, port}` — env-overridable.

### Distribution

- Docker image: `ghcr.io/sharma-bhaskar/aegis-server:0.1.0`.
- Library jars: `dev.aegiskms:aegis-{core,iam,audit,crypto,persistence,sdk-scala,sdk-java}:0.1.0` on Maven
  Central.
- CLI tarball: attached to the GitHub Release for v0.1.0.

### Known limitations (deferred)

- **No live OIDC / JWKS verification.** v0.1.0 ships HS256 only — operators issue self-signed tokens to
  themselves. RSA / ES256 + JWKS rotation are scoped for v0.2.0.
- **No agent-token issuance HTTP endpoint.** `aegis agent issue` in the CLI prints a clear "not yet wired
  up" message; the trait (`JwtIssuer`) is in place. Endpoint lands in v0.2.0 (PR A1).
- **No MCP server, no KMIP server.** Module skeletons exist in `aegis-mcp-server` and `aegis-kmip` so they
  can land additively in v0.2.0+.
- **`aegis-server` Postgres path leaks the connection pool until JVM exit.** A proper `Resource[IO, Unit]`
  boot scope is on the F1.b follow-up.
- **GCP / Azure / Vault / PKCS#11 root-of-trust adapters are not yet shipped.** AWS KMS only.
- **Audit fan-out to Postgres / Kafka / SIEM webhooks is not yet shipped.** Stdout sink only.
- **Risk scorer (W2), auto-responder (W3), LLM advisor (W4) are not yet shipped.** The W1 anomaly detector
  emits `AgentRecommendation` events; consuming them is manual.
- **No Helm chart yet.** `deploy/helm/aegis-kms/` is a placeholder; `deploy/docker/docker-compose.yml`
  brings the server up against a local Postgres for hands-on testing.

### Repository scaffolding (already in main before this release)

- sbt multi-project layout, Apache-2.0 license, CI workflow (`ci.yml`), contribution and security
  policies, scalafmt + scalafix configured.
- `apply-pr-backlog.sh` for splitting working-tree changes into one commit per PR.
