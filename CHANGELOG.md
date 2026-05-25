# Changelog

All notable changes to Aegis will be documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- **Redis-backed JWT revocation list — JTI blacklist (closes #24).** The kill-switch
  primitive the auto-responder's "Revoke" action will use to invalidate an agent's bearer
  token before its natural expiry.
  - **`RevocationList[F[_]]` SPI** in `aegis-iam`: `isRevoked(jti)` + `revoke(jti, expiresAt)`.
    Three impls ship: `RevocationList.noop` (never revoked), `RevocationList.inMemory`
    (process-local `Ref[Map[jti, expiresAt]]`, lazy TTL evict on read + prune on revoke), and
    `RedisRevocationList` (in `aegis-server`, Lettuce-backed, key-per-jti with `PEXPIREAT`).
  - **`RevocationAwareJwtVerifier`** decorator wraps any inner `JwtVerifier` and consults the
    list after signature + claims validation passes. Inner rejections (Expired,
    SignatureInvalid, …) short-circuit before the lookup — saves a Redis round-trip on
    already-bad tokens. Tokens without a `jti` (legacy / non-Aegis-issued) pass through
    unchecked.
  - **`JwtError.Revoked(jti)`** variant. `PrincipalResolver.jwt` maps it to
    `AuthenticationNotSuccessful` with a `"JWT revoked (jti=…)"` message so operators can
    distinguish "expired naturally" from "killed by auto-responder / admin revoke".
  - **Fail-open on Redis outage.** `isRevoked` returns `false` if the Redis call throws,
    logging a `warn`. Bounded security gap = token TTL; the alternative (fail-closed)
    would create a global outage on a partial-store failure. Operators who need
    fail-closed semantics can wrap the impl.
  - **`Server.boot` wiring.** New `aegis.iam.revocation.kind` HOCON key
    (`none` | `in-memory` (default) | `redis`) + `AEGIS_REVOCATION_KIND` /
    `AEGIS_REVOCATION_REDIS_URI` / `AEGIS_REVOCATION_REDIS_KEY_PREFIX` env vars. Empty
    Redis URI when `kind=redis` fails fast at boot — no silent fallback.
    `buildResolver` now takes the `RevocationList` and wraps the constructed verifier
    (HMAC / OIDC) with `RevocationAwareJwtVerifier` automatically.
  - **Lettuce-based Redis client** (`io.lettuce:lettuce-core` 6.4.0). Single-jar dep,
    synchronous `RedisCommands` wrapped in `IO.blocking` — lighter on the Docker image
    than redis4cats (which pulls all of cats-effect-redis + Reactor).
  - **Tests:** 7 unit cases in `RevocationListSpec` (noop, in-memory revoke + lookup,
    expired-on-read, idempotent revoke, prune-on-revoke, no-store-on-past-expiry, helper);
    5 decorator cases in `RevocationAwareJwtVerifierSpec` (passthrough, Revoked outcome,
    no-jti bypass, inner-rejection short-circuit, idempotent double-wrap); 8 Testcontainers
    cases in `RedisRevocationListSpec` (Docker-gated — basic write/read, TTL eviction,
    idempotency, prefix isolation, multi-jti lookups, fail-open on closed connection, …).

- **OIDC verifier + JWKS rotation + RS256/ES256 (closes #25).** Production-grade auth path.
  Previously the server could only accept HS256 JWTs signed with a single shared secret
  (`aegis.auth.kind=hmac`) — disqualifying for any real evaluator. New
  `aegis.auth.kind=oidc` mode verifies tokens against an OIDC provider's JWKS endpoint
  (RS256 / RS384 / RS512 / ES256 / ES384 / ES512). Components shipped:
  - **`JwksProvider` SPI** in `aegis-iam` with `http(uri, ttl)` (production) +
    `static(set)` (tests). The HTTP impl caches the `JwkSet` with a configurable TTL and
    refreshes lazily on `kid` miss — handles provider key rotation without operator action
    or Aegis restart. Uses `java.net.http.HttpClient` so the library tier doesn't pick up
    Pekko / sttp / http4s as a transitive dep.
  - **`JwkSet`** value type holding parsed `java.security.PublicKey` values keyed by `kid`,
    parsed from RFC 7517 JWKS JSON via jjwt's `Jwks.parser()` (gives RSA / EC support for
    free).
  - **`OidcJwtVerifier`** implements the existing `JwtVerifier` trait. Per-verify flow: read
    `kid` from the token header, look up the key in the cached JWKS (refresh on miss),
    verify the signature with the resolved public key via `Jwts.parser().keyLocator(...)`,
    validate `iss` against `expectedIssuer` (defends against token substitution across
    shared cloud-IDP key sets), validate `aud` against `expectedAudience` if configured,
    extract the `aegis_kind` / `aegis_groups` / `aegis_*` extension claims into the existing
    `JwtClaims.Human` / `JwtClaims.Agent` shape.
  - **Algorithm-confusion defence.** Passing a `PublicKey` to `verifyWith` makes jjwt refuse
    `HS256` tokens forged against the public key bytes — the classic
    "alg=RS256→alg=HS256 with public key as HMAC secret" attack is impossible.
    `parseSignedClaims` also refuses `alg=none`.
  - **`OidcJwtVerifier.fromIssuer(issuerUri, audience, ttl)`** — one-step factory that
    fetches `/.well-known/openid-configuration`, extracts `jwks_uri`, builds the verifier.
  - **`Server.boot`** wires `aegis.auth.kind=oidc` with the new HOCON keys
    `aegis.auth.oidc.issuer-uri` (`AEGIS_AUTH_OIDC_ISSUER_URI`), `aegis.auth.oidc.audience`
    (`AEGIS_AUTH_OIDC_AUDIENCE`, optional), and `aegis.auth.oidc.jwks-cache-ttl-seconds`
    (`AEGIS_AUTH_OIDC_JWKS_CACHE_TTL_SECONDS`, default 3600). Empty / missing `issuer-uri`
    fails fast at boot — never silently falls back to dev. `buildResolver` is now
    `IO[PrincipalResolver]` (was synchronous) so the OIDC path can hit the network during
    boot.
  - **Tests:** 11 cases in `OidcJwtVerifierSpec` covering RS256 + ES256 happy paths,
    Agent-claim round-trip, audience-None opt-out, issuer mismatch, audience mismatch,
    expired token, kid-not-in-JWKS, wrong-key-same-kid signature mismatch, malformed
    garbage, missing `aegis_kind`. Keycloak Testcontainers integration is deferred to a
    follow-up — the unit tests with hand-rolled RSA/EC keypairs exercise the verification
    logic comprehensively without the CI cost of a Keycloak container.

- **`AwsKmsRootOfTrust` wired into `Server.boot`.** Closes a doc-vs-code gap surfaced during the
  v0.2.0 readiness audit. The AWS adapter has shipped in the `aegis-crypto` library since v0.1.x
  (17 passing tests), but `Server.boot` was constructing `ActorBackedKeyService(system)` with the
  default `RootOfTrust.inMemory` (deterministic-MAC dev backend) — meaning the published Docker
  image used the dev backend regardless of how it was configured. The status / comparison docs
  claimed "AWS KMS — Shipped" while the running server signed with HMAC. Fix:
  - New `aegis.crypto.kind` HOCON key (`in-memory` (default) | `aws-kms`) with
    `AEGIS_CRYPTO_KIND` env-var override.
  - New `aegis.crypto.aws-kms.region` + `aegis.crypto.aws-kms.kek-arn` keys
    (`AEGIS_CRYPTO_AWS_KMS_REGION` / `AEGIS_CRYPTO_AWS_KMS_KEK_ARN`); missing config fails fast
    at boot, never silently falls back to dev.
  - New `AwsKmsRootOfTrust.resource(cfg): Resource[IO, AwsKmsRootOfTrust]` factory wraps the
    `KmsClient` in a cats-effect `Resource` so the SDK's connection pool / metric publisher /
    background threads are released on SIGTERM. The pre-existing `fromConfig` is kept (with a
    docstring warning about the leaked client) so single-shot scripts and embedder code that
    manages its own KMS-client lifecycle stay supported.
  - `Server.boot` gains a `rootOfTrustResource(config)` builder paralleling `journalResource`;
    the in-memory branch logs a `warn` flagging "NOT a real KMS, set kind=aws-kms for
    production" so operators can't accidentally rely on the dev backend.

### Changed

- **Doc drift cleanup, v0.2.0 readiness audit.**
  - `CHANGELOG.md` removed duplicate `### Added` heading in the Unreleased section (merged into
    a single Added block).
  - `docs/about/status.md` corrected GCP KMS / Azure Key Vault / HashiCorp Vault Transit rows
    from "v0.2.0" to "v0.3.0" (matches ROADMAP §3.0.a–c).
  - `docs/about/status.md` corrected the OIDC / JWKS row from "WIP" to "Designed" (no commits
    yet; the trait is in place but no implementation).
  - `docs/about/status.md` AWS KMS row now explicitly states the `Server.boot` wiring path
    instead of leaving it implicit.
  - `docs/about/status.md` KMIP and MCP rows now reference v0.4.0 (matches ROADMAP §4.0.*)
    instead of the previous v0.2.0 overclaim.
  - `docs/about/comparison.md` KMIP and MCP-native rows corrected from "Designed (v0.2.0)" to
    "Designed (v0.4.0)".

- **Audit-read REST API: `GET /v1/audit` (closes #20).** New `AuditQuery[F[_]]` SPI in
  `aegis-audit` with `Filter` (since / until / actor / resource / operation / limit / offset)
  and `Page` (records / limit / offset / hasMore). `PostgresAuditSink` now implements both
  `AuditSink` AND `AuditQuery` — one impl, two responsibilities. The query composes optional
  filters with `AND`, uses the "LIMIT n+1" trick to derive `hasMore` without a separate
  `COUNT(*)`, clamps `limit` to `[1, 1000]` and `offset` to `>= 0` defensively, and rebuilds
  `AuditRecord` instances from the row (including JSONB `context` round-trip back to
  `Map[String, String]`). New Tapir endpoint
  `GET /v1/audit?since&until&actor&key&op&limit&offset` returns
  `{records, limit, offset, hasMore}`. Authz: human principals only — agents and services are
  refused with `403 PermissionDenied` (v0.2.0 simplification of the future "audit:read permission
  via policy engine" model). Unknown `op` names reject with `400 InvalidField` rather than
  silently producing an empty result. When the server isn't wired with a query-capable sink
  (`aegis.audit.kind=stdout`), the endpoint returns `501 FeatureNotSupported` — same pattern as
  `/v1/agents/issue` when its dependency is missing. New tests: 8 Postgres-backed cases in
  `PostgresAuditSinkSpec` (filter by actor / resource / op / since-until, AND composition,
  pagination with `hasMore`, defensive clamping, JSONB round-trip) + 8 HTTP-level cases in
  `HttpRoutesAuditQuerySpec` (response shape, record round-trip, filter parsing, op-name
  validation, human JWT happy path, agent 403, no-reader 501, pagination propagation). Backs
  the `aegis audit tail` CLI stub that ships next.

- **Postgres audit table with indexed schema + retention (closes #19).** New
  `PostgresAuditSink` in `aegis-audit` writes every `AuditRecord` into a Doobie-backed
  `aegis_audit_events` table with one composite index per #20 audit-read filter
  (`actor_subject`, `resource`, `operation`, each paired with `occurred_at DESC`) plus a plain
  `occurred_at` index for retention scans. `context` is stored as JSONB so the existing
  `risk.score` / `outcome.decision` / `agent.jti` / etc. context keys survive without DDL churn —
  SIEM consumers query individual fields via `context->>'risk.score'`. Schema bootstraps on
  startup via `CREATE TABLE IF NOT EXISTS` + `CREATE INDEX IF NOT EXISTS` (idempotent; no Flyway
  dep yet). `actor_kind` column denormalises the `Principal` ADT discriminator
  (`Human` / `Service` / `Agent`) for fast filter scans. Retention via a `pruneBefore(cutoff)`
  method on the sink; `Server.boot` starts a background fiber that runs once daily and deletes
  rows older than `aegis.audit.retention.days` (default 365). Set `AEGIS_AUDIT_KIND=postgres` to
  enable; the existing `AEGIS_JDBC_URL` / `_USERNAME` / `_PASSWORD` env vars are reused (audit
  table lives in the same database as the event journal — operators configure one set of
  credentials). New `PostgresAuditSinkSpec` covers 8 Testcontainers cases (idempotent bootstrap,
  every-column write fidelity, principal-kind discrimination, empty-context default,
  insertion-order preservation, retention `pruneBefore` with strict `<` cutoff semantics +
  empty-table case, JSONB round-trip with newlines / quotes / unicode / long strings),
  Docker-gated via the existing `assume(dockerAvailable, ...)` pattern.

- **Agent-token issuance endpoint `POST /v1/agents/issue` (closes #18).** Exposes the existing
  `JwtIssuer` over REST so operators (and the upcoming `aegis agent issue` CLI) can mint
  short-lived agent JWTs programmatically. New `AgentTokenIssuer` in `aegis-iam` wraps the issuer
  with three concerns the raw `JwtIssuer` doesn't carry: **authz** (only `Principal.Human` can
  issue — `Service` and `Agent` callers are refused with `403 PermissionDenied`, enforcing the
  "agents cannot issue agents" rule from the spec), **validation** (label must be non-empty,
  scopes must parse as `Operation` names, TTL must be `> 0` and `≤ 24 h` by default), and
  **identity generation** (`agentId = agent-<uuid>`, `jti = <uuid>`). Wire body:
  `{label, scopes, ttlSeconds, parent?}` — when present, `parent` must equal the authenticated
  caller's subject (cross-principal issuance is rejected in v0.2.0; delegated issuance lands with
  a future release). Response: `{agentId, jwt, jti, expiresAt}`. The JWT carries the same claims
  the verifier already understands (`kind=agent`, `aegis_parent`, `aegis_purpose`, `aegis_ops`)
  plus a new `jti` claim for the future revocation list (#24). Wired into `Server.boot` for both
  auth modes: `hmac` reuses `aegis.auth.hmac.secret`; `dev` mints a per-boot ephemeral 48-byte
  secret (logged with a warning so operators don't confuse dev tokens with production).

- **`POST /v1/agents/issue` is audited.** Every call to the agent-issue endpoint — success
  AND failure — now produces an `AuditRecord` written to the configured sink (operation =
  `Create`, resource = `agent:<id>`, outcome carrying the agentId/jti/ttl/scopes). The JWT
  itself is NEVER recorded in the audit row (it's a bearer credential; recording it in
  plaintext would defeat its purpose). Test coverage asserts the JWT is absent from both
  outcome and context. `HttpRoutes` gained an optional `auditSink: Option[AuditSink[IO]]`
  constructor arg (no-op when not wired — the keys surface stays covered by
  `AuditingKeyService`); `Server.boot` wires the same `stdoutSink` already used for the
  keys-surface audit.

- **`jti` (RFC 7519 token ID) on all Aegis-issued JWTs.** `JwtClaims.Human` and `JwtClaims.Agent`
  gained a required `jti: String` field; `JwtIssuer` sets the `jti` claim via `builder.id(...)`;
  `JwtVerifier` extracts it on parse (tolerating absent `jti` as empty string for
  backwards-compatibility with externally-minted tokens). The JTI blacklist consumer ships with
  #24 (Redis-backed revocation list). 7 test sites updated to pass `jti` to the case-class
  constructors.

- **CI publishes `ghcr.io/<owner>/aegis-server:main` on every push to `main`.** New
  `.github/workflows/docker-main.yml` builds and publishes a floating `:main` image (and an
  immutable `:main-<short-sha>`) so the v0.2.0 wedge demo in the quickstart can be exercised
  without waiting for a tagged release. The workflow skips on docs-only commits (paths filter)
  to avoid burning CI minutes for typo fixes. `release.yml` (tagged releases) is untouched —
  `:0.1.x`, `:0.2.0`, … continue to be published from `v*` tags.

### Changed

- **`deploy/docker/docker-compose.yml` default image bumped `0.1.0` → `0.1.1`.** The compose
  default now pulls the latest stable tagged release; the embedded comment documents the three
  alternatives (`:main` for v0.2.0 preview, `:main-<sha>` for immutability, local build via
  `sbt 'server / Docker / publishLocal'`).

- **Docs + roadmap refresh reflecting the W2 + W3 wedge work on `main`.** `ROADMAP.md` 2.0.a /
  2.0.b / 2.0.c marked ✅ Shipped. `docs/index.md` feature table now lists the risk scorer,
  decision adapter, and auto-responder under "shipped (v0.2.0)" with explicit thresholds + default
  rules. `docs/about/status.md` updated per-capability snapshot (Agent-AI plane → Shipped; risk
  scorer / decision adapter / auto-responder rows replaced their WIP entries). `docs/about/comparison.md`
  gained explicit rows for "Risk-scored decisions" and "Auto-response to anomalies" (each marked
  as a first-class Aegis capability vs. DIY-on-CloudTrail-or-audit-devices elsewhere).
  `docs/ARCHITECTURE.md` request-lifecycle Mermaid diagram now shows the `RiskScorer`,
  `DecisionEngine`, `BaselineDetector`, and `AutoResponder` boxes wired through `AuditingKeyService` +
  `TappedAuditSink`, with explanatory prose covering the additive-risk-overlay-vs-policy-floor
  semantics and the "below-the-audit-decorator" no-recursion routing. `docs/getting-started/quickstart.md`
  extended from 14 to 18 steps: Step 14 switches the running stack from `:0.1.1` to `:main` (so the
  wedge demo actually exercises the new code — fixes the "I ran the quickstart and the auto-revoke
  didn't fire" report where Steps 15–17 silently produced no risk context against the pre-W2 image);
  Steps 15–17 are the **wedge demo** itself, tripping a `RateSpike`, showing the operator-grep-able
  `aegis-system` auto-revoke audit row, and exercising the decision adapter's `PermissionDenied` path.
  Time estimate updated 10 → 15 min, the introductory "What you'll have when you're done" callout
  spells out the wedge-demo deliverable so newcomers know what makes Aegis different before they start.

- **Auto-responder — recommendations become actions (closes #17).** New `AutoResponder` in
  `aegis-agent-ai` is itself a `RecommendationSink`: it decorates the existing in-memory store, so
  every `AgentRecommendation` is persisted first, then matched against a configured `List[AutoResponseRule]`,
  then executed if the rule fires and the per-`(actor, action)` cooldown allows.
  `AutoResponseAction` enum models the four execution actions: `Alert` (audit-only annotation),
  `Revoke` (calls `KeyService.revoke` on the target key extracted from `details("resource")`),
  `Deactivate` (mapped to `Revoke` for v0.2.0), and `Freeze` (records intent; full enforcement
  arrives with #24's JTI blacklist). Action audit rows are written with
  `actor = Principal.Service("aegis-system", TenantId("system"))` and the outcome string
  `AnomalyAlert(detector=…, severity=…, rec=<id>, action=…) Success|Failed …` so operators can grep
  the responder's timeline. The responder calls a "below the audit decorator" `KeyService` on
  purpose: routing through the outer `AuditingKeyService` would feed every auto-response back into
  the detector → recommendation pipeline, causing recursion. Default rule set covers all five
  baseline detectors at `High → Revoke` and `Medium → Alert`; `Low` is intentionally absent (too
  much noise — operators opt in). Wired into `Server.boot` between the recommendation store and the
  tapped audit sink. Failure modes (missing target key, invalid keyId, KMS error) are captured in
  the audit row, never thrown — `publish` is total. Operator-tuned rules via HOCON land in a follow-up.



- **Risk scorer with reasoning (closes #15).** New `RiskScorer[F[_]]` SPI in `aegis-core` returns a
  numeric score in `[0.0, 1.0]` plus a list of `RiskFactor` evidence rows (name + weight +
  human-readable evidence string) for every request. `BaselineRiskScorer` in `aegis-agent-ai`
  combines the five baseline detectors (scope, rate-spike, op-histogram, time-of-day, source-IP)
  with four contextual signals (`AgentPrincipal`, `CredentialAge` past 80 % of TTL, `BroadScope`
  > 5 allowed ops, `DestructiveOp` for Rotate / Compromise / Destroy / Revoke). `AuditingKeyService`
  takes an optional scorer constructor arg and stamps `risk.score` (two-decimal-place string) and
  `risk.factors` (semicolon-separated `name:weight` list) into every `AuditRecord.context` — for
  successful, denied, and failed calls alike, so post-incident review can answer "did the scoring
  engine already know this was risky?". Wired into `Server.boot` against the same `BaselineDetector`
  instance the tapped sink writes into. The decision adapter that *acts* on the score is #16 below.

- **Decision adapter — risk score becomes a verdict (closes #16).** New `Decision` enum in `aegis-core`
  (`Allow` / `Deny(reason)` / `StepUpRequired(reason)`) consolidated with `aegis-iam`'s pre-existing
  policy-decision type so the boolean policy gate and the risk overlay now speak the same vocabulary.
  New `DecisionEngine[F[_]]` SPI translates a `(RiskScore, Principal, Operation)` triple into a
  `Decision`. `ThresholdDecisionEngine` in `aegis-agent-ai` ships the default two-threshold
  implementation (`denyAt=0.85`, `stepUpAt=0.60`) with a per-op irreversibility tax —
  destructive ops (`Rotate`, `Compromise`, `Destroy`, `Revoke`) drop both thresholds by 0.15.
  `AuditingKeyService` gained an optional `engine: Option[DecisionEngine[IO]]` arg and now
  short-circuits the inner `KeyService` on `Deny` (returns `Left(KmsError(PermissionDenied, "risk: …"))`)
  and `StepUpRequired` (returns the new `Left(KmsError(StepUpRequired, reason))`). Every audit row
  stamps `outcome.decision` (`Allow` / `StepUp` / `Deny`) plus an `outcome.decision.reason` when the
  decision was non-`Allow`. New `ErrorCode.StepUpRequired` is an Aegis-specific extension (KMIP has no
  equivalent — the wire codec maps it to `OperationCanceledByRequester`); the HTTP layer translates it
  to `401 Unauthorized` with the reason in the JSON body. `locate` is intentionally never gated by
  the engine — filtering directory results would leak existence-or-not signal and isn't a useful
  security primitive; the policy gate handles discovery authorization separately. Wired into
  `Server.boot` with default thresholds; HOCON-configurable thresholds and a dedicated
  `WWW-Authenticate: aegis-stepup` response header land in follow-ups.

## 0.1.1 — 2026-05-09

First public, taggable release. Everything below shipped between the
`v0.1.0-rc.2` candidate and this tag — the full key-lifecycle and
crypto surface (sign / verify / encrypt / decrypt / wrap / unwrap /
rotate / compromise), JWT bearer auth, Postgres event journal,
Prometheus + OpenTelemetry observability, anomaly-detector baselines,
and the OpenAPI / Swagger UI documentation surface. v0.1.0 final was
never cut — what we'd planned as v0.1.0 is folded into this release.

### Changed

- **`Server` now boots inside a `Resource[IO, Unit]` (closes #12).** Refactored the entry point from
  `def main` + `unsafeRunSync` to `IOApp.Simple` + a single composed `Resource` chain. Each piece of
  the boot — Prometheus meter registry, journal connection pool, Pekko `ActorSystem`, HTTP binding —
  is acquired with a matching finalizer, so SIGTERM / SIGINT now unwinds the stack in reverse:
  HTTP unbind (5 s grace) → actor system terminate → journal pool close → meter registry close.
  v0.1.0's boot called `PostgresEventJournal.make(...).allocated.unsafeRunSync()._1` and discarded
  the finalizer, leaking the connection pool until JVM exit; that's gone. New `BootResourceSpec`
  acquires the full stack against a free local port, hits the listener, and verifies that releasing
  the resource closes the binding (no 200 on a subsequent connect).

### Added

- **Anomaly detector expansion: time-of-day, source-IP, op-histogram baselines (closes #13).**
  `BaselineDetector` now ships five detectors instead of two — adds `OpHistogramBaseline` (actor
  performed an `Operation` it has never used), `TimeOfDayBaseline` (actor active in a UTC hour
  outside their seen set), and `SourceIpBaseline` (request from a new IP, read from
  `AuditRecord.context("source.ip")`). Each detector has a cold-start guard: it requires the actor
  to have at least one prior observation in that dimension, so the first call doesn't alert. A
  single anomalous record can fire multiple detectors at once (compound anomalies — see the
  README's "Claude goes rogue" path). `ActorBaseline` gained `hoursSeen: Set[Int]` and
  `sourceIpsSeen: Set[String]`. `AuditRecord` gained an additive `context: Map[String, String] =
  Map.empty` field; the `SourceIpBaseline` detector reads `BaselineDetector.SourceIpContextKey`
  (`"source.ip"`) from it. The HTTP layer doesn't yet populate the context — that's a follow-up;
  until then the SourceIp detector is shape-complete and tested but inert in production.
- **OpenAPI 3.1 spec + Swagger UI on the REST plane (closes #52).** `HttpRoutes` now generates an
  OpenAPI document from the live `Endpoints.all` list and mounts the standard Swagger UI bundle at
  `/docs/`, with the raw YAML at `/docs/docs.yaml`. Because the spec is derived from the same Tapir
  endpoint definitions the routes interpret, drift between the docs and the wire shape is impossible
  by construction. The `tapir-openapi-docs` and `tapir-swagger-ui-bundle` deps were already in
  `Dependencies.scala` `tapir`; this PR is purely the route plumbing + a regression test that asserts
  every shipped path appears in the rendered spec.
- **Maven Central publishing — POM metadata + operator runbook (closes #14).**
  Each library module (`aegis-core`, `aegis-persistence`, `aegis-crypto`,
  `aegis-iam`, `aegis-audit`, `aegis-sdk-scala`, `aegis-sdk-java`,
  `aegis-kmip`, `aegis-http`, `aegis-agent-ai`, `aegis-mcp-server`) now
  declares its own one-line `description` so Sonatype's POM-validation
  staging gate accepts the artifact. `aegis-server` and `aegis-cli` keep
  `publish / skip := true` since they ship as a Docker image and a
  Universal tarball respectively. A `ThisBuild / description` fallback
  prevents an unnamed jar from regressing the gate. New `RELEASING.md`
  documents the one-time maintainer setup (Sonatype OSSRH account, GPG
  key generation + keyserver publication, the four GitHub Action secrets
  `PGP_SECRET` / `PGP_PASSPHRASE` / `SONATYPE_USERNAME` / `SONATYPE_PASSWORD`)
  plus the per-release workflow (CHANGELOG bump, `git tag v0.1.1 && git push
  origin v0.1.1`, what to expect on the Actions page) and a
  troubleshooting matrix. The existing `release.yml` workflow already
  gates the Maven publish step on `PGP_SECRET != ''`, so a release
  without secrets ships Docker + CLI only with a clear `::notice`.
- **OpenTelemetry tracing — application-level spans + autoconfigured SDK (closes #11).** New
  `TracingKeyService` decorator wraps each `KeyService[IO]` call in an OTel span named
  `kms.<operation>` with attributes `aegis.operation`, `aegis.key.id` (when applicable),
  `aegis.principal.subject`, `aegis.principal.kind` (`human` or `agent`), and `aegis.outcome`
  (`success` / `error_<code>`). Span status is set to `ERROR` with the `KmsError` message on
  failure. New `TracingRegistry` bootstraps the OTel SDK via `AutoConfiguredOpenTelemetrySdk` —
  configuration is driven entirely by the standard `OTEL_*` env vars / system properties
  (`OTEL_SERVICE_NAME`, `OTEL_TRACES_EXPORTER`, `OTEL_EXPORTER_OTLP_ENDPOINT`,
  `OTEL_TRACES_SAMPLER`, `OTEL_RESOURCE_ATTRIBUTES`). The decorator slots between
  `MeteredKeyService` and `AuditingKeyService`. **For full request-graph coverage** (pekko-http
  server spans, JDBC client spans, AWS SDK client spans), attach the OpenTelemetry Java Agent at
  JVM start (`-javaagent:opentelemetry-javaagent.jar`) — the agent and the SDK both read the same
  `OTEL_*` env vars, so configuration is unchanged and our manual spans become children of the
  agent's via W3C trace-context propagation. New `TracingKeyServiceSpec` uses the OTel
  `InMemorySpanExporter` to assert span names, attributes, status codes, and the locate-specific
  `aegis.locate.hits` attribute. Adds the `opentelemetry-api` + `-sdk` + `-exporter-otlp` +
  `-sdk-extension-autoconfigure` deps (server-tier only — library modules unaffected) plus
  `opentelemetry-sdk-testing` at test scope.
- **Docker Compose hardening: no default Postgres password (closes #51).**
  `deploy/docker/docker-compose.yml` no longer ships the
  `aegis-dev-password-change-me` default. Both the Postgres container and the
  `aegis-server` JDBC password now reference `${POSTGRES_PASSWORD:?...}` —
  Compose fails fast with a clear error if the operator hasn't exported the
  variable. `SECURITY.md` gains a new "Deploy-time configuration" section
  enumerating the env vars that must be supplied (`POSTGRES_PASSWORD`,
  `AEGIS_AUTH_HMAC_SECRET` when JWT auth is on, AWS creds when the KMS
  root-of-trust is configured) and noting that TLS termination is the
  fronting proxy's responsibility until the v0.4.0 KMIP plane ships native
  mTLS.
- **Prometheus `/metrics` endpoint (closes #10).** New `MeteredKeyService` decorator slots between
  `AuditingKeyService` and `AuthorizingKeyService` in the boot wiring and records three series per
  `KeyService` operation: `aegis_keys_op_total{operation}` (counter),
  `aegis_keys_op_duration_seconds{operation, outcome}` (timer with percentile histogram so dashboards
  can compute p50/p95/p99), and `aegis_keys_op_errors_total{operation, code}` (counter tagged by the
  `KmsError.code`, so denies surface as `code="PermissionDenied"`). The metrics layer sits **outside**
  auth so denies are countable; audit stays the outermost decorator so the audit row still reflects the
  true outcome. New `MetricsRegistry.make()` builds a `PrometheusMeterRegistry` and binds the standard
  JVM/GC/threads/classloader/processor/uptime collectors. New `MetricsRoutes.route` exposes
  `GET /metrics` in Prometheus exposition format (`text/plain; version=0.0.4`) on the same pekko-http
  port as the application routes — it lives in `aegis-server` rather than `aegis-http` so the Tapir
  API module stays Micrometer-free. `Server.scala` builds the registry once at boot and stitches the
  metrics route into the application route via `concat(...)`. Adds the `micrometer-core` +
  `micrometer-registry-prometheus` deps (server-tier only — library modules unaffected).

### Fixed

- **Server boot hung on first launch.** `aegis-server` used a Pekko user-guardian + Promise pattern
  to expose the `KeyOpsActor`'s `ActorRef` to the main thread. On some JDK + sbt + Pekko combinations,
  the guardian's `Behaviors.setup` block was never dispatched, so `Await.result(initialized.future, …)`
  hung past every reasonable timeout. The fix makes the user guardian *be* the `KeyOpsActor` directly
  (`ActorSystem[T] <: ActorRef[T]` in Pekko Typed) and removes the Promise/Await dance entirely.
  This affected the `sbt 'server / run'` README quickstart and the Docker image's startup.
- **CLI launcher script was named `bin/aegis-cli`, not `bin/aegis`.** sbt-native-packager defaults to
  the project name; we now set `executableScriptName := "aegis"` so the published tarball matches the
  README's `./aegis-cli-0.1.0/bin/aegis version` instructions.
- **`Server.scala` ran sbt's `run` task in-process (no fork).** Added `run / fork := true` for the
  `server` module so the run task gets an isolated JVM. Previously this entangled Pekko's dispatcher
  with sbt's classloader.

### Added

- **Sign / verify across the whole stack (closes #5).** New `sign(id, message, alg, by)` and
  `verify(id, message, signature, by)` methods on `KeyService[F[_]]` in `aegis-core`, with
  `Operation.Sign` / `Operation.Verify` added to the IAM allowlist enum, a new `Signature` type +
  `SigAlgorithm` enum (`RsaPssSha256`, `EcdsaSha256` for v0.1.1), and matching `AuditingKeyService`
  decorator records that capture the algorithm and `valid=true|false` outcome. The `RootOfTrust` SPI
  gained the same operations; `AwsKmsRootOfTrust` implements them via the AWS KMS `Sign` / `Verify`
  APIs (mapping `RsaPssSha256` → `RSASSA_PSS_SHA_256`, `EcdsaSha256` → `ECDSA_SHA_256`). On the wire:
  `POST /v1/keys/{id}/sign` (request: `{messageBase64, algorithm}`, response: `{signatureBase64,
  algorithm}`) and `POST /v1/keys/{id}/verify` (request adds `signatureBase64`, response is `{valid,
  algorithm}`). The CLI gained `aegis keys sign --id <id> --message <text|@file> [--alg
  RsaPssSha256]` and `aegis keys verify --id <id> --message <text|@file> --signature <base64> [--alg
  RsaPssSha256]`; verify exits 0 for `valid:true`, 3 for `valid:false`. The in-memory `KeyService`
  uses a deterministic HMAC-SHA-256 keyed by the KeyId so the dev REST surface has a working
  round-trip without a real KMS. Sign requires the key to be in `KeyState.Active`; calls against
  PreActive keys return `KmsError(IllegalOperation, ...)` and produce a `Failed` audit record.
- **`ReadmeQuickstartSpec` in `aegis-core`.** Compiles + runs the embedded-library example from
  `README.md` so that snippet can never silently bitrot. If you change the README's
  "Quickstart — embedding as a library" Scala block, mirror the change in this test.
- **Rotate(id, policy) across the whole stack (closes #8).** New
  `rotate(id, policy, by)` method on `KeyService[F[_]]`. `ManagedKey` gains
  `currentVersion: Int = 1` (additive — defaulted for back-compat); rotation increments it
  by one. Legal source state is `Active` only; rotating from any other state returns
  `KmsError(IllegalOperation, ...)`. The new value type `RotationPolicy` (`Manual |
  TimeBased(FiniteDuration) | OpCountBased(Long)`) is recorded on the rotation event and
  audit row — `Manual` for explicit calls today, the auto variants reserved for the v0.2.0
  scheduler. New `KeyEvent.Rotated(newVersion, policy)` journal event with circe codec so
  replays restore `currentVersion` deterministically. The "old version stays
  verifiable/decryptable after rotation" contract from `docs/ARCHITECTURE.md` §3 is
  preserved without per-version material storage: the in-memory dev backend keys its
  deterministic MAC by `KeyId` only (so byte output is version-stable), and AWS KMS
  handles per-version material internally — the same CMK decrypts both pre- and
  post-rotation ciphertexts. Added `Operation.Rotate` to the IAM allowlist enum;
  `AuthorizingKeyService` guards via the policy engine; `AuditingKeyService` records
  `newVersion=N policy=...`; `ActorBackedKeyService.rotate` routes through the actor
  mailbox for journal-serialized state changes; `PostgresEventJournal` learns the new event
  kind. On the wire: `POST /v1/keys/{id}/rotate` (request `{policy?}`, response full
  `ManagedKeyDto` with the bumped `currentVersion`). The CLI gained `aegis keys rotate
  --id <id> [--policy Manual|TimeBased:7days|OpCountBased:N]`. `ManagedKeyDto` (HTTP +
  CLI wire shapes) gained the `currentVersion` field; existing JSON without the field
  decodes as `currentVersion=1` via the case-class default.
- **Compromise operator override across the whole stack (closes #9).** New
  `compromise(id, reason, by)` method on `KeyService[F[_]]`. Marks the key as `Compromised`;
  from this state every cryptographic operation — including `verify` — refuses with
  `KmsError(IllegalOperation, ...)`. (Note: `verify` was previously permitted on any state;
  this PR tightens it to refuse `Compromised` and `Destroyed`, matching the lock-down
  semantics described in `docs/ARCHITECTURE.md` §3.) Compromise is one-way: from
  `{PreActive, Active, Deactivated}` → `Compromised`; `Destroyed` keys cannot be compromised.
  The mandatory `reason` is a non-empty human-readable justification (e.g. "discovered in S3
  audit leak 2026-05-08") and ends up on the audit row at `severity=Critical`. Added
  `Operation.Compromise` to the IAM allowlist enum and a new `KeyEvent.Compromised` journal
  event with circe codec so the journal replays the state transition deterministically. The
  state-mutating call routes through `KeyOpsActor` so the journal append + state transition
  are serialized with the rest of the lifecycle. On the wire: `POST /v1/keys/{id}/compromise`
  (request: `{reason}`, response: full `ManagedKeyDto`); blank reasons are rejected with 400
  `InvalidField`. The CLI gained `aegis keys compromise --id <id> --reason "<text>"`.
- **Wrap / unwrap across the whole stack (closes #7).** New `wrap(id, dek, by)` and
  `unwrap(id, wrappedDek, by)` methods on `KeyService[F[_]]` for KMIP-style envelope
  encryption, with `Operation.Wrap` / `Operation.Unwrap` added to the IAM allowlist enum and
  a new `WrappedDek` value type. The `RootOfTrust` SPI gained `wrap` / `unwrapDek`;
  `AwsKmsRootOfTrust` implements them by delegating to the existing AWS KMS `Encrypt` /
  `Decrypt` calls with an empty `EncryptionContext` (AWS doesn't expose separate Wrap/Unwrap
  APIs for symmetric CMKs — this is the conventional wire-up). On the wire:
  `POST /v1/keys/{id}/wrap` (request: `{dekBase64}`, response: `{wrappedDekBase64}`) and
  `POST /v1/keys/{id}/unwrap` (request: `{wrappedDekBase64}`, response: `{dekBase64}`). The
  CLI gained `aegis keys wrap --id <id> --dek <text|@file>` and `aegis keys unwrap --id <id>
  --wrapped <b64>`. Same state-gate as encrypt/decrypt: wrap requires `Active`; unwrap is
  permitted on `Active` + `Deactivated` so historical wrapped DEKs remain recoverable across
  rotations, refused on `Compromised` / `Destroyed`. The `AuditingKeyService` decorator
  records `dekLen` (not the bytes) so audit logs show what was protected without leaking
  key material.
- **Encrypt / decrypt across the whole stack (closes #6).** New
  `encrypt(id, plaintext, context, by)` and `decrypt(id, ciphertext, context, by)` methods on
  `KeyService[F[_]]`, with `Operation.Encrypt` / `Operation.Decrypt` added to the IAM allowlist
  enum and a new `Ciphertext` value type. Encryption context (the `Map[String, String]` AAD) is
  carried as a separate parameter — not embedded in the ciphertext — so the same context must be
  supplied to both sides, mirroring AWS KMS semantics. A context mismatch on decrypt returns
  `KmsError(CryptographicFailure, ...)`. The `RootOfTrust` SPI gained the same operations;
  `AwsKmsRootOfTrust` implements them via the AWS KMS `Encrypt` / `Decrypt` APIs with
  `EncryptionContext` plumbed through `AwsKmsPort`. On the wire: `POST /v1/keys/{id}/encrypt`
  (request: `{plaintextBase64, context}`, response: `{ciphertextBase64, context}`) and
  `POST /v1/keys/{id}/decrypt` (request: `{ciphertextBase64, context}`, response:
  `{plaintextBase64, context}`). The CLI gained `aegis keys encrypt --id <id> --plaintext
  <text|@file> [--context k=v,k2=v2]` and `aegis keys decrypt --id <id> --ciphertext <b64>
  [--context k=v,k2=v2]`. The in-memory `KeyService` uses a deterministic HMAC-keyed
  XOR-keystream layout (`HMAC(id, ctx) || pt XOR keystream(id, ctx)`) so the dev REST surface
  has a working round-trip without a real KMS. Encrypt requires the key to be in
  `KeyState.Active`; decrypt is permitted on `Active` and `Deactivated` keys (so existing
  ciphertexts remain readable after a future rotation lands), but refused on `Compromised` /
  `Destroyed`. The `AuditingKeyService` decorator records the **context keys (not values)** and
  the plaintext length on success, so audit logs surface what was protected without leaking the
  AAD's payload.

### Documentation

- **README accuracy pass.** Each section that described future capabilities is now explicitly
  marked 🚧 WIP (status column in tables, design-preview callouts above example/demo transcripts).
  The "Modules" table now lists per-module v0.1.0 status. The library-embedding example was rewritten
  to actually compile (the previous version used `KeyService.inMemory[IO]` which doesn't typecheck —
  `KeyService.inMemory` returns `IO[KeyService[IO]]`). Added a callout under "Docker Compose
  quickstart" telling users how to build the image locally before v0.1.0 hits GHCR.

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
