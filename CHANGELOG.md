# Changelog

All notable changes to Aegis will be documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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
