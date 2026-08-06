# Changelog

All notable changes to Aegis will be documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- **GCP Cloud KMS root-of-trust (closes #31, ROADMAP 3.0.a).** `AEGIS_CRYPTO_KIND=gcp-kms` selects
  `dev.aegiskms.crypto.gcp.GcpKmsRootOfTrust`, the second cloud backend and the one that proves the
  `RootOfTrust` SPI is not AWS-shaped. Configured with project / location / key-ring / crypto-key;
  credentials come from Application Default Credentials. Cloud KMS is missing two primitives the AWS
  adapter leans on, so this is a genuine adapter rather than a rename:
  - **No `GenerateDataKey`.** AWS returns a plaintext + wrapped DEK pair from one HSM-side call. Cloud KMS
    has no equivalent, so `generateDataKey` composes `GenerateRandomBytes` (HSM protection level) with
    `Encrypt` under the KEK. The randomness still comes from Google's HSMs rather than this process, but it
    costs an extra round-trip and the plaintext DEK transits the client — inherent to Cloud KMS, and now
    documented in the ARCHITECTURE root-of-trust table.
  - **No `Verify`.** Cloud KMS only signs. `verify` fetches the CryptoKeyVersion's public key and checks
    locally with JCE — the documented Google pattern, and not a weakening, since verification needs only
    public material.
  - Signing sends a locally computed SHA-256 `Digest`, not the message. The encryption-context map is
    serialised to Cloud KMS's single opaque AAD string using the same canonical, length-prefixed encoding
    the software backend uses, so map ordering cannot change the bytes and `{"ab":"c"}` cannot collide with
    `{"a":"bc"}`. Oversized plaintexts are rejected locally against Cloud KMS's 64 KiB symmetric-encrypt
    limit rather than deferred to a remote `INVALID_ARGUMENT`.
  - **New artifact `aegis-crypto-gcp`.** `google-cloud-kms` pulls ~52 transitive jars (~45 MB of gRPC,
    protobuf, Guava, GAX) — roughly doubling `aegis-crypto`, which is library-tier and meant to embed in
    any JVM app. Vendor adapters therefore get their own artifacts from here on; the SPI stays in
    `aegis-crypto` and consumers depend only on the backends they use. Azure, Vault, and PKCS#11 will
    follow this shape. Moving the existing AWS adapter out is a breaking change and deserves its own issue.
  - **Env-gated integration suite.** `GcpKmsIntegrationSpec` runs against a real Cloud KMS project when
    `AEGIS_IT_GCP_*` is set and skips cleanly otherwise, the same way the Testcontainers suites skip without
    Docker. It pins the things a stub cannot: that AAD binding is enforced by the service, that
    `GenerateRandomBytes` accepts the location format we build, and that a signature Cloud KMS produces
    verifies against the public key it returns. It also pins the fact that Cloud KMS ciphertext is **not**
    scoped by `KeyId` — every Aegis key maps to the same CryptoKey, unlike the software backend's per-key
    derivation — so ROADMAP 3.0.e (per-key RoT routing) changes that visibly rather than silently.

- **Agent kill-switch — revoke a parent's whole agent fleet in one call (closes #102, ROADMAP 3.0.n).**
  `POST /v1/agents/revoke` and `aegis agent revoke --parent alice@org [--issued-after <ISO>]` blacklist the
  `jti` of every currently-active agent under an operator. Revocation goes through the `RevocationList` SPI,
  so it works unchanged against the Redis-backed list — a kill lands fleet-wide, not on whichever replica
  served the request. Idempotent, and a store failure on one agent does not abort the sweep. The response
  reports killed / already-revoked / expired separately: mid-incident, "I stopped 12" and "I stopped 1 and
  11 were already dead" are different answers. Audit gets one record per revoked agent plus one summary row
  for the sweep.

- **Step-up authentication (ROADMAP 3.0.n).** `ErrorCode.StepUpRequired` has existed since the risk engine
  landed, but nothing could ever *demand* step-up — it was only produced as advice by the risk scorer. Now
  `Principal.Human` and `JwtClaims.Human` carry the OIDC-standard `amr` and `auth_time` claims, and
  `StepUpPolicy` gates the kill-switch on both: a strong authentication method **and** a recent one. Failing
  callers get a real RFC 7235 challenge — `WWW-Authenticate: aegis-stepup realm="aegis", reason=…, acr=…,
  max_age=…` — naming what they need. Configurable via `aegis.security.step-up.{methods,max-age-seconds}`.
  Everything fails closed: a missing `amr`, a missing `auth_time`, a future `auth_time`, or a non-human
  principal is refused, because a token minted before Aegis understood step-up must not pass as having done
  it. `pwd` is deliberately not an accepted method — it is what the user already presented to get the
  session.
  - Freshness is the condition doing the real work. A long-lived token minted after a legitimate MFA login
    is exactly what an attacker steals; without a time bound it would satisfy an `amr`-only check forever.

- **Auto-responder can pull the kill-switch (`AutoResponseAction.KillAgentFleet`).** Off by default and
  absent from `DefaultRules`: it requires both `aegis.auto-response.kill-fleet.enabled=true` and an operator
  writing the rule. One false positive revokes an operator's entire fleet rather than one credential, so
  enabling it is a deliberate decision about blast radius — never something inherited by upgrading. With the
  flag off the action degrades to an audited no-op rather than failing silently.

- **Agent registry — one answer to "which agents exist right now?" (closes #101, ROADMAP 3.0.m).**
  `GET /v1/agents` and `aegis agent list` return every agent credential minted in the last 7 days with its
  issuing operator, scopes, validity window, last-seen activity, and lifecycle status
  (`Active` / `Expired` / `Revoked`). Filterable by `parent` and `status`, paginated, and human-principal
  only — letting an agent enumerate its peers would hand a compromised credential a map of every other
  credential to target. A new `aegis_agents_active` Prometheus gauge tracks the live count.
  - **Derived from the audit log, not a new table.** Agent issuance is already recorded by
    `HttpRoutes.writeAgentIssueAudit` (agent id, jti, scopes, ttl, label, issuing human), so
    `AgentRegistry.auditBacked` reads that back and joins it against the revocation list rather than adding a
    second write path that could disagree with it. Agents issued *before* this release still appear — there
    is no backfill. Retention cannot lose a live agent: tokens are capped at 24 h while audit retention
    defaults to 365 days.
  - Requires a queryable audit sink. On the default `stdout` sink, `GET /v1/agents` returns
    `501 FeatureNotSupported` — the same behaviour `/v1/audit` and `/v1/advisor/scan` already have.
  - **`AuditQuery` SPI additions (source-breaking for external implementors):** `Filter.resourcePrefix` for
    left-anchored `resource` matching (keeps the existing btree index usable; LIKE metacharacters are
    escaped), and `lastActivityBy(actors, since)` — a `GROUP BY` that answers "when was each of these actors
    last seen" in one round-trip. The latter is abstract rather than defaulted on purpose: a default
    returning empty would make external implementations silently under-report last-seen.
  - `InMemoryAuditSink` now implements `AuditQuery` with the same filter semantics as `PostgresAuditSink`, so
    read-side consumers can be unit-tested against a real implementation. It remains deliberately
    unselectable via `aegis.audit.kind`.

- **Software root-of-trust — real crypto with no cloud account (closes #34, ROADMAP 3.0.d).**
  `AEGIS_CRYPTO_KIND=software` selects `dev.aegiskms.crypto.software.SoftwareRootOfTrust`, the second
  `RootOfTrust` implementation and the first that needs no external service. It performs genuine
  AES-256-GCM, RSA-PSS-SHA-256 and ECDSA-P-256 through the JDK's own JCE providers — no new dependency,
  no network call — so signatures actually verify and ciphertext is actually ciphertext, unlike the
  deterministic-MAC `in-memory` backend. Key material lives in a PKCS#12 keystore
  (`AEGIS_CRYPTO_SOFTWARE_KEYSTORE_PATH` + `_PASSWORD`, or an ephemeral in-heap keystore when the path is
  unset). Each operation family derives its own AES key from the KEK via HKDF-SHA-256 keyed by purpose and
  `KeyId`, so ciphertext for one key cannot be opened as another and the wrap / encrypt / data-key families
  are cryptographically separated; the encryption context is bound as GCM AAD. `rotate` mints a new KEK
  generation and retains earlier ones — the generation travels in the ciphertext header, so material
  wrapped before a rotation still unwraps after it.
  - **Not a production backend, and Aegis says so.** The KEK and signing keys sit in the server's heap, so
    selecting it logs a warning banner at boot and `Preflight` reports it as a dev-grade setting —
    `AEGIS_SECURITY_PREFLIGHT=enforce` refuses to bind a network-reachable address with it configured.
    It is meant for CI, integration tests, and evaluating Aegis without AWS credentials.
  - **Known limitation:** signing is not separated per key. One keypair per `SigAlgorithm` serves the whole
    keystore, so a signature produced for key A verifies under key B. `AwsKmsRootOfTrust` behaves the same
    way (it signs with the single configured CMK regardless of `KeyId`); per-key backing keys are ROADMAP
    3.0.e (per-key RoT routing) across every adapter. The behaviour is pinned by an explicit test.

- **Real SDKs — `aegis-sdk-scala` + `aegis-sdk-java` now work (closes #98, ROADMAP 2.2.a).** Both published
  SDK artifacts previously threw on their only entry point (`NotImplementedError` /
  `UnsupportedOperationException`). The CLI's tested blocking client (`AegisHttpClient` + `WireFormats` +
  `HttpPort`) moved down into `aegis-sdk-scala` under `dev.aegiskms.sdk`, gaining bearer-token auth
  (`Authorization: Bearer <jwt>`) alongside the dev `X-Aegis-User` header. `AegisClient.https(baseUrl, token)`
  / `AegisClient.dev(baseUrl, principal)` return a working client with full REST coverage (key lifecycle,
  sign/verify, encrypt/decrypt, wrap/unwrap, rotate/compromise, agent issuance, audit read, advisor).
  `aegis-sdk-java`'s `AegisClientJ` is now a thin pure-Java delegate over the new `javadsl.AegisJavaClient`:
  `java.util` collections in, wire DTOs out, failures as one `AegisClientException`. The CLI consumes the SDK
  client, so the wire code exists exactly once.

- **Production preflight (closes #99, ROADMAP 2.2.b).** `Server.boot` step 0 cross-checks the bind address
  against dev-grade settings (`auth.kind=dev`, `policy.kind=dev`, `crypto.kind=in-memory`,
  `journal.kind=in-memory`). Loopback binds always pass. On a network-reachable bind,
  `aegis.security.preflight=warn` (default) prints one unmissable banner listing each finding and its risk;
  `enforce` (set `AEGIS_SECURITY_PREFLIGHT=enforce` — recommended for production) refuses to boot before any
  resource is acquired.

### Changed

- **CLI wire DTOs moved package.** `dev.aegiskms.cli.{AegisHttpClient, WireFormats, HttpPort}` are now
  `dev.aegiskms.sdk.*` (the CLI re-uses them from the SDK). Source-breaking only for code that imported the
  CLI's internals — the CLI itself is unchanged on the command line.

## 0.2.1 — 2026-06-06

### Added

- **`aegis advisor explain <agent-id>` — agent-session timeline + LLM narration (closes #29, ROADMAP
  2.1.b/2.1.d).** The last piece of the v0.2.1 LLM-advisor wedge: assembles one agent's audit timeline
  (chronological events, risk scores, anomaly flags + a deterministic summary) and — when an LLM provider is
  configured (#30) — narrates it in plain language. **Read-only and safe by construction** (2.1.d): the model
  is handed only the structured timeline under a strict read-only system prompt, the prompt is bounded by a
  `maxEvents` cap, and any LLM failure **degrades gracefully** to the bare deterministic timeline rather than
  erroring. With `aegis.advisor.llm.provider=none` (the default) there are no outbound calls at all.
  - **`AdvisorService.explain`** (`aegis-agent-ai`): pages the audit log filtered to the agent, builds the
    timeline via the pure `AdvisorExplain.timeline`, then optionally narrates via the injected `LlmClient`.
  - **`GET /v1/advisor/explain/{agentId}`** (`aegis-http`): human-only, `501` when no advisor is wired; knobs
    `lookbackDays` / `maxEvents`.
  - **`aegis advisor explain <agent-id>`** (`aegis-cli`): prints the narrative (when present) followed by the
    event timeline.
  - **Wiring**: `Server.boot` now builds the LLM provider from `aegis.advisor.llm.*` and threads it into the
    advisor — the integration point for #30. New `application.conf` `aegis.advisor.llm` block (provider /
    api-key / base-url / model / max-tokens, all env-overridable; defaults to `provider=none`).

- **Pluggable LLM provider SPI + adapters (#30, ROADMAP 2.1.c).** The `LlmClient[F]` SPI in `aegis-agent-ai`
  now has three bundled, config-selected adapters: **Anthropic** (`POST /v1/messages`) and **OpenAI**
  (`POST /v1/chat/completions`) for the "pair with your existing AI vendor" path, and **Ollama**
  (`POST /api/generate`) for local/private use — audit data never leaves the host. `LlmClient.fromConfig`
  selects by name (`none` → disabled, returns no client; unknown name fails fast). Adapters call through a
  tiny testable `LlmHttp` seam (JDK-backed default), so each provider's request shape and response parsing are
  unit-tested with no network or API key. The contract stays read-only — the model only ever
  describes/recommends, never executes a crypto op. (Bedrock is the remaining fast-follow — it needs AWS
  SigV4; the SPI is provider-shaped for it. Wired into a running feature by `advisor explain`, #29.)

- **`aegis advisor scan` — read-only audit triage (closes #28, ROADMAP 2.1.a).** The first slice of the
  v0.2.1 LLM-advisor wedge, deliberately *deterministic* (no LLM, no mutation): it aggregates the audit log
  into a bounded operator summary — idle keys, broad-scope agents, active anomalies, and the riskiest agents.
  Keeping the analysis deterministic means the headline demo runs in CI with no API key and the numbers are
  reproducible. The pluggable `LlmClient` (#30) layers natural-language narration over these same facts later.
  - **`AdvisorService[F]` SPI + `AdvisorScan` analyzer** (`aegis-agent-ai`): the heuristics live in a pure
    `AdvisorScan.analyze` (property-testable against synthetic records); `AdvisorService.deterministic` pages
    the audit log via the existing `AuditQuery` SPI up to a 50k-row cap and marks the report `truncated` when
    the window exceeds it (no silent under-reporting).
  - **`GET /v1/advisor/scan`** (`aegis-http`): human-principals-only (Service/Agent get 403), `501` when the
    server has no queryable audit sink (audit kind ≠ postgres) — same access model as `GET /v1/audit`. Tuning
    knobs `lookbackDays` / `unusedDays` / `broadScope` / `top` fall back to defaults (90 / 30 / 5 / 5).
  - **`aegis advisor scan`** (`aegis-cli`): replaces the long-standing stub; flags `--lookback-days`,
    `--unused-days`, `--broad-scope`, `--top`; sectioned terminal output that prints "none" for empty
    findings.
  - **Wiring**: `Server.boot` builds the advisor over the same `AuditQuery` that backs the audit-read
    endpoint, so it's available exactly when audit-read is. `aegis-http` now depends on `aegis-agent-ai` (both
    server-tier; no Pekko added to the library tier).

### Fixed

- **`Docker (main)` workflow flaked on a transient GHCR push.** The `:main` image build/push intermittently
  red-X'd with `unknown blob` even though the image built and every layer uploaded — a registry-side manifest
  race, not a build failure. The publish step now retries up to 3× with backoff so a flaky push no longer
  fails an otherwise-good `main` build. (`release.yml` has the same single-shot publish and would benefit from
  the same treatment.)

- **Honey-key auto-revoke never fired (regression in #26).** Two gaps meant a honey-key touch
  produced the `HoneyKey`/High recommendation but no `Revoke` action: (1) `AutoResponder.DefaultRules`
  was built from only the five baseline detector names — `"HoneyKey"` was missing, so the rule
  lookup returned `None`; (2) `AutoResponder.extractKeyId` required a `key:<id>` resource prefix,
  but op-on-key audit records carry the bare `KeyId`, so even with a matching rule the revoke failed
  with "resource is not a key reference." Added `"HoneyKey"` to `DefaultRules` and taught
  `extractKeyId` to accept a bare `KeyId` (still rejecting `name:` / `pattern:` create/locate
  resources). The canary now actually revokes the key on first agent touch. Caught by a new
  end-to-end test (`HoneyKeyAutoRevokeE2ESpec`) that assembles the real detector → auto-responder →
  actor stack rather than hand-built recommendation fixtures.

### Changed

- **Doobie `1.0.0-RC5` → `1.0.0-RC12`** (latest RC; `1.0.0` final is not yet released).
- **Docker release publishing** now also pushes the floating `:MAJOR.MINOR` and `:latest` aliases
  for stable `vX.Y.Z` tags (pre-release tags get the exact tag only).
- **MkDocs `strict: true`** to match the CI `--strict` build; fixed several intra-page anchor links.
- **Maven Central publishing migrated to the Sonatype Central Portal.** Bumped sbt `1.10.2` →
  `1.12.11` and `sbt-ci-release` `1.6.1` → `1.11.2`, and removed the
  `sonatypeCredentialHost := "s01.oss.sonatype.org"` setting — the legacy OSSRH host was sunset
  2025-06-30, and `sbt-ci-release` 1.11+ targets `central.sonatype.com` automatically. `RELEASING.md`
  updated with the Central Portal namespace + user-token setup. (Publishing still requires the
  `PGP_*` / `SONATYPE_*` secrets to be configured.)

## 0.2.0 — 2026-05-31

### Added

- **Honey keys (canary keys) with auto-revoke on agent touch (closes #26).** Operator-marked
  `KeyId`s that fire a `Severity.High` recommendation any time an agent principal touches
  them; `AutoResponder.DefaultRules` then translate High → Revoke, killing both the key and
  the agent's JWT via the wired `RevocationList`. The first touch is the trip wire by
  design — there's no cold-start guard like the other detectors have.
  - **`HoneyKeyRegistry` SPI** (`aegis-agent-ai`): tiny — `isHoney(KeyId): Boolean` +
    `snapshot: Set[KeyId]`. Three impls: `empty` (production-safe default), `fromSet` for
    HOCON-backed wiring, and the ctor-default on `BaselineDetector.make` so embedders
    compile unchanged.
  - **`BaselineDetector` gains a 6th detector** (`"HoneyKey"`) that runs after the five
    existing ones. Restricted to agent principals only — humans validating that a canary
    is still alive don't trigger auto-revoke. Skips Create / Locate audit resources (their
    `name:...` / `pattern:...` shapes don't yield a parseable `KeyId`).
  - **`Server.boot` wiring**: `aegis.security.honey-keys` HOCON list parsed into a
    `Set[KeyId]` and threaded into `BaselineDetector.make(honeyKeys = ...)`. Supports both
    HOCON-list syntax and the `AEGIS_HONEY_KEYS` comma-separated env-var override. Boot
    fails fast on malformed `KeyId` strings (a typo'd canary that doesn't catch the agent
    is the opposite of what an operator wanted).
  - **Tests:** `HoneyKeyRegistrySpec` (4 cases — `empty`, `fromSet` semantics, snapshot
    fidelity, `fromSet(Set.empty)` equivalence). `BaselineDetectorSpec` (+6 cases —
    happy-path fire, first-touch trip wire, human-touch no-fire, non-honey no-fire,
    empty-registry inert, Create/Locate skip).

- **Kafka + NATS JetStream audit fan-out sinks (closes #22, closes #23).** Two new streaming
  audit destinations alongside the existing SIEM webhook (#21). Both follow the same shape
  — bounded `Queue` + background drain fiber + retry + JSONL dead-letter — and compose with
  the primary durable sink via `FanOutAuditSink`, so operators can run e.g.
  `postgres + kafka + nats` simultaneously.
  - **`KafkaAuditSink`** (`aegis-server`) uses Pekko-Connectors-Kafka's `SendProducer` with
    an idempotent producer config (`acks=all`, `enable.idempotence=true`,
    `max.in.flight.requests.per.connection=5`, `retries=Int.MaxValue`, `compression=lz4`).
    Each record's Kafka key is its `correlationId` so messages from the same KMS request
    land on the same partition, preserving order for downstream consumers.
  - **`NatsAuditSink`** (`aegis-server`) uses `io.nats:jnats` 2.21 with JetStream's
    `publishAsync` + `PubAck` for durability — the drain fiber only ack's a record once
    JetStream has durably persisted it. Optional `autoCreateStream=true` provisions the
    stream on boot if missing (idempotent — existing streams are left untouched). Supports
    optional NATS credentials file (`.creds` from `nsc add user --csv`).
  - **`Server.boot` fan-out wiring:** `kafkaAuditSinkResource` and `natsAuditSinkResource`
    are added alongside `webhookAuditSinkResource`. All three return an empty list when
    disabled, so the default path stays zero-cost. Fail-fast at boot on empty
    `bootstrap-servers` / `topic` / `servers` / `stream` / `subject`.
  - **New HOCON blocks:** `aegis.audit.kafka.{enabled, bootstrap-servers, topic, client-id,
    max-retries, initial-backoff-ms, max-backoff-ms, dead-letter-file, queue-capacity}` and
    `aegis.audit.nats.{enabled, servers, stream, subject, auto-create-stream,
    credentials-file, max-retries, initial-backoff-ms, max-backoff-ms, dead-letter-file,
    queue-capacity}`. All overridable via `AEGIS_AUDIT_KAFKA_*` / `AEGIS_AUDIT_NATS_*`.
  - **New dependencies:** `pekko-connectors-kafka` 1.1.0 (pairs with pekko 1.1.x) and
    `io.nats:jnats` 2.21.1. Test-only Testcontainers modules for Kafka and NATS.
  - **Tests:** `KafkaAuditSinkSpec` (4 cases — happy-path consume, canonical-JSON round-trip,
    transport failure → DLQ, Config validation) and `NatsAuditSinkSpec` (5 cases — same
    coverage plus idempotent `autoCreateStream`). Integration tests use shared containers
    via `BeforeAndAfterAll` per the workflow-speed pattern established in PR #86. Skip
    cleanly on machines without Docker.
  - **Doc updates:** ROADMAP audit-sink table (Kafka + NATS both ✅ v0.2.0); also flipped
    several stale `🔜 v0.2.0` rows that had drifted from reality (risk scorer, OIDC,
    agent-token endpoint, Redis revocation). ARCHITECTURE.md mermaid diagrams + v0.2.0
    status table updated.

- **MySQL + SQLite event journal adapters (closes #49, closes #50).** The persistence SPI now
  ships three relational backends instead of one. Operators pick via the existing
  `aegis.persistence.journal.kind` HOCON key.
  - **`MysqlEventJournal`** mirrors `PostgresEventJournal` against MySQL 8.x via the
    `mysql-connector-j` driver (already in `Dependencies.persistence`). Schema deltas vs.
    Postgres: `BIGSERIAL` → `BIGINT AUTO_INCREMENT`, `JSONB` → `JSON`, `TIMESTAMPTZ` → UTC
    ISO-8601 in `VARCHAR(40)` (MySQL `DATETIME` has no TZ; `TIMESTAMP` has a 2038 problem).
    Bootstrap catches `ERROR 1061 Duplicate key name` so the migration is idempotent without
    MySQL's missing `CREATE INDEX IF NOT EXISTS`.
  - **`SqliteEventJournal`** for embedded / single-node / CI use via `org.xerial:sqlite-jdbc`
    (newly added). Schema uses SQLite's affinity types (`INTEGER PRIMARY KEY AUTOINCREMENT`,
    `TEXT` for everything else). `poolSize` is forced to 1 because SQLite serialises writes
    internally — a larger pool just produces SQLITE_BUSY errors. JSON payloads round-trip as
    strings (no native JSON type pre-3.45).
  - **New HOCON blocks** `aegis.persistence.journal.mysql` and `aegis.persistence.journal.sqlite`
    with env-var overrides (`AEGIS_MYSQL_*`, `AEGIS_SQLITE_JDBC_URL`). `Server.journalResource`
    dispatches across `in-memory | postgres | mysql | sqlite`; the kind-unknown branch fails
    fast at boot with a clear error.
  - **Tests:** `MysqlEventJournalSpec` (3 cases, Testcontainers `mysql:8.4`, gated on Docker
    via the same `assume(dockerAvailable)` pattern as the Postgres spec). `SqliteEventJournalSpec`
    (4 cases) needs no Docker — uses per-test temp files. The fourth SQLite case asserts
    durability across connection churn (the property that makes SQLite usable for embedded
    deployments).

- **`RoleBasedPolicyEngine` wired in `Server.boot` (closes #77).** The role-based engine has shipped
  in `aegis-iam` since v0.1.0 with full tests, but `Server.boot` always instantiated
  `DevPolicyEngine` regardless of `aegis.auth.kind`. As a result, the "alice can sign but not revoke"
  human-RBAC story we sell as the wedge's safety net was a no-op for humans in production HMAC / OIDC
  mode — only the agent-scope recursion still fired.
  - **New `aegis.policy` HOCON block:** `kind = dev | role-based` (default `dev`), plus
    `role-based.role-bindings` (group → list of KMIP operation names) and
    `role-based.subject-bindings` (subject → list of operation names). Env-var overrides via
    `AEGIS_POLICY_KIND`.
  - **`Server.buildPolicyEngine`** parses the HOCON, validates every operation name against
    `Operation.values` (typos like `"Sgn"` fail fast at boot, not silently never-match), and rejects
    `kind=role-based` when both binding maps are empty — silent allow-all on misconfiguration would
    defeat the purpose of opting in.
  - **Per-builder warn logs** when either auth or policy is in dev mode replace the old
    unconditional "starting in DEV MODE" startup warning so the message reflects what's actually
    configured.
  - **Tests:** new `PolicyEngineResourceSpec` (7 cases) mirrors `RootOfTrustResourceSpec` — exercises
    each branch including the fail-fast paths and validates the bindings produce the expected
    Allow/Deny decisions.

- **Generic SIEM webhook audit sink — closes the last `priority/high` audit row for v0.2.0
  (closes #21, ROADMAP 2.0.i).** Pluggable HTTPS POST sink with HMAC signing, exponential backoff
  retry, and dead-letter to disk. Fan-out alongside the primary durable sink (Postgres or stdout) so
  operators get `postgres + webhook` simultaneously.
  - **`AuditRecordJson`** (in `aegis-audit`, library tier): canonical circe encoder for
    `AuditRecord`. Distinct from `aegis-http`'s `AuditRecordDto` (which is the REST audit-read
    endpoint's wire format and may evolve with the API) so downstream SIEM consumers pin to a stable
    schema.
  - **`FanOutAuditSink`** (in `aegis-audit`): composes one primary + N secondaries. **Asymmetric
    semantics by design** — primary failures propagate (durability contract); secondary failures are
    logged at WARN and swallowed (best-effort). `FanOutAuditSink.of` is a pass-through when the
    secondaries list is empty so the boot composition stays zero-cost on the default path.
  - **`WebhookAuditSink`** (in `aegis-server`): bounded async queue + background drain fiber. POSTs
    one record per request as JSON with `X-Aegis-Signature: sha256=<hex>` (GitHub-webhook
    convention). 2xx acks. 4xx → DLQ immediately (no retry — auth/malformed are not transient).
    5xx and transport errors retry up to `max-retries` with exponential backoff capped at
    `max-backoff`. Records exceeding the retry budget land in a JSONL dead-letter file (parent
    directory auto-created on first write). Reuses the boot `ActorSystem`'s pekko `Http` extension
    — no new connection pool.
  - **`Server.boot` fan-out wiring:** when `aegis.audit.webhook.enabled=true`, the primary sink is
    wrapped via `FanOutAuditSink.of(primary, List(webhook))` before being passed to the auto-
    responder and `HttpRoutes`. The audit-read `AuditQuery` lookup matches on `primarySink` (not
    the wrapped sink) so `GET /v1/audit` still works when fan-out is enabled.
  - **New `aegis.audit.webhook` HOCON block:** `enabled`, `url`, `secret`, `max-retries`,
    `initial-backoff-ms`, `max-backoff-ms`, `dead-letter-file`, `queue-capacity`, all overridable
    via `AEGIS_AUDIT_WEBHOOK_*`. Boot fails fast on empty URL or empty secret when enabled.
  - **Tests:** `FanOutAuditSinkSpec` (5 cases) covers the asymmetric failure semantics + identity
    collapse on empty secondaries. `WebhookAuditSinkSpec` (6 cases) is an integration suite that
    spins up a real pekko-http server on `127.0.0.1:0` per test and validates: 2xx ack, HMAC
    signature matches an independent recompute, 4xx → immediate DLQ, 5xx retries to DLQ, transport
    failure retries to DLQ, dead-letter file is well-formed JSONL.

- **Source-IP plumbed into audit records — activates `SourceIpBaseline` (closes #78).** The
  detector has been inert since v0.1.0 because `source.ip` never landed in
  `AuditRecord.context`. This change wires the HTTP transport's remote address through to
  every audit row produced by `AuditingKeyService`.
  - **`RequestContext` SPI** in `aegis-audit`: a tiny `IOLocal`-backed side-channel with
    `current: IO[Map[String, String]]` and `set(Map): IO[Unit]`. Two impls ship:
    `RequestContext.empty` (no-op, the default so existing callers compile unchanged) and
    `RequestContext.fromIOLocal(local)` (the real wire-up). Lives in `aegis-audit` so the
    library tier stays Pekko-free — only cats-effect is on the classpath.
  - **`AuditingKeyService`** gains an optional `requestContext` ctor param. The decorator
    calls `requestContext.current` inside `instrument` / `locate` and `preflightContext`
    merges the per-request bag last so a transport-supplied key (e.g. `source.ip`)
    wins over a same-key value from the scorer/engine.
  - **`Endpoints.scala`** introduces a server-only `extractFromRequest`-based
    `sourceIpInput`. It does NOT appear in the OpenAPI document (the wire shape is
    unchanged for clients), but every keys / agents / audit endpoint gains an internal
    `Option[String]` slot for the remote IP. The extractor reads from `req.underlying`
    cast to pekko's `RequestContext` because Tapir's pekko adapter hardcodes
    `ServerRequest.connectionInfo` to `(None, None, None)` — naive use of
    `connectionInfo.remote` would always yield `None`.
  - **`application.conf`** sets `pekko.http.server.remote-address-attribute = on` so
    pekko populates `AttributeKeys.remoteAddress` on every incoming request (the default
    is `off` for backwards compatibility).
  - **`HttpRoutes.runIO(clientIp)(io)`** sets the IOLocal as the first IO step of every
    request, before any user-facing work runs. Setting it inside the IO chain (rather than
    on the calling thread) is what makes the value visible to deeper IO consumers — every
    subsequent `flatMap` in the fiber inherits it, including the read inside
    `AuditingKeyService.preflightContext`.
  - **`Server.boot`** constructs one `IOLocal[Map[String,String]]` and hands the same
    `RequestContext.fromIOLocal(local)` to both `AuditingKeyService` and `HttpRoutes` —
    separate locals would leave the read empty. No new HOCON keys; the wiring is automatic
    when the server runs.
  - **Tests**: 4 new `AuditingKeyServiceSpec` cases covering the back-compat empty path,
    the source.ip stamp on a state-changing op, the source.ip stamp on the read-only
    `locate` path, and the three-way coexistence with `risk.score` + `outcome.decision`
    on the same record. Plus a new `HttpRoutesSourceIpSpec` integration suite (3 cases)
    that drives requests through the full `Route` and asserts the audit log carries
    `source.ip` end-to-end — covering criterion #4 of the issue.
  - **`BaselineDetector` doc cleanup.** Removed the three "inert until the HTTP plumbing
    PR populates this key" comments now that this PR is that plumbing.

- **CLI `agent issue` + `audit tail` subcommands (closes #79).** The two demo-critical CLI
  surfaces moved from stubs (`(planned — PR A1)` / `(planned — PR F2.b)`) to real
  implementations against the v0.2.0 backends.
  - **`aegis agent issue --label … --scopes Op,Op,… --ttl <seconds> [--parent <subject>]`** —
    POSTs to `/v1/agents/issue` and prints `agentId`, `jti`, `expiresAt`, and the bearer JWT
    on separate lines so a shell user can copy individual values or grep them out.
  - **`aegis audit tail [--since] [--until] [--actor] [--key] [--op] [--limit] [--offset]
    [--watch]`** — GETs `/v1/audit` with the supplied filters URL-encoded. Default mode
    prints one page; `--watch` polls every 2 s, advancing `--since` to the highest `at:`
    seen so far (basic `tail -f` UX without dragging cats-effect into the CLI's startup
    path).
  - **`IssueAgentRequestDto` / `IssueAgentResponseDto` / `AuditRecordDto` /
    `AuditQueryResponseDto`** mirrored into `aegis-cli/WireFormats.scala` (duplicated from
    `aegis-http` on purpose — `aegis-cli` does not depend on Tapir + pekko-http to keep its
    boot time low).
  - **`AegisHttpClient`** gains `issueAgent` and `queryAudit` methods with the same
    `Either[ClientError, A]` shape as the other endpoint wrappers, including the standard
    `PermissionDenied → exit 5` / `ItemNotFound → exit 4` mapping.
  - **Tests**: 11 new `CliSpec` cases covering required-flag errors, scope splitting/trimming,
    URL encoding of query params (e.g. `actor=alice%40org`), the empty-page footer, and the
    `--watch` boolean-flag parsing. Existing "agent/audit placeholder" assertions in
    `CommandsSpec` and `CliSpec` updated — `advisor scan` is now the only remaining stub.

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
