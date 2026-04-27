# PR backlog — file ↔ commit mapping

This document maps every file landed in this working tree to the PR it belongs to. The PR sequence is
**additive only** until the integration PR (I1): each PR adds new files, none modify existing ones.
Run `apply-pr-backlog.sh` from the repo root to commit each PR in order.

The apply script does not push — that is the user's responsibility (`git push` per PR, or open them as
GitHub PRs).

---

## PR D1 — Docs refresh (rebrand + positioning)

Pre-existing doc edits that predate the backend batch but were still uncommitted in the
working tree. Lands first so later branches don't conflict on `README.md`. No code
changes; no module touched.

**Modified files:**

- `README.md` — rebrand from "Aegis-KMS" to "Aegis", refreshed positioning copy
- `docs/POSITIONING.md` — same refresh, propagated into the positioning doc

---

## PR F1 — Pekko Typed `KeyOpsActor` + `EventJournal` SPI

The single actor that owns the live `Map[KeyId, ManagedKey]`, plus the journal SPI that drives state
recovery on boot. Replays the journal into the in-memory map deterministically.

**New files:**

- `modules/aegis-core/src/main/scala/dev/aegiskms/core/KeyEvent.scala`
- `modules/aegis-persistence/src/main/scala/dev/aegiskms/persistence/EventJournal.scala`
- `modules/aegis-server/src/main/scala/dev/aegiskms/app/KeyOpsActor.scala`
- `modules/aegis-server/src/main/scala/dev/aegiskms/app/ActorBackedKeyService.scala`
- `modules/aegis-server/src/test/scala/dev/aegiskms/app/KeyOpsActorSpec.scala`

---

## PR F2 — Audit sink + `AuditingKeyService` decorator

Decorator that writes one `AuditRecord` per `KeyService` call, including denied / failed ones. Two sinks
ship: `InMemoryAuditSink` for tests and `StdoutAuditSink` for the dev-mode demo.

**New files:**

- `modules/aegis-audit/src/main/scala/dev/aegiskms/audit/AuditingKeyService.scala`
- `modules/aegis-audit/src/main/scala/dev/aegiskms/audit/InMemoryAuditSink.scala`
- `modules/aegis-audit/src/main/scala/dev/aegiskms/audit/StdoutAuditSink.scala`
- `modules/aegis-audit/src/test/scala/dev/aegiskms/audit/AuditingKeyServiceSpec.scala`

---

## PR F3 — IAM allowlist policy engine + `AuthorizingKeyService`

Subject + role-binding allowlist with the recursive parent-check that blocks agent-scope escalation. Plus
the decorator that consults the engine before delegating.

**New files:**

- `modules/aegis-iam/src/main/scala/dev/aegiskms/iam/RoleBasedPolicyEngine.scala`
- `modules/aegis-iam/src/main/scala/dev/aegiskms/iam/AuthorizingKeyService.scala`
- `modules/aegis-iam/src/test/scala/dev/aegiskms/iam/RoleBasedPolicyEngineSpec.scala`
- `modules/aegis-iam/src/test/scala/dev/aegiskms/iam/AuthorizingKeyServiceSpec.scala`

---

## PR L1 — AWS KMS `RootOfTrust` adapter (layered mode)

`AwsKmsRootOfTrust` implements `RootOfTrust[IO]` over a tiny `AwsKmsPort` seam. The port has only the three
operations the adapter calls; testing subclasses the port, not the SDK client.

**New files:**

- `modules/aegis-crypto/src/main/scala/dev/aegiskms/crypto/aws/AwsKmsPort.scala`
- `modules/aegis-crypto/src/main/scala/dev/aegiskms/crypto/aws/AwsKmsRootOfTrust.scala`
- `modules/aegis-crypto/src/test/scala/dev/aegiskms/crypto/aws/AwsKmsRootOfTrustSpec.scala`

---

## PR W1 — Anomaly detector MVP — sliding-window baseline

`BaselineDetector` with two heuristics (`ScopeBaseline`, `RateSpike`), `AgentRecommendation` event type,
`RecommendationSink` SPI + in-memory impl, and a `TappedAuditSink` that fans audit records through the
detector.

**New files:**

- `modules/aegis-agent-ai/src/main/scala/dev/aegiskms/agent/AgentRecommendation.scala`
- `modules/aegis-agent-ai/src/main/scala/dev/aegiskms/agent/BaselineDetector.scala`
- `modules/aegis-agent-ai/src/main/scala/dev/aegiskms/agent/RecommendationSink.scala`
- `modules/aegis-agent-ai/src/main/scala/dev/aegiskms/agent/TappedAuditSink.scala`
- `modules/aegis-agent-ai/src/test/scala/dev/aegiskms/agent/BaselineDetectorSpec.scala`
- `modules/aegis-agent-ai/src/test/scala/dev/aegiskms/agent/TappedAuditSinkSpec.scala`

---

## PR C1 — CLI MVP

A self-contained CLI that talks to the Aegis REST surface over `java.net.http.HttpClient`. Commands:
`version`, `login`, `keys create/get/activate/destroy`. Placeholders for `agent issue`, `audit tail`,
`advisor scan` — backends ship in later PRs.

**New files:**

- `modules/aegis-cli/src/main/scala/dev/aegiskms/cli/HttpPort.scala`
- `modules/aegis-cli/src/main/scala/dev/aegiskms/cli/WireFormats.scala`
- `modules/aegis-cli/src/main/scala/dev/aegiskms/cli/AegisHttpClient.scala`
- `modules/aegis-cli/src/main/scala/dev/aegiskms/cli/Config.scala`
- `modules/aegis-cli/src/main/scala/dev/aegiskms/cli/Commands.scala`
- `modules/aegis-cli/src/test/scala/dev/aegiskms/cli/AegisHttpClientSpec.scala`
- `modules/aegis-cli/src/test/scala/dev/aegiskms/cli/CommandsSpec.scala`
- `modules/aegis-cli/src/test/scala/dev/aegiskms/cli/CliSpec.scala`
- `modules/aegis-cli/src/test/scala/dev/aegiskms/cli/ConfigSpec.scala`

**Modified files (rewritten from scaffold):**

- `modules/aegis-cli/src/main/scala/dev/aegiskms/cli/Cli.scala`

---

## PR I1 — Integration: actor + audit + IAM + W1 wired into `Server.scala`

The only PR that **modifies** existing files. Wires the full stack:

```
HttpRoutes
  → AuditingKeyService (TappedAuditSink → BaselineDetector + RecommendationSink + StdoutAuditSink)
    → AuthorizingKeyService (DevPolicyEngine)
      → ActorBackedKeyService
        → KeyOpsActor
          → EventJournal.inMemory
```

Adds a `DevPolicyEngine` (permissive Humans + recursive agent-parent checks) so the dev-mode bootstrap
works without OIDC. Adds an `IntegrationWiringSpec` that exercises the assembled stack end-to-end.

**New files:**

- `modules/aegis-server/src/main/scala/dev/aegiskms/app/DevPolicyEngine.scala`
- `modules/aegis-server/src/test/scala/dev/aegiskms/app/IntegrationWiringSpec.scala`

**Modified files:**

- `modules/aegis-server/src/main/scala/dev/aegiskms/app/Server.scala` — wiring rebuilt
- `modules/aegis-iam/src/main/scala/dev/aegiskms/iam/AuthorizingKeyService.scala` — comment fix only:
  the original docstring had the decorator order backwards (audit must be OUTSIDE auth so denies are
  audited).

---

## What's NOT in this batch

Backlog items deferred to later PRs:

- **F1.b** — Doobie/Postgres `EventJournal`
- **F2.b** — Postgres `AuditSink`
- **F2.c** — Kafka / SIEM webhook fan-out
- **F3.b** — OIDC + JWT auth replacing the dev-mode `X-Aegis-User` header
- **W1.b** — Admin endpoint that exposes the in-memory recommendation sink
- **W2** — Risk scorer (numeric scores feeding access decisions)
- **W3** — Auto-responder consuming `AgentRecommendation`s
- **W4** — LLM advisor over the audit log
- **L2 / L3 / L4** — GCP / Azure / Vault `RootOfTrust` adapters
- **A1+** — MCP server + agent-token issuance endpoint
- **K1–K5** — Full KMIP TTLV server
- **S1–S3** — SDK polish (Scala + Java) and CLI fit-and-finish
