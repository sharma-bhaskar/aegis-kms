# Status

What's real today, what's WIP, what's not yet started — at the per-capability level. We keep
this page deliberately blunt because honesty about pre-alpha status is the only way to build
trust at this stage.

## Release status

**v0.1.1 — pre-alpha (last tagged release). v0.2.0 in progress on `main`.** The W2 risk scorer,
W2.b decision adapter, and W3 auto-responder all landed since v0.1.1 and are tested on `main`;
they ship with the next tag. Production-stable backends, KMIP, and MCP remain designed and
roadmapped, not shipped.

| Status | What it means |
|---|---|
| :material-check:{ .green } **Shipped** | Code is on `main`, tested, in v0.1.1 |
| :material-check-decagram:{ .amber } **MVP** | Functionally complete but lacks the polish / edge cases of a production-ready feature |
| :material-progress-clock:{ .amber } **WIP** | Active work in flight, target landing in the next 1-2 releases |
| :material-blueprint:{ .grey } **Designed** | Architecture is settled, no code yet |
| :material-lightbulb-outline:{ .grey } **Opportunity** | Identified gap, design pending |

## Per-capability snapshot

### Crypto operations

| Capability | Status | Detail |
|---|---|---|
| `create` / `get` / `activate` / `revoke` / `destroy` | :material-check: Shipped | Full lifecycle, REST + CLI |
| `sign` / `verify` | :material-check: Shipped | RSA-PSS-SHA-256, ECDSA-SHA-256 via AWS KMS |
| `encrypt` / `decrypt` with EncryptionContext AAD | :material-check: Shipped | AES-256, AWS KMS-backed |
| `wrap` / `unwrap` (KMIP-style envelope) | :material-check: Shipped | Symmetric KEK |
| `rotate(policy)` | :material-check: Shipped | Manual policy; auto-scheduler in v0.2.0 |
| `compromise(reason)` | :material-check: Shipped | One-way, severity=Critical audit |

### Identity & authorization

| Capability | Status | Detail |
|---|---|---|
| `Principal.Human` / `Principal.Agent` ADT | :material-check: Shipped | Sealed trait, total case analysis |
| Dev-mode `X-Aegis-User` header | :material-check: Shipped | Workstation only |
| JWT bearer auth (HS256) | :material-check: Shipped | Configurable secret |
| OIDC / JWKS verification | :material-progress-clock: WIP | v0.2.0 |
| Agent-token issuance endpoint | :material-blueprint: Designed | v0.2.0 |
| Policy engine (rules richer than allow/deny per principal) | :material-blueprint: Designed | v0.3.0 |

### Audit & observability

| Capability | Status | Detail |
|---|---|---|
| Append-only audit log | :material-check: Shipped | `AuditingKeyService` decorator |
| Audit fan-out to stdout | :material-check: Shipped | Default sink |
| Audit fan-out: Kafka / S3 / Webhook / Postgres | :material-blueprint: Designed | SPI in place, adapters in v0.2.0 |
| Agent-aware audit fields (`risk.score`, `risk.factors`, `outcome.decision`) | :material-check: Shipped | Stamped on every record by `AuditingKeyService`. `source.ip` plumbing through the HTTP layer is still pending. |
| Prometheus `/metrics` | :material-check: Shipped | Per-op counters, latency histograms, errors-by-code |
| OpenTelemetry tracing (auto-configured SDK) | :material-check: Shipped | `kms.<op>` spans with attributes |
| OpenAPI 3.1 spec + Swagger UI | :material-check: Shipped | At `/docs/` |

### Anomaly detection & response

| Capability | Status | Detail |
|---|---|---|
| `BaselineDetector` — 5 detectors | :material-check: Shipped | Scope, rate-spike, op-histogram, time-of-day, source-IP |
| `AgentRecommendation` events | :material-check: Shipped | Emitted on detection |
| Risk scorer (`RiskScorer` SPI + `BaselineRiskScorer`) | :material-check: Shipped | 5 baseline factors + 4 contextual factors → `RiskScore(value, factors)` |
| Decision adapter (`Allow` / `StepUp` / `Deny`) | :material-check: Shipped | `ThresholdDecisionEngine`, denyAt=0.85, stepUpAt=0.60, destructive-op offset 0.15 |
| Auto-responder (revoke / deactivate / freeze / alert) | :material-check: Shipped | Default rules: 5 detectors × High → Revoke + Medium → Alert. Per-(actor, action) 60 s cooldown. |
| LLM advisor | :material-blueprint: Designed | v0.4.0 (PR W4) |

### Persistence

| Capability | Status | Detail |
|---|---|---|
| In-memory event journal | :material-check: Shipped | Default for dev |
| Postgres event journal | :material-check: Shipped | Doobie + bootstrap migration |
| MySQL / SQLite | :material-blueprint: Designed | v0.3.0 |

### Crypto adapters (RootOfTrust)

| Capability | Status | Detail |
|---|---|---|
| AWS KMS | :material-check: Shipped | Full sign/verify/encrypt/decrypt/wrap/unwrap |
| GCP KMS | :material-blueprint: Designed | v0.2.0 |
| Azure Key Vault | :material-blueprint: Designed | v0.2.0 |
| HashiCorp Vault Transit | :material-blueprint: Designed | v0.2.0 |
| PKCS#11 / HSM | :material-blueprint: Designed | v0.4.0 |

### Wire planes

| Capability | Status | Detail |
|---|---|---|
| REST `/v1/keys/*` | :material-check: Shipped | Full surface, OpenAPI documented |
| KMIP server (TCP + TLS) | :material-blueprint: Designed | Skeleton in `aegis-kmip`; v0.2.0 lands the wire |
| MCP server (LLM tool surface) | :material-blueprint: Designed | Skeleton in `aegis-mcp-server`; v0.2.0 |
| Agent-AI plane | :material-check: Shipped | Detector + risk scorer + decision adapter + auto-responder all wired in `Server.boot` |

### Distribution & deployment

| Capability | Status | Detail |
|---|---|---|
| Docker image (GHCR) | :material-check: Shipped | `ghcr.io/sharma-bhaskar/aegis-server:0.1.1` |
| CLI universal tarball | :material-check: Shipped | Attached to GitHub Release |
| Library jars on Maven Central | :material-progress-clock: WIP | Workflow ready, blocked on Sonatype + GPG setup |
| Helm chart | :material-blueprint: Designed | v0.3.0 |
| docker-compose for self-host | :material-check: Shipped | `deploy/docker/docker-compose.yml` |

### Compliance & operational maturity

| Capability | Status | Detail |
|---|---|---|
| SOC 2 Type 1 | :material-progress-clock: WIP | Audit in progress |
| SOC 2 Type 2 | :material-blueprint: Designed | Targeted late 2026 |
| Penetration test report | :material-blueprint: Designed | Targeted before v1.0 |
| Production deployments | :material-lightbulb-outline: Opportunity | 0 today; design partners welcome |

## What this means for you

- **You're evaluating whether to deploy Aegis to production?** Don't, yet. Wait for v0.5+ at
  the earliest, ideally v1.0.
- **You're evaluating whether to be a design partner?** This is exactly the right time. The
  product can absorb feedback before the architecture calcifies.
- **You're contributing code?** The library tier is stable enough to build on; the server tier
  is where most of the v0.2.0 work happens.

See the [Developer Guide](../development/developer-guide.md) for setup, or jump to the
[Roadmap](roadmap.md) for what lands when.
