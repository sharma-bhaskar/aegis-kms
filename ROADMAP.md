# Aegis-KMS Roadmap

This document is the **single source of truth for what Aegis-KMS is building toward** and which release each capability lands in. The README sells the design; this file tracks the execution.

If you want to follow along or contribute, the live work happens in [GitHub Issues](https://github.com/sharma-bhaskar/aegis-kms/issues), grouped by [Milestones](https://github.com/sharma-bhaskar/aegis-kms/milestones) and visualized on the [Project board](https://github.com/sharma-bhaskar/aegis-kms/projects). Each row in the tables below corresponds to one or more issues with `area/*` and `kind/*` labels.

**Status legend:**

- ✅ Shipped — works in the latest release.
- ⚠️ MVP — partially shipped; functional but minimal.
- 🚧 WIP — being worked on now.
- 🔜 Designed — SPI/skeleton in place, implementation queued.
- 💡 Opportunity — not yet in design; on the table for community input.

---

## Vision

Aegis exists to make AI-agent access to keys safe by default. The wedge is **four checks on every request**, regardless of which wire it came in on:

1. **Identity & Context** — who is this, on whose behalf, in what scope?
2. **Risk Scoring** — does this request match the actor's behavioral baseline?
3. **Anomaly Detection** — is this part of a pattern we should escalate?
4. **Real-time Response** — allow / step-up / deny / rotate / revoke / alert, automatically, before the next request lands.

Every release moves the substrate closer to that loop closing inside Aegis without a human in the path for the cases that don't need one.

See [POSITIONING.md](docs/POSITIONING.md) for the full framing and [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the system design. This roadmap is the *delivery plan* that turns those documents into shipped capability.

---

## Release milestones

The trade-off in each release is roughly **balanced** across three axes — *make it a real KMS* (cryptographic operations + lifecycle), *ship the wedge* (the four pillars that differentiate Aegis), and *build the platform* (integrations, observability, deployment). Each release moves the needle on all three.

### v0.1.0 — Substrate ✅ *shipped*

The foundation that everything else lands on.

| Real KMS | Wedge | Platform |
|---|---|---|
| `KeyService` algebra (create/get/locate/activate/revoke/destroy) | `Principal.Human` / `Principal.Agent` with parent linkage | Postgres event journal (Doobie/HikariCP) |
| In-memory + Pekko-actor backed lifecycle state | `BaselineDetector` MVP (scope + rate-spike) | AWS KMS root-of-trust adapter |
| REST endpoints `/v1/keys/*` | `RoleBasedPolicyEngine` (allowlist + recursive parent-check) | JWT bearer auth (HS256 issue + verify) |
| `aegis` admin CLI (version/login/keys CRUD) | `AuditingKeyService` decorator + stdout sink | Docker image (GHCR) + library jars |

Non-goals: cryptographic operations, multi-cloud RoT, KMIP, MCP, OIDC. All deferred to later milestones.

---

### v0.1.1 — Make it a real KMS

**Theme:** turn Aegis from a *key registration* service into a *key management* service. Every claim about layered-mode AWS KMS in the README should run end-to-end after this release.

| # | Capability | Area | Status |
|---|---|---|---|
| 1.1.a | `sign(id, message, alg)` in `KeyService` algebra + REST + AWS adapter | Real KMS | 🚧 |
| 1.1.b | `verify(id, message, signature, alg)` | Real KMS | 🚧 |
| 1.1.c | `encrypt(id, plaintext, ctx)` / `decrypt(id, ciphertext, ctx)` | Real KMS | 🚧 |
| 1.1.d | `wrap(id, dek)` / `unwrap(id, wrappedDek)` | Real KMS | 🚧 |
| 1.1.e | `rotate(id, policy)` — new active version, old → Deactivated | Real KMS | 🚧 |
| 1.1.f | `compromise(id, reason)` operator override | Real KMS | 🚧 |
| 1.1.g | Prometheus metrics endpoint (`/metrics`) — request rate, latency, error rate, audit lag, journal append latency | Platform | 🚧 |
| 1.1.h | OpenTelemetry tracing (auto-instrument REST + JDBC + AWS SDK) | Platform | 🚧 |
| 1.1.i | `Resource[IO, Unit]` boot scope — clean Postgres pool / actor system shutdown | Platform | 🚧 |
| 1.1.j | Anomaly detector: time-of-day baseline, source-IP set, op-type histogram | Wedge | 🚧 |
| 1.1.k | Maven Central publish (Sonatype OSSRH + GPG + workflow secrets) | Platform | 🚧 |

**Demo target:** "Boot Aegis against an existing AWS KMS CMK, sign a payload, see the audit record, watch metrics in Grafana."

---

### v0.2.0 — Ship the wedge

**Theme:** the first release where the README's "Claude goes rogue" example actually runs end-to-end. Anomaly + risk + auto-response close the loop.

| # | Capability | Area | Status |
|---|---|---|---|
| 2.0.a | Risk scorer (W2) — multi-factor numeric score; reasoning recorded in audit context | Wedge | 🔜 |
| 2.0.b | Decision adapter (`allow` / `step-up` / `deny`) wired into IAM | Wedge | 🔜 |
| 2.0.c | Auto-responder (W3) — configurable rules from `AgentRecommendation` → action (revoke / deactivate / freeze / alert) | Wedge | 🔜 |
| 2.0.d | Agent-token issuance HTTP endpoint (`POST /v1/agents/issue`) | Wedge | 🔜 |
| 2.0.e | `aegis agent issue` CLI — wire the existing stub to the new endpoint | Wedge | 🔜 |
| 2.0.f | Postgres audit table (queryable, indexed on actor + occurredAt + key) | Platform | 🔜 |
| 2.0.g | `GET /v1/audit?since=&actor=&key=&op=` audit-read API | Platform | 🔜 |
| 2.0.h | `aegis audit tail` CLI — wire the existing stub to the new audit-read API | Wedge | 🔜 |
| 2.0.i | Generic SIEM webhook audit sink (HTTPS POST per event, batched + retried) | Platform | 🔜 |
| 2.0.j | Kafka audit fan-out (Pekko-Connectors-Kafka) | Platform | 🔜 |
| 2.0.k | Redis-backed JWT revocation list (jti blacklist) — required for instant agent revoke | Platform | 🔜 |
| 2.0.l | Honey keys / canary keys — fake keys with auto-alert if any agent touches them | Wedge | 💡 |
| 2.0.m | OIDC verifier + JWKS rotation + RS256 / ES256 signature support | Wedge | 🔜 |
| 2.0.n | OPA (Open Policy Agent) integration — externalize policy evaluation (Rego) via sidecar | Wedge | 💡 |

**Demo target:** "Issue an agent token, watch it sign 49 invoices fine, watch it try one off-scope key, watch the auto-revoke fire before the next attempt — all in `aegis audit tail`."

---

### v0.2.1 — LLM advisor

**Theme:** read-only AI assistant that explains the audit log to operators.

| # | Capability | Area | Status |
|---|---|---|---|
| 2.1.a | `aegis advisor scan` — finds unused keys, scope-creep, anomalies; bounded prompt set | Wedge | 🔜 |
| 2.1.b | `aegis advisor explain <agent-id>` — human-readable timeline of why a recommendation fired | Wedge | 🔜 |
| 2.1.c | Pluggable LLM provider (OpenAI / Anthropic / Bedrock / Ollama for local) | Wedge | 💡 |
| 2.1.d | Prompt safety: never executes mutations; structured output schemas; refuses arbitrary queries | Wedge | 🔜 |

**Demo target:** "`aegis advisor scan` returns 'these 3 keys haven't been used in 60 days, these 2 agents have unusually broad scopes, there are no active anomalies.'"

---

### v0.3.0 — Multi-cloud + production deployment

**Theme:** make Aegis credible for the "we run multiple clouds and a few HSMs" enterprise.

| # | Capability | Area | Status |
|---|---|---|---|
| 3.0.a | GCP KMS root-of-trust adapter (`google-cloud-kms`) | Real KMS | 🔜 |
| 3.0.b | Azure Key Vault root-of-trust adapter (`azure-security-keyvault-keys`) | Real KMS | 🔜 |
| 3.0.c | HashiCorp Vault Transit root-of-trust adapter | Real KMS | 🔜 |
| 3.0.d | Software root-of-trust (JCE-backed; dev/test only) | Real KMS | 🔜 |
| 3.0.e | Per-key RoT routing — different keys can live in different backends | Real KMS | 💡 |
| 3.0.f | Helm chart (`deploy/helm/aegis-kms`) — production-ready with Postgres dependency | Platform | 🔜 |
| 3.0.g | Kubernetes operator (CRDs for `AegisKey`, `AegisAgent`) | Platform | 💡 |
| 3.0.h | OpenTelemetry log export (Loki / Datadog / Honeycomb) | Platform | 💡 |
| 3.0.i | Multi-tenancy: per-tenant key/agent/audit isolation | Platform | 💡 |
| 3.0.j | Time-windowed access policies (e.g. business-hours-only keys) | Wedge | 🔜 |
| 3.0.k | Just-In-Time (JIT) access — agent requests scoped permission on-demand | Wedge | 💡 |
| 3.0.l | Approval workflows — Slack / PagerDuty / OpsGenie integration for step-up | Wedge | 💡 |

**Demo target:** "Helm-install Aegis on a fresh cluster, register an existing AWS CMK, register a GCP CryptoKey, watch a single audit feed cover both backends."

---

### v0.4.0 — KMIP + MCP

**Theme:** open the wires that bring storage vendors and AI hosts to the same control plane.

| # | Capability | Area | Status |
|---|---|---|---|
| 4.0.a | KMIP TTLV codec (1.4 / 2.0 / 2.1 / 3.0 with version negotiation) | Real KMS | 🔜 |
| 4.0.b | KMIP TLS 1.3 server with mTLS | Real KMS | 🔜 |
| 4.0.c | KMIP operations: `Create`, `Get`, `Activate`, `Destroy`, `Register` (BYOK), `Encrypt`, `Decrypt`, `Sign`, `SignatureVerify` | Real KMS | 🔜 |
| 4.0.d | Tested integrations: NetApp ONTAP, Veeam, Oracle TDE | Real KMS | 💡 |
| 4.0.e | MCP server (`aegis-mcp-server`) with curated tool surface | Wedge | 🔜 |
| 4.0.f | MCP tool annotations + host-side approval flow | Wedge | 🔜 |
| 4.0.g | Per-prompt accountability — record originating LLM prompt with each MCP-driven key op | Wedge | 💡 |
| 4.0.h | Model identifier in audit (`actor.model = "claude-3.5-sonnet"`) | Wedge | 💡 |
| 4.0.i | LangChain / LlamaIndex tool integration package | Wedge | 💡 |
| 4.0.j | OpenAI function-calling surface (`aegis-agent-ai`) for non-MCP frameworks | Wedge | 🔜 |

**Demo target:** "An NetApp filer, a Claude agent, and a Java application all use the same Aegis instance, with one audit trail, one identity model, one policy engine."

---

### v0.5.0 — HSM-backed + Standalone hardening

**Theme:** the FIPS / regulated-industry release.

| # | Capability | Area | Status |
|---|---|---|---|
| 5.0.a | PKCS#11 root-of-trust adapter (Thales Luna, Entrust nShield, YubiHSM, AWS CloudHSM, SoftHSM for dev) | Real KMS | 🔜 |
| 5.0.b | SoftHSM Testcontainer for CI integration testing | Real KMS | 🔜 |
| 5.0.c | Hardware attestation docs (FIPS 140-2 Level 3 attestation chain) | Platform | 💡 |
| 5.0.d | Standalone-mode hardening: AEAD wrapping, key-derivation hierarchy | Real KMS | 🔜 |
| 5.0.e | Master-key rotation tooling | Real KMS | 💡 |
| 5.0.f | Audit log immutability proofs (Merkle hash chain or signed batches) | Wedge | 💡 |

**Demo target:** "Boot Aegis against a SoftHSM container, generate a key inside the HSM, prove the bytes never leave the device — all in CI."

---

### v0.6.0 — Compliance + multi-tenancy

**Theme:** the SaaS-readiness release.

| # | Capability | Area | Status |
|---|---|---|---|
| 6.0.a | Multi-tenant Aegis: tenants / projects / per-tenant isolation across keys, agents, audit, policies | Platform | 💡 |
| 6.0.b | Compliance reports: "list every key any AI agent touched in Q2" exportable as CSV / PDF | Wedge | 💡 |
| 6.0.c | NIST AI RMF / EU AI Act mapping doc — how Aegis features map to compliance requirements | Wedge | 💡 |
| 6.0.d | GDPR / data-residency labels on keys + region-based deny rules | Platform | 💡 |
| 6.0.e | Audit log retention policies + cold-storage tiering (S3 → Glacier) | Platform | 💡 |
| 6.0.f | SOC2-friendly access logs (separate from operational logs) | Platform | 💡 |

---

### v1.0.0 — API stability + production-hardened

**Theme:** the "we promise the algebra won't change under you" release.

| # | Capability | Area | Status |
|---|---|---|---|
| 1.0.a | All `KeyService` operations have full coverage on every shipped RoT | Real KMS | 💡 |
| 1.0.b | Backward-compatibility guarantees documented for the algebra + REST surface | Platform | 💡 |
| 1.0.c | Performance targets: 1000 sign ops/sec at p99 < 50ms (with AWS KMS RoT, single pod) | Platform | 💡 |
| 1.0.d | Chaos/fault testing: journal partition tolerance, RoT outage handling, audit sink backpressure | Platform | 💡 |
| 1.0.e | Production deployment docs: HA topology, capacity planning, runbook | Platform | 💡 |

---

## Cross-cutting capability tracks

The release tables above slice the work by milestone. The tables below slice by capability *area* — useful when you're contributing in a specific domain.

### Database support

| Database | Status | Use-case | Tracking |
|---|---|---|---|
| Postgres 14+ | ✅ v0.1.0 | event journal, audit table | — |
| CockroachDB | ✅ works as Postgres | drop-in HA replacement | document only |
| MySQL 8+ | ⚠️ driver in deps; adapter not wired | event journal | v0.2.0 nice-to-have |
| MariaDB | ⚠️ same as MySQL | event journal | v0.2.0 nice-to-have |
| SQLite | 💡 opportunity | embedded dev / CI / single-node demo | v0.2.0 nice-to-have |
| DynamoDB | 💡 opportunity | AWS-native event store | v0.3.0+ |
| MongoDB | 💡 not pursued | document journal model | unlikely — Postgres covers the use |

### Audit / event fan-out (downstream sinks)

| Sink | Status | Tracking |
|---|---|---|
| Stdout JSON | ✅ v0.1.0 | — |
| Postgres audit table | 🔜 v0.2.0 | issue-tagged `area/audit` |
| Generic SIEM webhook | 🔜 v0.2.0 | issue-tagged `area/audit` |
| Kafka | 🔜 v0.2.0 | issue-tagged `area/audit area/integration/kafka` |
| NATS / NATS JetStream | 💡 v0.2.0+ | issue-tagged `area/audit area/integration/nats` |
| AWS SQS / SNS | 💡 v0.3.0 | issue-tagged `area/audit area/integration/aws` |
| GCP Pub/Sub | 💡 v0.3.0 | issue-tagged `area/audit area/integration/gcp` |
| Azure Event Hubs / Service Bus | 💡 v0.3.0 | issue-tagged `area/audit area/integration/azure` |
| Splunk HEC | 💡 v0.3.0 | issue-tagged `area/audit area/integration/splunk` |
| OpenTelemetry log export | 💡 v0.3.0 | issue-tagged `area/observability` |
| S3 object-store fan-out | 🔜 v0.3.0 | issue-tagged `area/audit` |
| WebSocket live audit feed | 💡 v0.4.0 | issue-tagged `area/audit kind/feature` |

### Root of Trust adapters (key bytes)

| Backend | Status | Tracking |
|---|---|---|
| AWS KMS | ✅ v0.1.0 | — |
| GCP KMS | 🔜 v0.3.0 | issue-tagged `area/integration/gcp area/crypto` |
| Azure Key Vault | 🔜 v0.3.0 | issue-tagged `area/integration/azure area/crypto` |
| HashiCorp Vault Transit | 🔜 v0.3.0 | issue-tagged `area/integration/vault area/crypto` |
| Software RoT (JCE) | 🔜 v0.3.0 | issue-tagged `area/crypto` |
| PKCS#11 (Luna / nShield / YubiHSM / CloudHSM / SoftHSM) | 🔜 v0.5.0 | issue-tagged `area/crypto kind/security` |

### Wire planes

| Plane | Status | Tracking |
|---|---|---|
| REST (`aegis-http`) | ✅ v0.1.0 (basic) | extend in 0.1.1 with crypto ops |
| OpenAPI advertising + Swagger UI | ⚠️ deps wired; route exposure pending | v0.1.1 |
| KMIP (`aegis-kmip`) — TTLV / TLS / multi-version | 🔜 v0.4.0 | issue-tagged `area/wire/kmip` |
| MCP (`aegis-mcp-server`) | 🔜 v0.4.0 | issue-tagged `area/wire/mcp area/ai-governance` |
| Agent-AI (`aegis-agent-ai`) — function-call surface | 🔜 v0.4.0 | issue-tagged `area/wire/agent-ai` |

### Policy management

| Capability | Status | Tracking |
|---|---|---|
| Role/scope allowlist + parent-check | ✅ v0.1.0 | — |
| Risk-scored decisions (allow / step-up / deny) | 🔜 v0.2.0 | `area/policy area/risk` |
| Time-windowed access (key X usable Mon-Fri 9-18 UTC) | 🔜 v0.3.0 | `area/policy` |
| Just-In-Time (JIT) access | 💡 v0.3.0+ | `area/policy area/ai-governance` |
| Approval workflows (Slack / PagerDuty / OpsGenie) | 💡 v0.3.0+ | `area/policy area/integration/*` |
| OPA (Rego) externalized policy | 💡 v0.2.0+ | `area/policy area/integration/opa` |
| AWS Cedar policy language | 💡 v0.4.0+ | `area/policy area/integration/aws` |
| Policy-as-code with Git (hot-reload on commit) | 💡 v0.4.0+ | `area/policy` |
| Policy simulation / preview (dry-run on past 24h) | 💡 v0.4.0+ | `area/policy kind/feature` |
| Policy explainer (denied requests return the firing rule) | 💡 v0.2.0 | `area/policy kind/feature` |
| Policy versioning & rollback | 💡 v0.4.0+ | `area/policy` |
| Tenant isolation in policy evaluation | 🔜 v0.6.0 | `area/policy area/multi-tenancy` |

### AI governance (beyond the four pillars)

| Capability | Status | Tracking |
|---|---|---|
| Agent registry (list all live agents, parents, scopes, last activity) | 🔜 v0.2.0 | `area/ai-governance` |
| Agent kill-switch ("revoke all agents under alice@org issued in 24h") | 🔜 v0.2.0 | `area/ai-governance area/auto-response` |
| Per-prompt accountability (record originating LLM prompt) | 💡 v0.4.0 | `area/ai-governance area/wire/mcp` |
| Model identifier in audit (`actor.model = "..."`) | 💡 v0.4.0 | `area/ai-governance area/audit` |
| Token cost / op-rate tracking per agent | 💡 v0.4.0+ | `area/ai-governance` |
| Honey keys / canary keys with auto-alert | 💡 v0.2.0 | `area/ai-governance kind/security` |
| Scope-creep detection (effective scope vs. baseline) | 💡 v0.3.0 | `area/ai-governance area/risk` |
| Compliance reports (SOC2 / PCI / HIPAA exportable) | 💡 v0.6.0 | `area/ai-governance area/compliance` |
| LLM advisor with RAG over audit log | 🔜 v0.2.1 | `area/ai-governance area/wedge/llm-advisor` |
| Bring-your-own-LLM provider for advisor | 💡 v0.2.1+ | `area/ai-governance` |
| NIST AI RMF / EU AI Act compliance mapping | 💡 v0.6.0 | `area/ai-governance area/compliance kind/docs` |

### Observability + ops

| Capability | Status | Tracking |
|---|---|---|
| Stdout JSON logs | ✅ v0.1.0 | — |
| Prometheus metrics (`/metrics`) | 🔜 v0.1.1 | `area/observability` |
| OpenTelemetry tracing (REST + JDBC + AWS SDK) | 🔜 v0.1.1 | `area/observability` |
| OpenTelemetry log export | 💡 v0.3.0 | `area/observability` |
| `request-id` MDC propagation (logs ↔ audit ↔ response header) | 🚧 v0.1.1 | `area/observability` |
| `Resource[IO, Unit]` boot scope (graceful shutdown) | 🔜 v0.1.1 | `area/server-tier` |
| Helm chart | 🔜 v0.3.0 | `area/deployment` |
| Kubernetes operator (CRDs) | 💡 v0.3.0+ | `area/deployment kind/feature` |
| Docker Compose hardening (no default passwords) | 🔜 v0.1.1 | `area/deployment kind/security` |

### Authentication + identity

| Capability | Status | Tracking |
|---|---|---|
| HMAC JWT (HS256) issue + verify | ✅ v0.1.0 | — |
| Dev-mode `X-Aegis-User` header | ✅ v0.1.0 | — |
| OIDC discovery + JWKS rotation | 🔜 v0.2.0 | `area/iam` |
| RS256 / ES256 / EdDSA verifier | 🔜 v0.2.0 | `area/iam` |
| OIDC providers tested: Keycloak, Authentik, Dex, Auth0, Okta | 💡 v0.3.0 | `area/iam area/integration/oidc` |
| Agent-token issuance HTTP endpoint | 🔜 v0.2.0 | `area/iam area/wedge` |
| Redis-backed JWT revocation list (jti blacklist) | 🔜 v0.2.0 | `area/iam area/integration/redis` |
| mTLS for KMIP plane | 🔜 v0.4.0 | `area/iam area/wire/kmip` |
| Hardware-bound credentials (WebAuthn for human auth) | 💡 v0.4.0+ | `area/iam kind/security` |

### SDK + client surface

| SDK | Status | Tracking |
|---|---|---|
| Scala SDK (`aegis-sdk-scala`) — full REST coverage | ⚠️ skeleton | v0.2.0 |
| Java SDK (`aegis-sdk-java`) — full REST coverage | ⚠️ skeleton | v0.2.0 |
| Kotlin coroutines wrapper | 💡 | community welcome |
| TypeScript / Node SDK | 💡 | community welcome |
| Python SDK | 💡 | community welcome |
| Go SDK | 💡 | community welcome |
| Rust SDK | 💡 | community welcome |
| `langchain-aegis` Python package | 💡 v0.4.0 | `area/sdk area/ai-governance` |

---

## Contributing

If you want to pick up something from this roadmap:

1. **Find the capability** in the tables above.
2. **Look at the corresponding GitHub issue** (every actionable row has one — search the [issues page](https://github.com/sharma-bhaskar/aegis-kms/issues) by the area label, e.g. `area/integration/nats`).
3. **Comment on the issue** to claim it, ask design questions, or propose a different approach.
4. **Open a PR** that closes the issue with `Closes #N`.

Items marked **💡 Opportunity** don't have detailed designs yet — they're the best candidates for proposing your own approach. Items marked **🔜 Designed** have an SPI or skeleton in place; the work is mostly mechanical implementation.

Most issues will be tagged `good first issue` once their parent area has its first contributor; if you're new to the codebase, the [`good first issue` filter](https://github.com/sharma-bhaskar/aegis-kms/labels/good%20first%20issue) is the place to start.

---

## How this roadmap is maintained

- This file is **edited as part of the same PR that ships a feature**. When v0.1.1 ships, the v0.1.1 table moves from "next" to "shipped" and v0.1.2's table appears. The status legend in the cross-cutting tables is updated in lockstep.
- Major changes in scope (a new milestone, a major capability moving between releases) get their own PR with discussion in the description.
- Anything marked **💡 Opportunity** can move to **🔜 Designed** when somebody writes the design doc — typically a `docs/proposals/<topic>.md` PR — and gets sign-off.

The goal of this file is to be **honest about the gap between what we ship and what we plan to ship**, to help users decide whether Aegis is right for their use today, and to give contributors a clear picture of where the project is heading.

[Open an issue](https://github.com/sharma-bhaskar/aegis-kms/issues/new) if anything here looks wrong or out of date.
