# Aegis-KMS — Architecture

Aegis-KMS is a key management service designed for a world where humans, services, storage vendors, and AI agents all need to use the same keys safely. Four protocol planes (REST, KMIP, MCP, Agent-AI) terminate at a single audited core. The core is split into a library-safe tier (algebras, codecs, SDKs) that any JVM application can embed, and a server tier that adds wire protocols, persistence, and a pluggable root-of-trust.

This document describes the system the project is building toward. For current implementation state, see [§9 Status](#9-status).

## 1. Module layout

The build is split into two tiers. The split is enforced at build time: anything in the library-safe tier that imports Pekko fails to compile because Pekko isn't on its classpath. This guarantees `aegis-core` and the SDKs stay slim enough to embed in any JVM app.

```
                     ┌────────────────────────────────────────────────────────┐
                     │                     aegis-server                       │
                     │   (entry point, wires HTTP + KMIP + MCP + agent-ai)    │
                     └───────┬───────────┬───────────┬───────────┬────────────┘
                             │           │           │           │
                ┌────────────▼─┐  ┌──────▼─────┐  ┌──▼───────┐  ┌▼──────────┐
   server tier  │  aegis-http  │  │ aegis-kmip │  │ aegis-   │  │ aegis-    │
  (Pekko-aware) │  Tapir +     │  │ TTLV + TLS │  │ mcp-     │  │ agent-ai  │
                │  pekko-http  │  │            │  │ server   │  │           │
                └──────┬───────┘  └─────┬──────┘  └────┬─────┘  └─────┬─────┘
                       │                │              │              │
                       └────────┬───────┴──────────────┴──────────────┘
                                │
        ┌───────────────────────▼───────────────────────────────┐
        │               aegis-core  (algebras, model)           │
        │   KeyService[F[_]], ManagedKey, KmsError, Principal   │
        └───┬──────────────┬──────────────┬─────────────────────┘
            │              │              │
   ┌────────▼─────┐  ┌─────▼─────┐  ┌─────▼──────┐  ┌──────────┐  ┌──────────┐
   │ aegis-       │  │ aegis-    │  │ aegis-     │  │ aegis-   │  │ aegis-   │
   │ persistence  │  │ crypto    │  │ iam        │  │ audit    │  │ sdk-*    │
   │ Doobie / PG  │  │ Root of   │  │ OIDC, JWT, │  │ event    │  │ Scala +  │
   │              │  │  Trust    │  │ agent ID   │  │ log      │  │ Java     │
   └──────────────┘  └───────────┘  └────────────┘  └──────────┘  └──────────┘
            ────────────  library-safe tier (no Pekko)  ────────────
```

| Module | Tier | Purpose |
| --- | --- | --- |
| `aegis-core` | library | `KeyService[F[_]]` algebra, `ManagedKey`, `KmsError`, `Principal`. The contract every plane terminates at. |
| `aegis-persistence` | library | Doobie + Postgres event journal and read model. |
| `aegis-crypto` | library | Pluggable Root-of-Trust: AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault, PKCS#11, local file (dev). |
| `aegis-iam` | library | OIDC verifier, JWT signer, agent-identity issuer, policy evaluator. |
| `aegis-audit` | library | Append-only audit event sink, decoupled from the journal. |
| `aegis-sdk-scala` / `aegis-sdk-java` | library | Thin clients over the REST surface, no Pekko. |
| `aegis-http` | server | Tapir endpoint definitions + pekko-http interpreter, OpenAPI advertised. |
| `aegis-kmip` | server | KMIP 1.4 / 2.0 / 2.1 / 3.0 with version negotiation, TTLV codec, TLS server. |
| `aegis-mcp-server` | server | Model Context Protocol surface exposing KMS tools to LLM clients. |
| `aegis-agent-ai` | server | Lower-level agent-AI plane: function-call shape, richer KMS-specific affordances. |
| `aegis-server` | server | Boot wiring; sbt-native-packager produces a Docker image. |
| `aegis-cli` | tool | Operator CLI built on `aegis-sdk-scala`. |

Pekko alignment is enforced by `dependencyOverrides` in `build.sbt` so a transitive bump in any single artifact can't desynchronize the actor system at runtime.

## 2. Wire-protocol planes

All four planes terminate at the same `KeyService[F[_]]` algebra. They differ in framing, auth flow, and which subset of operations they expose.

| Plane | Framing | Auth | Audience |
| --- | --- | --- | --- |
| REST (`aegis-http`) | JSON over HTTP/1.1, OpenAPI advertised | OIDC bearer or agent-issued JWT | App developers, dashboards, CLI |
| KMIP (`aegis-kmip`) | TTLV over TLS 1.3, mTLS | Client certificate | Storage vendors, databases, backup |
| MCP (`aegis-mcp-server`) | JSON-RPC 2.0 over stdio or SSE | Agent JWT scoped to a session | LLM agents (Claude, GPT, etc.) |
| Agent-AI (`aegis-agent-ai`) | JSON over HTTP, function-call shape | Agent JWT | Custom tool-use frameworks |

Two AI surfaces is intentional. **MCP** is the standard contract Claude and other MCP-aware clients already speak, and exposing it means any MCP host can use Aegis-KMS without writing custom integration code. The **Agent-AI** plane serves agents that aren't MCP-native and benefits from richer KMS-specific affordances — envelope-encryption helpers, structured rationales, batch operations — that don't fit neatly into MCP's tool-call shape.

## 3. AI agents and MCP

AI agents are first-class citizens, not bolted on. Three properties make this work:

**Identity.** Every agent action carries a `Principal.Agent(sub, parentHuman, scopes)`. The `parentHuman` is the operator who issued the agent its credential, and that link is mandatory — every audit query "everything done on behalf of alice" trivially includes everything her agents did. There is no anonymous agent identity.

**Scoped credentials.** Agents are issued short-lived JWTs with explicit allowlists: which keys, which operations, which time window. An agent that should only sign with one key for the next hour gets a credential that does *exactly* that. The IAM module enforces this on every call before `KeyService` runs.

**Tool surface.** The MCP server publishes a curated set of tools — `create_key`, `sign`, `unwrap`, `rotate`, `list_keys` — each one annotated with the permissions it requires and the side effects it produces. An LLM client sees them in the same shape as any other MCP tool, and the host-side approval UI (e.g. Claude's tool-use confirmation) gives the human operator a chance to approve sensitive operations before they run.

The result: a Claude or GPT agent can use Aegis-KMS as if it were any other MCP-connected tool, while every action remains attributable, scope-limited, and audited.

## 4. Request lifecycle

Every request, regardless of plane, follows the same shape:

```
client ─► plane terminator ─► IAM (authn + authz) ─► KeyService ─► [persistence + root-of-trust]
                                                          │
                                                          └─► AuditEvent ─► audit sink
```

For a `POST /v1/keys` over REST, the concrete steps are:

1. `aegis-http` matches the route, generates a `request-id`, and parses the JSON body into a wire DTO.
2. The DTO is validated and translated to the core domain (`KeySpec`); a parse failure short-circuits to `400 InvalidField` and `KeyService` is never called.
3. IAM resolves the bearer token to a `Principal` and checks the `create_key` permission against policy.
4. `KeyService.create(spec, principal)` runs. The state-changing event is persisted to the journal first; the audit event is emitted after the persist commits, so the audit log can never describe a key the journal doesn't have.
5. If the audit sink is unavailable, the operation still commits and the actor records a `PendingAuditDelivery` event for a sweeper. The audit row is delivered late, never lost.
6. The new `ManagedKey` is mapped back to a wire DTO (`ManagedKeyDto`) and returned with `201 Created`.

KMIP, MCP, and Agent-AI flows differ only in steps 1, 2, and 6 — the framing layer. Steps 3–5 are identical for every plane.

## 5. Audit and logging

Aegis-KMS distinguishes **operational logs** (for engineers) from **audit events** (for compliance and forensics). They have different retention, different consumers, and different write paths.

```
                                                    ┌─ stdout (JSON, slf4j) ──► loki / cloudwatch / datadog
   any plane ──► HTTP / KMIP / MCP / Agent ──► logger ─┤
                            │                          └─ stderr (errors)
                            │
                            ▼
                       KeyService
                            │
                            │  on every state-changing event
                            ▼
                        audit sink
                            │
                            ├─► append-only Postgres table
                            ├─► fan-out to S3 / object store
                            └─► optional SIEM webhook
```

### What gets logged vs audited

| Event | Operational log | Audit event |
| --- | --- | --- |
| HTTP request received | yes (request id, method, path, status, ms) | no |
| `KeyService.create` succeeded | yes (info) | **yes** (`KeyCreated`) |
| `KeyService.activate` succeeded | yes (info) | **yes** (`KeyStateChanged`) |
| `KeyService.destroy` succeeded | yes (info) | **yes** (`KeyDestroyed`) |
| Validation error (bad JSON, unknown algorithm) | yes (warn) | no |
| Permission denied | yes (warn) | **yes** (`AccessDenied`) |
| Authentication failure | yes (warn) | **yes** (`AuthFailed`) |
| Internal error / unexpected exception | yes (error) | **yes** (`InternalError`) |
| Root-of-trust unwrap / wrap | yes (debug) | **yes** (`KeyMaterialAccessed`) |

### Audit event shape

```scala
final case class AuditEvent(
  eventId:    UUID,
  occurredAt: Instant,
  actor:      Principal,        // who did it (human or agent)
  action:     AuditAction,      // KeyCreated, KeyStateChanged, …
  resource:   ResourceRef,      // KeyId, PolicyId, …
  outcome:    Outcome,          // Success | Denied(reason) | Failed(reason)
  context:    Map[String, String] // request id, source ip, kmip cid, mcp session
)
```

### Correlation

Every inbound request gets a `request-id` allocated at the plane boundary. It propagates into:

- the structured log line (MDC),
- `AuditEvent.context["request_id"]`,
- the response header (`X-Request-Id` or KMIP `Unique Identifier`) so callers can quote it in support tickets.

A single `request-id` joins log lines, audit events, and the client-side trace into one timeline.

## 6. Security model

**No raw key material on the wire.** REST and KMIP both return key *handles* (`KeyId`); the actual material lives behind the Root of Trust (AWS KMS, Vault, PKCS#11, etc.). All cryptographic operations are server-side; clients never see plaintext key bytes.

**Principals are explicit.** `Principal.Human(sub, roles)` and `Principal.Agent(sub, parentHuman, scopes)` are separate cases — agent identities always carry a back-pointer to the human who issued them. Audit queries like "everything done on behalf of `alice`" are a single join, not a heuristic.

**Defense in depth at every plane.** REST and Agent-AI use OIDC-issued bearer tokens; KMIP uses mTLS; MCP uses session-scoped JWTs. All four converge on the same IAM policy check before `KeyService` runs.

**Library-safe tier has no I/O.** `aegis-core` is pure Scala — no Pekko, no JDBC, no HTTP. This makes property tests against `KeyService` cheap, keeps the SDKs slim, and lets embedders decide their own effect type.

## 7. Operational topology

```
                       ┌──────────────────────────────┐
                       │       Load Balancer (TLS)    │
                       └───────┬──────────────┬───────┘
                               │              │
                       ┌───────▼─────┐ ┌──────▼───────┐
                       │ aegis-server│ │ aegis-server │   N replicas, each runs:
                       │   pod 1     │ │   pod 2      │     • HTTP (8080)
                       └───────┬─────┘ └──────┬───────┘     • KMIP (5696, mTLS)
                               │              │              • MCP   (8443, optional)
                               └──────┬───────┘              • Agent-AI (8081, internal)
                                      │
                              ┌───────▼────────┐
                              │  Postgres HA   │  ─── event journal + audit log
                              └────────────────┘
                                      │
                              ┌───────▼────────┐
                              │  Root of Trust │  ─── never accessed except through aegis-crypto
                              └────────────────┘
```

The `ActorSystem` is local to each pod; cross-pod consistency is achieved through the journal — two pods racing on the same `KeyId` conflict at the persistence layer, not via cluster sharding. This is deliberate: a single-pod-first deployment lets KMIP, MCP, and the SDKs ride alongside without waiting on cluster-mode work, and most production deployments run a small fixed pool of pods rather than autoscaling the KMS itself.

## 8. Where to read next

- `modules/aegis-core/src/main/scala/dev/aegiskms/core/KeyService.scala` — the algebra everything wires through.
- `modules/aegis-http/src/main/scala/dev/aegiskms/http/HttpRoutes.scala` — Tapir → pekko-http wiring.
- `modules/aegis-http/src/test/scala/dev/aegiskms/http/HttpRoutesSpec.scala` — what "done" looks like for each capability's tests.
- [`architecture.html`](https://sharma-bhaskar.github.io/aegis-kms/architecture.html) — interactive walk-through of one REST request from edge to audit log.

## 9. Status

What's implemented today vs. what the design above describes. This is the only place in the document that talks about implementation phasing.

| Capability | Status |
| --- | --- |
| `aegis-core` algebra (`KeyService`, `ManagedKey`, `KmsError`, `Principal`) | ✅ Available |
| In-memory reference `KeyService` for tests and dev | ✅ Available |
| REST plane (`aegis-http`): create / get / activate / destroy with Tapir + pekko-http | ✅ Available |
| Server boot wiring (`aegis-server`), HTTP integration tests | ✅ Available |
| Persistent `KeyOpsActor` with event-sourced state | 🚧 In progress |
| Doobie + Postgres event journal & read model | 🚧 In progress |
| Pluggable Root of Trust (AWS KMS first, others via the same SPI) | 🔜 Designed |
| IAM: OIDC verification, JWT signing, agent-identity issuance | 🔜 Designed |
| KMIP plane: TTLV codec, schema, operations, TLS server, multi-version | 🔜 Designed |
| MCP server with curated KMS tool surface | 🔜 Designed |
| Agent-AI plane | 🔜 Designed |
| Scala / Java SDKs and operator CLI | 🔜 Designed |

The full system is the point. Anything not yet built is either in active development or has its module skeleton, dependency contract, and tier placement already locked into the build so it can land without disturbing the surrounding code.
