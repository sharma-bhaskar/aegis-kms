# Aegis-KMS — Architecture

> Status: **PR #1 (HTTP vertical slice) merged.** This document describes the target architecture; sections marked **(planned)** are not yet implemented but the module skeletons exist and the boundaries are already enforced by the build.

Aegis-KMS is a Scala 3 / Pekko Typed key management service with four wire-protocol planes — REST, KMIP TTLV, MCP (for AI agents), and a low-level agent-AI plane — sharing a single audited key-operations core. It is a clean-room successor to the legacy uKM project and is laid out so that the library-safe tier (algebras, codecs, SDKs) can be consumed without dragging in Pekko.

## 1. Module layout

The build is split into two tiers. The split is enforced at build time: anything in the library-safe tier that accidentally pulls in Pekko will fail to compile because Pekko isn't on its classpath.

```
                     ┌────────────────────────────────────────────────────────┐
                     │                     aegis-server                       │
                     │   (entry point, wires HTTP + KMIP + MCP + agent-ai)    │
                     └───────┬───────────┬───────────┬───────────┬────────────┘
                             │           │           │           │
                ┌────────────▼─┐  ┌──────▼─────┐  ┌──▼───────┐  ┌▼──────────┐
   server tier  │  aegis-http  │  │ aegis-kmip │  │ aegis-   │  │ aegis-    │
  (Pekko-aware) │  (Tapir +    │  │ (TTLV +    │  │ mcp-     │  │ agent-ai  │
                │   pekko-http)│  │  TLS)      │  │ server   │  │           │
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
   │ (Doobie/PG)  │  │ (AWS KMS, │  │ (OIDC,JWT) │  │ (event   │  │ (Scala + │
   │              │  │  jjwt)    │  │            │  │  log)    │  │   Java)  │
   └──────────────┘  └───────────┘  └────────────┘  └──────────┘  └──────────┘
            ────────────  library-safe tier (no Pekko)  ────────────
```

| Module | Tier | Today | Target |
| --- | --- | --- | --- |
| `aegis-core` | library | `KeyService[F[_]]`, `ManagedKey`, `KmsError`, `Principal`, in-memory ref impl | Stable algebra, no behaviour change |
| `aegis-persistence` | library | empty | Doobie + Postgres event journal & read model (PR #3) |
| `aegis-crypto` | library | empty | AWS KMS RoT + local-file RoT, JWT signer (PR #4) |
| `aegis-iam` | library | empty | OIDC verifier, agent-identity issuer (PR #5) |
| `aegis-audit` | library | empty | Append-only audit event sink |
| `aegis-sdk-scala` / `aegis-sdk-java` | library | empty | Thin clients for the REST surface |
| `aegis-http` | server | Tapir endpoints + pekko-http interpreter, 7 route tests | + auth, + rate limits |
| `aegis-kmip` | server | empty | KMIP 1.4 / 2.0 / 2.1 / 3.0 with version negotiation (PR-K1…K5) |
| `aegis-mcp-server` | server | empty | Model Context Protocol server exposing KMS tools to LLMs |
| `aegis-agent-ai` | server | empty | Lower-level agent-AI plane (function-call style) |
| `aegis-server` | server | Boot wiring + smoke spec | sbt-native-packager Docker image |
| `aegis-cli` | tool | empty | Operator CLI built on `aegis-sdk-scala` |

Pekko alignment is enforced via `ThisBuild / dependencyOverrides` in `build.sbt` so a transitive bump in any single artifact can't desynchronize the actor system at runtime.

## 2. Request lifecycle (REST plane, today)

```
 client                pekko-http              Tapir server                 KeyService          in-memory
                                              endpoint                       [IO]                store
   │                       │                       │                           │                   │
   │── POST /v1/keys ─────►│                       │                           │                   │
   │   {spec…}             │── route match ───────►│                           │                   │
   │                       │                       │── decode CreateKeyRequest │                   │
   │                       │                       │   .toCore : KeySpec       │                   │
   │                       │                       │── principalOf(X-Aegis-User) ─┐                │
   │                       │                       │                           │  │                │
   │                       │                       │── svc.create(spec, princ) ────►│              │
   │                       │                       │                           │  │── put ─────────►│
   │                       │                       │                           │◄─┤                │
   │                       │                       │◄── Right(ManagedKey) ──────  │                │
   │                       │                       │                           │  │                │
   │                       │                       │── ManagedKeyDto.fromCore ──                   │
   │                       │◄── 201 + JSON ────────│                                                │
   │◄── 201 + JSON ────────│                                                                       │
                                                          (audit emission planned — see §4)
```

Key points:

- **Wire DTOs are decoupled from core** (`JsonCodecs.scala`). The REST contract can evolve without touching `aegis-core`. Every DTO has explicit `fromCore` / `toCore` so the boundary is testable.
- **Errors are mapped, not leaked.** `KmsError` (a closed ADT in `aegis-core`) maps to HTTP status codes inside `HttpRoutes.errorOut`. `ItemNotFound → 404`, `PermissionDenied → 403`, `AuthenticationNotSuccessful → 401`, validation → 400, default → 500.
- **Effects.** `KeyService[IO]` runs on the Cats Effect runtime. Tapir's pekko-http interpreter wants `Future`, so server logic does `io.unsafeToFuture()` at the boundary. The actor tier (PR #2) will route commands through `EventSourcedBehavior` and the IO adapter will `ask` the actor.

Once PR #2 lands, the third column above splits into:

```
KeyService[IO] ── ask ──► KeyOpsActor (EventSourcedBehavior)
                              │
                              ├─ command handler  (decides Reply or Persist)
                              ├─ event handler    (folds events into KeyOpsState)
                              └─ journal          (in-memory now, Doobie/PG via PR #3)
```

## 3. Wire-protocol planes

All four planes terminate at the same `KeyService[F[_]]` algebra. They differ only in framing, auth, and which subset of operations they expose.

| Plane | Framing | Auth (target) | Audience |
| --- | --- | --- | --- |
| REST (`aegis-http`) | JSON over HTTP/1.1, OpenAPI advertised | OIDC bearer + agent-issued JWT | App developers, dashboards |
| KMIP (`aegis-kmip`) | TTLV over TLS 1.3 (mTLS) | Client certificate | Storage, DB, backup vendors |
| MCP (`aegis-mcp-server`) | JSON-RPC 2.0 over stdio / SSE | Agent-issued JWT scoped to a session | LLM agents (Claude, GPT, etc.) |
| Agent-AI (`aegis-agent-ai`) | JSON over HTTP, function-call shape | Agent-issued JWT | Custom agents, tool-use frameworks |

**Why two AI surfaces?** MCP is the standardized contract; the lower-level agent-AI plane lets us expose richer KMS-specific affordances (e.g. envelope-encryption helpers, structured rationales) that don't fit MCP's tool-call shape.

## 4. Audit and logging

Aegis-KMS distinguishes **operational logs** (for engineers) from **audit events** (for compliance and forensics). They have different retention, different consumers, and different write paths.

```
                                                            ┌─ stdout (JSON, pekko-slf4j) ──► loki / cloudwatch
   any plane ──► HttpRoutes / KmipServer / McpServer ──► logger ─┤
                            │                                    └─ stderr (errors)
                            │
                            ▼
                     KeyOpsActor (PR #2)
                            │
                            │  on every state-changing event
                            ▼
                  AuditSink (aegis-audit)
                            │
                            ├─► append-only Postgres table  (PR #3)
                            ├─► fan-out to S3 / object store (planned)
                            └─► optional SIEM webhook        (planned)
```

### What gets logged vs audited

| Event | Operational log | Audit event |
| --- | --- | --- |
| HTTP request received | yes (request ID, method, path, status, ms) | no |
| `KeyService.create` succeeded | yes (info) | **yes** (`KeyCreated`) |
| `KeyService.activate` succeeded | yes (info) | **yes** (`KeyStateChanged`) |
| `KeyService.destroy` succeeded | yes (info) | **yes** (`KeyDestroyed`) |
| Validation error (bad JSON, unknown algorithm) | yes (warn) | no |
| Permission denied | yes (warn) | **yes** (`AccessDenied`) |
| Authentication failure | yes (warn) | **yes** (`AuthFailed`) |
| Internal error / unexpected exception | yes (error) | **yes** (`InternalError`) |
| Root-of-trust unwrap / wrap | yes (debug) | **yes** (`KeyMaterialAccessed`) |

### Audit event shape (target)

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

Audit events are written **after** the state-changing event has been persisted to the journal (PR #2 + #3). The order is: command → persist event → fold into state → emit audit event → reply. If the audit sink is unavailable, the operation is still committed but the actor records a `PendingAuditDelivery` event that a sweeper retries — the log is append-only and may be late, but is never lost.

### Correlation

Every inbound request gets a `request-id` (generated at the HTTP/KMIP/MCP boundary). It propagates into:

- the structured log line (MDC),
- the `AuditEvent.context["request_id"]`,
- the response header (`X-Request-Id`) so callers can quote it in support tickets.

### Logging stack

`pekko-slf4j` bridges Pekko logging into Logback. `application.conf` already wires `org.apache.pekko.event.slf4j.Slf4jLogger` so `ActorSystem` startup, supervisor restarts, and stream materialization warnings all flow through the same pipeline. Output is JSON-line so a Loki / CloudWatch / Datadog agent can ingest without a custom parser.

## 5. Security model

- **No raw key material on the wire.** REST and KMIP both return key *handles* (`KeyId`); the actual material lives behind `RootOfTrust` (AWS KMS or a local file-backed RoT for dev). Crypto operations are server-side.
- **Principals are explicit.** `Principal.Human(sub, roles)` and `Principal.Agent(sub, parentHuman, scopes)` are separate cases — agent identities always carry a back-pointer to the human who issued them, so audit log queries like "everything done on behalf of user `alice`" are a single join.
- **Library-safe tier has no I/O.** `aegis-core` is pure Scala — no Pekko, no JDBC, no HTTP. This makes property tests against `KeyService` cheap and keeps the SDKs slim.

## 6. Operational topology

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
                              │  AWS KMS / RoT │  ─── never accessed except through aegis-crypto
                              └────────────────┘
```

The Pekko Typed `ActorSystem` is local to each pod; cross-pod consistency is achieved through the journal (PR #3) — two pods racing on the same `KeyId` will conflict at the persistence layer, not via cluster sharding. This is deliberate: shipping single-pod first lets KMIP, MCP, and the SDKs ride alongside without waiting on cluster-mode work.

## 7. Where to read next

- `modules/aegis-core/src/main/scala/dev/aegiskms/core/KeyService.scala` — the algebra everything wires through.
- `modules/aegis-http/src/main/scala/dev/aegiskms/http/HttpRoutes.scala` — Tapir → Pekko-HTTP wiring.
- `modules/aegis-http/src/test/scala/dev/aegiskms/http/HttpRoutesSpec.scala` — what "done" looks like for each PR's tests.
- `docs/architecture.html` — animated walk-through of a single REST request from edge to audit log (open in a browser).
