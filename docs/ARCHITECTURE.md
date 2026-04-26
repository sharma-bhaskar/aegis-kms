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

### When KMIP matters (and when it doesn't)

KMIP is **infrastructure plumbing**, not an application API. It exists for a specific class of consumer:

- **Storage arrays.** NetApp, Dell EMC, HPE, Pure Storage all encrypt data at rest and need somewhere to store the wrapping keys. Their firmware is built around KMIP because it's the OASIS standard.
- **Database TDE.** Oracle TDE, Microsoft SQL Server EKM, MongoDB Enterprise, Percona pgcrypto integrations, and IBM Db2 all support KMIP for the master encryption key.
- **Backup systems.** Veeam, Commvault, Veritas, Rubrik all keep encrypted backups and consult a KMIP server for the keys.
- **Tape libraries.** LTO encryption (LTO-4 onward) was built around the assumption of a KMIP key manager.
- **HSM proxies and gateways.** Products that need to surface an HSM as a KMS to other tools.

If you are *not* one of those things — if you are an app developer, a microservice author, a CLI tool, an AI agent, or a script — KMIP is the wrong wire for you. You want REST/SDK or MCP. KMIP exists in Aegis-KMS so that the storage and database products in your environment can keep working without a proprietary KMS, not because it's the recommended interface for new application code.

In a deployment that has no storage / DB / backup / tape consumers, the KMIP listener can be disabled in configuration and the rest of the system runs unchanged.

## 3. Key lifecycle — how a key actually behaves

A managed key in Aegis-KMS is a state machine, not a bag of bytes. Every operation either reads the current state or transitions it, and every transition produces an audit event.

```
       create                 activate              schedule rotation
   ┌──────────►  PreActive  ───────────►  Active  ──────────────┐
   │                                       │  ▲                 │
   │                                       │  │                 ▼
   │                                       │  │             Active'  (new version)
   │                                       │  │                 │
   │                                       ▼  │                 │
   │                                  Deactivated  ◄────────────┘ old version, verify-only
   │                                       │
   │                                       ▼  retention period
   │                                   Compromised? ──► Compromised  (manual)
   │                                       │
   │                                       ▼
   └────────────────────────────────►  Destroyed     audit row preserved forever
```

Each transition has a single owner and a clear semantic:

- **Create** — a `KeyService.create(spec, principal)` call allocates a `KeyId`, asks the Root of Trust to materialize key bytes (or generate them inside an HSM), wraps the material under the master key, and stores the wrapped blob in the journal. The key starts in `PreActive` — it exists but cannot yet be used for cryptographic operations. This is deliberate: it lets policy engines, auditors, or human operators approve a key before it goes live.
- **Activate** — a separate operation transitions `PreActive → Active`. From here, `sign`, `verify`, `encrypt`, `decrypt`, `wrap`, `unwrap` are all legal. The wrapped material never leaves the Root of Trust; cryptographic operations happen server-side and only the result crosses the wire.
- **Rotate** — rotation creates a *new version* of the same logical key. The old version moves to `Deactivated` (still legal for `verify` and `decrypt` so existing ciphertexts and signatures stay readable). The new version becomes `Active` for new `sign` and `encrypt` calls. Rotation is configurable per-key: time-based, operation-count-based, or manual.
- **Deactivate / Compromise** — `Deactivated` keys can still verify and decrypt; useful during a controlled rotation. `Compromised` is a manual override that locks the key down — it can no longer perform *any* cryptographic operation. A compromise is itself an audit event of the highest severity, with `outcome=Compromised` and the operator who declared it as `actor`.
- **Destroy** — destruction is the only state from which there is no return. The wrapped material is deleted from the journal; the Root of Trust is asked to destroy the source material. The audit row marking the destruction is kept forever — compliance requires you can prove a key existed and was destroyed cleanly, even decades later.

### What a user actually does

- **An app developer** asks for a key by name and uses it: `kms.create("invoice-signing")`, `kms.activate(id)`, then any number of `kms.sign(id, message)` calls. Rotation, key material lifecycle, and audit are handled entirely by the KMS.
- **A storage / database vendor** speaks KMIP. Their existing integration code that already talks to Vault Enterprise or Thales CipherTrust works against Aegis-KMS without modification — same TTLV operations, same TLS profile, same key handles.
- **An operator** uses the CLI or a dashboard built on the Scala/Java SDK. They schedule rotations, approve key creations, revoke compromised keys, and audit who-did-what.
- **An AI agent** uses MCP tool calls (covered next), with credentials scoped to specific keys, operations, and time windows.

### Where keys come from

Aegis-KMS does **not** generate key material itself. It delegates to a pluggable **Root of Trust** (RoT), exposed by `aegis-crypto` as an SPI. The same `KeyService.create` call produces very different security properties depending on which RoT is configured:

| RoT provider | How a fresh DEK is generated | Where plaintext lives |
| --- | --- | --- |
| `software` (dev / test) | JCE `SecureRandom` (CSPRNG, `/dev/urandom` on Linux) | In JVM heap during the operation, then zeroed |
| `aws-kms` | `GenerateDataKey` against an AWS KMS CMK; AWS HSMs (CloudHSM-backed) generate it | Returned plaintext used in-process, immediately discarded |
| `gcp-kms` | Cloud KMS `Encrypt`/`Decrypt` against a CryptoKey | Same |
| `azure-keyvault` | HSM-backed key operations | Same |
| `vault-transit` | HashiCorp Vault generates and wraps | Same |
| `pkcs11` | `C_GenerateKey` inside a real HSM (Thales Luna, Entrust nShield, YubiHSM, AWS CloudHSM, SoftHSM for dev) | **Never leaves the HSM** — every crypto op runs inside the device |

Only the *wrapped* DEK (encrypted under the RoT's master key) is persisted in the journal. On every subsequent operation, the wrapped DEK is fetched, unwrapped by the RoT (often inside HSM memory), used for the requested op, then forgotten. This is the property that makes the same `KeyService` algebra appropriate for a developer laptop and for a FIPS 140-2 Level 3 deployment — the algebra doesn't change, the RoT does.

**RoT choice is the single biggest security knob.** A software RoT offers no FIPS attestation, no hardware tamper resistance, and no protection against a compromised host extracting key bytes. A PKCS#11 RoT against a FIPS Level 3 HSM gives you all three. Aegis-KMS treats this as a deployment decision, not a code change.

### Bring Your Own Key (BYOK)

Some keys aren't generated — they're imported. Use cases include compliance/legal escrow, customer-managed keys ("HYOK"), and migrations from a previous KMS. Aegis-KMS supports import on every plane:

- **REST** — `POST /v1/keys/import` with the wrapped key material.
- **KMIP** — standard `Register` operation.
- **CLI** — `aegis key import --from <file>`.

Imported material is rewrapped by the configured RoT before being persisted, so escrow material never sits in Postgres in plaintext.

## 4. AI agents and MCP

AI agents are first-class citizens, not bolted on. Three properties make this work:

**Identity.** Every agent action carries a `Principal.Agent(sub, parentHuman, scopes)`. The `parentHuman` is the operator who issued the agent its credential, and that link is mandatory — every audit query "everything done on behalf of alice" trivially includes everything her agents did. There is no anonymous agent identity.

**Scoped credentials.** Agents are issued short-lived JWTs with explicit allowlists: which keys, which operations, which time window. An agent that should only sign with one key for the next hour gets a credential that does *exactly* that. The IAM module enforces this on every call before `KeyService` runs.

**Tool surface.** The MCP server publishes a curated set of tools — `create_key`, `sign`, `unwrap`, `rotate`, `list_keys` — each one annotated with the permissions it requires and the side effects it produces. An LLM client sees them in the same shape as any other MCP tool, and the host-side approval UI (e.g. Claude's tool-use confirmation) gives the human operator a chance to approve sensitive operations before they run.

The result: a Claude or GPT agent can use Aegis-KMS as if it were any other MCP-connected tool, while every action remains attributable, scope-limited, and audited.

## 5. Request lifecycle

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

## 6. Audit and logging

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

## 7. Security model

**No raw key material on the wire.** REST and KMIP both return key *handles* (`KeyId`); the actual material lives behind the Root of Trust (AWS KMS, Vault, PKCS#11, etc.). All cryptographic operations are server-side; clients never see plaintext key bytes.

**Principals are explicit.** `Principal.Human(sub, roles)` and `Principal.Agent(sub, parentHuman, scopes)` are separate cases — agent identities always carry a back-pointer to the human who issued them. Audit queries like "everything done on behalf of `alice`" are a single join, not a heuristic.

**Defense in depth at every plane.** REST and Agent-AI use OIDC-issued bearer tokens; KMIP uses mTLS; MCP uses session-scoped JWTs. All four converge on the same IAM policy check before `KeyService` runs.

**Library-safe tier has no I/O.** `aegis-core` is pure Scala — no Pekko, no JDBC, no HTTP. This makes property tests against `KeyService` cheap, keeps the SDKs slim, and lets embedders decide their own effect type.

## 8. Operational topology

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

## 9. Where to read next

- `modules/aegis-core/src/main/scala/dev/aegiskms/core/KeyService.scala` — the algebra everything wires through.
- `modules/aegis-http/src/main/scala/dev/aegiskms/http/HttpRoutes.scala` — Tapir → pekko-http wiring.
- `modules/aegis-http/src/test/scala/dev/aegiskms/http/HttpRoutesSpec.scala` — what "done" looks like for each capability's tests.
- [`architecture.html`](https://sharma-bhaskar.github.io/aegis-kms/architecture.html) — interactive walk-through of one REST request from edge to audit log.

## 10. How Aegis-KMS compares

Most teams evaluating Aegis-KMS are also looking at one of: a cloud provider's KMS, HashiCorp Vault, OpenBao, or a focused KMIP server. Here is the honest comparison.

### vs AWS KMS / GCP KMS / Azure Key Vault

These are excellent products if your entire infrastructure lives in a single cloud. Aegis-KMS is for teams that don't have that luxury, or don't want to inherit it.

- **Vendor lock-in.** The proprietary cloud KMSes only work inside their own cloud. Aegis-KMS deploys anywhere a JVM and Postgres can run — your VPC, your colo, an air-gapped sovereign cloud, even a developer laptop.
- **Cost model.** AWS KMS is $1 per key per month plus $0.03 per 10,000 calls. At sustained API rates this becomes a meaningful line item — and it's a line item that grows with usage instead of with capacity. Aegis-KMS has no per-call cost; you pay for the compute and storage you actually run.
- **Wire protocol.** None of the cloud KMSes speak KMIP, the OASIS standard storage vendors and database engines have built integrations for. To use AWS KMS with a KMIP-only client (a NetApp filer, an Oracle TDE deployment, a Veeam backup target) you need a proxy or a wrapper service. Aegis-KMS speaks KMIP natively.
- **AI agent identity.** Cloud KMSes have IAM users and roles. They do not model "an agent acting on behalf of a human" — there's no equivalent of `Principal.Agent` with a mandatory `parentHuman`. If your AI agents need keys, you have to invent the identity model yourself, and audit trails won't naturally answer "what did Alice's agents do today."

### vs HashiCorp Vault / Vault Enterprise

Vault is a general secrets manager that happens to include a transit secrets engine for crypto operations. Aegis-KMS is a purpose-built KMS.

- **Surface area.** Vault does secrets, PKI, SSH CA, database credentials, AppRole, identity federation, and many more things. That breadth is a strength when you need a one-stop shop, and a liability when you don't — every Vault upgrade has surface area you're not using. Aegis-KMS does keys.
- **License.** Vault moved to BSL in 2023. Vault Enterprise is closed-source and required for the KMIP secrets engine. Aegis-KMS is Apache-2.0 with KMIP in the OSS distribution.
- **Multiple wire planes share an algebra.** REST, KMIP, MCP, and Agent-AI in Aegis-KMS terminate at the same `KeyService` algebra — they share validation, audit, and identity by construction. Vault's KMIP engine and KV/transit engines are separate code paths with separate semantics.
- **AI surface.** Vault has no MCP server. To let an LLM agent use Vault you write a custom adapter and design the auth scoping yourself. Aegis-KMS publishes a curated MCP tool set out of the box, with the agent-identity model wired in.

### vs OpenBao

OpenBao is the Linux Foundation's MPL-2.0 fork of Vault, created in response to the BSL relicense. Most of what is true of Vault applies, with two differences:

- OpenBao is fully open-source (MPL-2.0). License-wise it's a peer to Aegis-KMS.
- OpenBao does not include the KMIP secrets engine — that was Vault Enterprise only and didn't make it into the fork. If you want OSS KMIP, Aegis-KMS is the path.

### vs PyKMIP / Cosmian / EJBCA

These are KMIP-focused servers, similar in scope to Aegis-KMS's KMIP plane.

- They are KMIP-only. Aegis-KMS adds REST, MCP, and Agent-AI on the same core — one deployment serves storage vendors, application developers, and AI agents simultaneously, with one audit trail.
- They are written in Python (PyKMIP), Rust (Cosmian), or Java (EJBCA). Aegis-KMS is Scala 3 with a JVM library tier — embeddable in any JVM application as a dependency, not just as a server.

### vs Tink / BouncyCastle

Different category, mentioned because the question comes up. Tink and BouncyCastle are cryptographic libraries — algorithms, modes, and primitives. They have no notion of key lifecycle, identity, audit, or centralized policy. Aegis-KMS uses libraries like these underneath; it provides the surrounding infrastructure that turns "I can call AES-GCM" into "I can manage 50 keys across 12 services with policy and audit."

### When *not* to use Aegis-KMS

Honest counter-positioning:

- **You are 100% on one cloud and don't anticipate moving.** AWS KMS is well-integrated with AWS services. Don't fight gravity.
- **You already run Vault Enterprise and use a small fraction of it.** The cost of operating two systems may exceed the cost of staying on Vault.
- **You need a general secrets manager (database creds, dynamic secrets, SSH CA).** Aegis-KMS is intentionally narrow. Pair it with a secrets manager rather than expecting one tool to do both.

## 11. Status

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
