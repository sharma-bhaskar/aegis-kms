# Aegis-KMS

**Agent-native key management for AI and distributed systems.**

Aegis-KMS is a control plane for cryptographic keys. It runs in front of your existing key store — AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault, an on-prem PKCS#11 HSM, or its own software root of trust — and adds three things every legacy KMS is missing:

1. **Agent identity tied to a human.** Every Claude / GPT / custom-agent action carries a `Principal.Agent(sub, parentHuman, scopes)`. The parent human is mandatory. Audit queries like "everything Alice's agents did today" are a one-line join, not a heuristic.
2. **Intelligence layer over static policy.** Boolean allow/deny is the floor. Aegis adds context-aware risk scoring, baseline-aware anomaly detection on key usage, and an LLM advisor that explains why a key looks unused or risky and suggests rotation policies. *(Substrate today; full feature set in [Status](docs/ARCHITECTURE.md#11-status).)*
3. **MCP-native.** Claude, Cursor, and any MCP-aware tool can use Aegis-KMS as a tool out of the box. The same agent identity and scope checks apply whether the call arrives over MCP, REST, or KMIP.

Apache-2.0 · KMIP 1.4 / 2.x compliant · embeddable as a JVM library.

> **Status:** pre-alpha. The scaffold and four wire planes are designed; `aegis-agent-ai` (anomaly detection + risk scoring + LLM advisor) is the next active workstream. See [docs/ARCHITECTURE.md §11](docs/ARCHITECTURE.md#11-status) for what runs today.

Read more: [positioning](docs/POSITIONING.md) · [architecture](docs/ARCHITECTURE.md) · [usage guide](docs/USAGE.md) · [interactive walk-through](https://sharma-bhaskar.github.io/aegis-kms/architecture.html).

## Three ways to deploy

Most teams should start with **layered** — keep your existing key store, get the intelligence and agent layer on top.

| | **Layered** *(recommended)* | **Standalone** | **HSM-backed** |
| --- | --- | --- | --- |
| Who generates the key bytes? | AWS / GCP / Azure KMS or Vault — your existing service | Aegis, via its software or cloud-KMS RoT | The HSM, internally |
| Where does the key material live? | In your cloud KMS or Vault — Aegis stores only a reference | Wrapped in Aegis's Postgres | Inside the HSM, never leaves |
| Where does the crypto op run? | Proxied to the cloud KMS | In Aegis (after RoT unwrap) | Inside the HSM |
| What does Aegis own? | Identity, audit, **intelligence**, MCP, KMIP fronting | Everything (full data plane too) | Identity, audit, **intelligence**, MCP, KMIP fronting |
| Best for | Teams already on AWS / GCP / Vault wanting agent governance + AI integration **without migrating keys** | Air-gapped, sovereign cloud, full-stack OSS | FIPS 140-2 Level 3, regulated industries |

The reason layered is the recommended path: most teams will not, and should not, migrate their existing AWS KMS CMKs. Layered mode means you keep your keys exactly where they are and adopt Aegis only as the **control and intelligence plane** — agent identity, audit consolidation, anomaly detection, MCP integration, and a unified interface across multiple cloud KMSes.

## Architecture at a glance

![Aegis-KMS — system surfaces, animated](docs/architecture-flow.svg)

Apps, operators, storage vendors, and AI agents reach Aegis-KMS over four wire planes (REST, KMIP, MCP, Agent-AI). All four converge through IAM and a context-aware risk scorer into a single audited `KeyService`. Below `KeyService`, a pluggable **Root of Trust** decides where keys actually live — AWS KMS, GCP, Azure, Vault, PKCS#11 HSM, or local software. Every state change emits an `AuditEvent` with the actor identity preserved end to end; agent identities always carry a back-pointer to the human who issued them.

## How keys are generated

This is the question every evaluator asks. The short answer: **Aegis is a control plane; the data plane is pluggable.** Concretely, key generation depends on which deployment mode you're in.

### Layered mode — you already have AWS KMS / GCP / Azure / Vault

You don't migrate keys. You register them.

```bash
# point Aegis at your existing CMKs — no key material moves
aegis key register \
  --aws-arn arn:aws:kms:us-east-1:111122223333:key/abcd-... \
  --alias   invoice-signing
```

Or create new keys and have Aegis delegate generation to your cloud KMS:

```bash
aegis key create invoice-signing --backend aws-kms --spec ec-p256
# Aegis calls `aws kms CreateKey` under the hood;
# AWS HSMs generate the key; Aegis stores only the ARN + metadata.
```

Every subsequent `sign` / `decrypt` / `verify` call goes through Aegis (IAM check, risk score, audit, MCP visibility) and is proxied to AWS KMS for the actual crypto. **No plaintext key material ever touches Aegis's host.**

### Standalone mode — Aegis owns the data plane too

```bash
aegis key create invoice-signing --backend software --spec ec-p256
```

Aegis asks the configured Root of Trust for fresh material, wraps it under the RoT master key, and persists the wrapped form in Postgres. Plaintext is used briefly in-process for crypto ops, then immediately discarded.

| RoT provider | How a fresh DEK is generated | Plaintext lifetime |
| --- | --- | --- |
| `software` (dev / test) | JCE `SecureRandom` (CSPRNG, `/dev/urandom` on Linux) | In JVM heap during the op, then zeroed |
| `aws-kms` (envelope mode) | `GenerateDataKey` against an AWS CMK; AWS HSMs generate the DEK | In-process briefly, then discarded |
| `gcp-kms` / `azure-keyvault` / `vault-transit` | Same envelope pattern | Same |
| `pkcs11` | `C_GenerateKey` inside the HSM | **Never leaves the HSM** |

The difference between layered mode with `aws-kms` and standalone mode with `aws-kms` RoT: in layered mode AWS KMS holds the *whole* key and every op proxies to AWS; in standalone envelope mode AWS KMS only wraps a DEK that Aegis stores in Postgres and unwraps per-operation.

### HSM-backed mode — FIPS Level 3

```bash
aegis key create invoice-signing --backend pkcs11 --spec ec-p256
```

Aegis calls into the HSM via PKCS#11. The key is generated inside the device. Every crypto op runs inside the HSM. Aegis holds only an opaque handle. This is the deployment for regulated industries that need attestation that key material has never existed outside a tamper-resistant boundary.

### Bring Your Own Key (BYOK) — any mode

If you have existing key material (compliance escrow, customer-managed keys, legacy migration), import it on any plane:

```bash
aegis key import \
  --alias       customer-acme-key \
  --wrapped     wrapped.bin \
  --wrap-scheme RSA-OAEP-SHA256
```

The imported key is wrapped by the configured backend before being persisted, so escrow material never sits anywhere in plaintext.

## How it works end-to-end

![Aegis-KMS — key lifecycle, end to end](docs/usage-flow.svg)

A key in Aegis-KMS moves through four phases, and every transition is gated by IAM and recorded in the audit log:

1. **Create.** An operator (human or via `aegis-cli`) requests a new key. IAM checks role and policy; the chosen backend generates the key (in layered mode this is AWS / GCP / Vault; in standalone it's the configured RoT; in HSM mode it's the device); audit records `KeyCreated`. The key starts in `PreActive` and transitions to `Active`.
2. **Use.** An app (REST), a storage / database vendor (KMIP), or an AI agent (MCP) calls `encrypt` / `decrypt` / `sign` / `verify`. IAM checks the principal's scopes; the risk scorer evaluates the request against baseline; the operation runs through the backend; audit records `KeyUsed` with both the immediate actor and, for agents, the parent human operator.
3. **Rotate.** Triggered manually, by policy, or by an `aegis-agent-ai` recommendation. `KeyService.rotate` mints a new version; the previous version stays available for decrypt-only so existing ciphertexts keep working; audit records `KeyRotated`.
4. **Retire.** The operator deactivates the key (no new ops accepted), a configurable grace window passes, then `destroy` purges the wrapped DEK or revokes the cloud-KMS reference; audit records `KeyDestroyed`.

The same `KeyService` algebra is reached from all four wire planes, which is why an AI agent calling over MCP is subject to exactly the same IAM checks, risk scoring, and audit trail as a human operator calling over REST.

## Which wire do I use?

Most users only need one. KMIP is infrastructure plumbing; if you're writing application code, use REST or the SDK.

| You are... | Use | Why |
| --- | --- | --- |
| App developer (any language with HTTP / a JVM SDK) | **REST + SDK** | JSON over HTTPS, OpenAPI generated, easy to adopt |
| AI agent or LLM tool | **MCP** | Native tool-use surface; scoped agent identity with mandatory parent-human linkage |
| Storage array · database TDE · backup product · tape library · HSM proxy | **KMIP** | Your product already speaks KMIP — Aegis-KMS is a drop-in replacement for Vault Enterprise or Thales CipherTrust |
| Custom tool-use / agent framework that isn't MCP-native | **Agent-AI** | Function-call shape with richer KMS-specific affordances |

KMIP is an OASIS binary protocol from 2010 (TTLV framing over mTLS). It exists because **storage vendors** (NetApp, Dell EMC, Pure Storage), **databases** (Oracle TDE, MSSQL EKM, MongoDB Enterprise), **backup systems** (Veeam, Commvault, Veritas), and **tape libraries** needed a standard way to talk to a KMS. If you are not one of those things, you almost certainly want REST or the SDK, not KMIP.

KMIP is **optional** in any deployment — disable the listener in config and the rest of Aegis-KMS works exactly the same.

## Using Aegis-KMS

Four ways to use it, depending on who you are. End-to-end walkthrough with auth setup, full options, and common patterns is in [docs/USAGE.md](docs/USAGE.md).

### As an app developer — REST + SDK

```bash
export AEGIS_URL=https://aegis.your-org.internal
export AEGIS_TOKEN=$(your-oidc-flow)

# create — in layered mode this delegates to your cloud KMS
curl -X POST $AEGIS_URL/v1/keys \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"alias":"invoice-signing","backend":"aws-kms","spec":{"algorithm":"EC","curve":"P-256","usage":["Sign","Verify"]}}'

curl -X POST $AEGIS_URL/v1/keys/<id>/activate -H "Authorization: Bearer $AEGIS_TOKEN"

curl -X POST $AEGIS_URL/v1/keys/<id>/sign \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"<base64>","algorithm":"ECDSA-SHA256"}'
```

```scala
import cats.effect.IO
import dev.aegiskms.sdk.{AegisClient, AegisConfig}
import dev.aegiskms.core.KeySpec

val client = AegisClient[IO](AegisConfig(url, token))
for
  k   <- client.keys.create(KeySpec.ec256("invoice-signing"))
  _   <- client.keys.activate(k.id)
  sig <- client.keys.sign(k.id, message = bytes)
yield sig
```

### As an operator — `aegis-cli`

```bash
aegis login
aegis key register --aws-arn arn:aws:kms:... --alias prod-signing       # layered: register existing
aegis key create invoice-signing --backend aws-kms --spec ec-p256       # layered: new key delegated
aegis key list --state Active
aegis key rotate <id>
aegis audit --actor alice@org --since 24h
aegis agent issue --parent alice@org --scopes "key:<id>:sign" --ttl 1h
aegis advisor scan                                                       # LLM advisor: unused / risky / under-rotated keys
```

### As an AI agent — MCP

The operator issues a scoped, short-lived agent credential. The MCP client (Claude Desktop, Cursor, any MCP host) is configured to point at Aegis-KMS and uses that credential.

```jsonc
// claude_desktop_config.json
{
  "mcpServers": {
    "aegis-kms": {
      "command": "aegis-mcp-bridge",
      "args": ["--url", "https://aegis.your-org.internal", "--token-env", "AEGIS_AGENT_JWT"]
    }
  }
}
```

The agent sees tools like `create_key`, `sign`, `verify`, `rotate`, `list_keys`. Every call is gated by IAM against the agent's allowlist, scored by the risk engine, audited under the agent's identity, and joined back to the parent human in the audit log.

### As a storage / database / backup vendor — KMIP

```
Host:      aegis.your-org.internal
Port:      5696
TLS:       1.3, mTLS (client cert via `aegis cert issue --cn <name>`)
Versions:  KMIP 1.4 / 2.0 / 2.1 / 2.2 / 3.0 (auto-negotiated)
```

In layered mode, KMIP requests are scoped, scored, and proxied to the underlying cloud KMS or HSM. Your storage array doesn't know it's not talking to a traditional KMIP server; meanwhile, every request is observable to Aegis's intelligence layer and the audit log.

## How it compares

| Capability | Cloud KMS<br/>(AWS / GCP / Azure) | Vault Enterprise | OpenBao | **Aegis-KMS** |
| --- | --- | --- | --- | --- |
| License | Proprietary | BSL | MPL-2.0 | **Apache-2.0** |
| Self-hostable / air-gapped | No | Yes | Yes | **Yes** |
| KMIP 1.4 / 2.x wire protocol | No | Enterprise only | No | **Yes** |
| MCP server for AI agents | No | No | No | **Yes** |
| Agent identity tied to a human operator | No | No | No | **Yes** |
| Risk-scored access (not just policy) | No | No | No | **Yes** *(in design)* |
| Anomaly detection on key usage | No | No | No | **Yes** *(in design)* |
| LLM advisor (explain / suggest / clean) | No | No | No | **Yes** *(in design)* |
| Layered mode (front existing AWS / GCP / Vault, no migration) | n/a | No | No | **Yes** |
| Embeddable as a JVM library | No | No | No | **Yes** |
| Per-operation cost | $$ per API call | License + ops | Ops only | **Ops only** |

Deeper writeup in [docs/ARCHITECTURE.md §10](docs/ARCHITECTURE.md#10-how-aegis-kms-compares).

## Modules

| Module | Purpose | Depends on Pekko? |
| --- | --- | --- |
| `aegis-core` | Pure domain (DTOs, `KeyService[F]` algebra) | No |
| `aegis-crypto` | Root-of-trust SPI + provider impls (software / AWS / GCP / Azure / Vault / PKCS#11) | No |
| `aegis-iam` | Principals, policies, JWT/OIDC, agent identity | No |
| `aegis-audit` | Append-only audit log SPI | No |
| `aegis-persistence` | Doobie-based store + Postgres / MySQL drivers | No |
| `aegis-sdk-scala` | Scala client SDK | No |
| `aegis-sdk-java` | Java client SDK | No |
| `aegis-kmip` | KMIP codec + TCP server | Yes |
| `aegis-http` | pekko-http REST + OpenAPI | Yes |
| `aegis-agent-ai` | **Risk scorer · anomaly detector · auto-responder · LLM advisor** | Yes |
| `aegis-mcp-server` | MCP tool surface for LLMs | Yes |
| `aegis-server` | Main server app wiring everything | Yes |
| `aegis-cli` | `aegis` admin CLI | No |

## Quickstart — running the server

Prerequisites: JDK 21, sbt 1.10+, Postgres 14+.

```bash
git clone https://github.com/sharma-bhaskar/aegis-kms.git
cd aegis-kms
sbt "server/run"
```

## Quickstart — embedding as a library

```scala
libraryDependencies ++= Seq(
  "dev.aegiskms" %% "aegis-core"        % "0.1.0",
  "dev.aegiskms" %% "aegis-crypto"      % "0.1.0",
  "dev.aegiskms" %% "aegis-persistence" % "0.1.0"
)
```

```scala
import cats.effect.IO
import dev.aegiskms.core.*

val keys: KeyService[IO] = KeyService.inMemory[IO]

val program: IO[Unit] =
  for
    alice <- IO.pure(Principal.Human("alice", Set("admins")))
    k     <- keys.create(KeySpec.aes256("invoice-signing"), alice)
    got   <- keys.get(k.id, alice)
  yield println(got)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the list of good-first-issue labels on the issue tracker.

## License

Apache-2.0. See [LICENSE](LICENSE).
