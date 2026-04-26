# Aegis-KMS

An open-source, KMIP-compliant Key Management Service — usable as an embeddable
library or as a standalone server, with first-class support for AI agents.

**Status:** pre-alpha. Scaffold only; no functionality yet.

## Architecture at a glance

![Aegis-KMS — system surfaces, animated](docs/architecture-flow.svg)

Apps and operators reach Aegis-KMS over **REST**, storage and database vendors over **KMIP**, AI agents over **MCP**, and custom tool-use frameworks over the **Agent-AI** plane. All four converge through IAM into a single audited `KeyService`, which writes through to a Postgres event journal and a pluggable Root of Trust (AWS KMS, GCP, Azure, Vault, PKCS#11). Every state change emits an `AuditEvent` with the actor identity preserved end to end — agent identities always carry a back-pointer to the human who issued them. Deeper reading: [architecture overview](docs/ARCHITECTURE.md) · [interactive walk-through](https://sharma-bhaskar.github.io/aegis-kms/architecture.html).

## Why

Existing OSS key managers are either tied to one cloud vendor, built around
legacy wire formats, or lack a clean story for AI agents acting on a user's
behalf. Aegis-KMS aims to be:

- **Standards-compliant** — strict OASIS KMIP 1.4 / 2.x conformance.
- **Vendor-neutral** — pluggable root-of-trust (AWS KMS, GCP KMS, Azure Key
  Vault, HashiCorp Vault, PKCS#11).
- **Embeddable** — `aegis-core` has no actor-system dependency; use it as a
  library from any JVM app.
- **Agent-aware** — first-class short-lived agent principals with mandatory
  operator linkage and explicit operation allowlists.
- **LLM-friendly** — built-in MCP server surface so Claude and other MCP
  clients can use the KMS as a tool.

## How it works end-to-end

![Aegis-KMS — key lifecycle, end to end](docs/usage-flow.svg)

A key in Aegis-KMS moves through four phases, and every transition is gated by IAM and recorded in the audit log:

1. **Create.** An operator (human or via `aegis-cli`) requests a new key. IAM checks role and policy; `KeyService` generates the DEK; the Root of Trust wraps it; Postgres stores the wrapped DEK; audit records `KeyCreated`. The key starts in `PreActive` and transitions to `Active`.
2. **Use.** An app (REST), a storage/database vendor (KMIP), or an AI agent (MCP) calls `encrypt` / `decrypt` / `sign` / `verify`. IAM checks the principal's scopes and key allowlist; the wrapped DEK is loaded and unwrapped by the Root of Trust; the operation runs; audit records `KeyUsed` with both the immediate actor and, for agents, the parent human operator.
3. **Rotate.** Triggered manually or by rotation policy. `KeyService.rotate` mints a new version under the same key id; the previous version stays available for decrypt-only so existing ciphertexts keep working; audit records `KeyRotated`.
4. **Retire.** The operator deactivates the key (no new ops accepted), a configurable grace window passes, then `destroy` purges the wrapped DEK; audit records `KeyDestroyed`. The key terminal state is `Destroyed`.

The same `KeyService` algebra is reached from all four wire planes, which is why an AI agent calling over MCP is subject to exactly the same IAM checks and audit trail as a human operator calling over REST.

## Which wire do I use?

Most users only need one. KMIP is infrastructure plumbing; if you're writing application code, use REST or the SDK.

| You are... | Use | Why |
| --- | --- | --- |
| App developer (any language with HTTP / a JVM SDK) | **REST + SDK** | JSON over HTTPS, OpenAPI generated, easy to adopt |
| AI agent or LLM tool | **MCP** | Native tool-use surface; scoped agent identity with mandatory parent-human linkage |
| Storage array · database TDE · backup product · tape library · HSM proxy | **KMIP** | Your product already speaks KMIP — Aegis-KMS is a drop-in replacement for Vault Enterprise or Thales CipherTrust |
| Custom tool-use / agent framework that isn't MCP-native | **Agent-AI** | Function-call shape with richer KMS-specific affordances |

KMIP is an OASIS binary protocol from 2010 (TTLV framing over mTLS). It exists because **storage vendors** (NetApp, Dell EMC, Pure Storage), **databases** (Oracle TDE, MSSQL EKM, MongoDB Enterprise), **backup systems** (Veeam, Commvault, Veritas), and **tape libraries** needed a standard way to talk to a KMS without each one inventing its own protocol. If you are not one of those things, you almost certainly want REST or the SDK, not KMIP.

KMIP is **optional** in any deployment — disable the listener in config and the rest of Aegis-KMS works exactly the same.

## Where do keys come from?

Aegis-KMS itself does **not** generate key material. It delegates to a pluggable **Root of Trust** (RoT). The same `KeyService` API runs against any of these — you swap the RoT, not the KMS.

| RoT provider | How a key is generated | Plaintext exposure |
| --- | --- | --- |
| `software` (dev / test) | JCE `SecureRandom` (CSPRNG, `/dev/urandom` on Linux) | In JVM memory briefly during the op |
| `aws-kms` | `GenerateDataKey` against an AWS KMS CMK; AWS HSMs generate the DEK | Plaintext used in-process, then discarded |
| `gcp-kms` | Cloud KMS `Encrypt`/`Decrypt` against a CryptoKey | Same |
| `azure-keyvault` | HSM-backed key operations | Same |
| `vault-transit` | HashiCorp Vault generates and wraps | Same |
| `pkcs11` | `C_GenerateKey` inside a real HSM (Thales, Entrust, YubiHSM, AWS CloudHSM, SoftHSM for dev) | **Never leaves the HSM** |

Only the *wrapped* DEK (encrypted under the RoT's master key) is persisted to Postgres. On every operation the wrapped DEK is loaded, unwrapped by the RoT (often inside HSM memory), used, then forgotten.

**BYOK** — if you already have key material (compliance escrow, legacy migration, customer-managed keys), import it via REST `POST /v1/keys/import`, KMIP `Register`, or `aegis key import`. The imported key is wrapped by the configured RoT before being persisted, so escrow material never sits in Postgres in plaintext.

## Using Aegis-KMS

Four ways to use it, depending on who you are. End-to-end walkthrough with auth setup, full options, and common patterns is in [docs/USAGE.md](docs/USAGE.md).

### As an app developer — REST + SDK

Create a key, activate it, sign with it. Tokens are standard OIDC bearer tokens issued by your existing IdP (Okta, Auth0, Google Workspace, Azure AD, AWS IAM Identity Center).

```bash
export AEGIS_URL=https://aegis.your-org.internal
export AEGIS_TOKEN=$(your-oidc-flow)

# create
curl -X POST $AEGIS_URL/v1/keys \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"alias":"invoice-signing","spec":{"algorithm":"EC","curve":"P-256","usage":["Sign","Verify"]}}'

# activate
curl -X POST $AEGIS_URL/v1/keys/<id>/activate -H "Authorization: Bearer $AEGIS_TOKEN"

# sign
curl -X POST $AEGIS_URL/v1/keys/<id>/sign \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"<base64>","algorithm":"ECDSA-SHA256"}'
```

Or from Scala / Java via the SDK:

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

Rotation runs in the background per the key's policy; old versions stay verify-only, new versions sign. Your application code never changes.

### As an operator — `aegis-cli`

Day-to-day key management without writing code.

```bash
aegis login                                                      # OIDC device-code flow
aegis key create invoice-signing --spec ec-p256 --usage sign,verify
aegis key activate <id>
aegis key list --state Active
aegis key rotate <id>                                            # new version; old becomes verify-only
aegis key deactivate <id>
aegis key destroy <id>                                           # terminal; audit row preserved forever
aegis audit --actor alice@org --since 24h
aegis agent issue --parent alice@org --scopes "key:<id>:sign" --ttl 1h
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

The agent sees tools like `create_key`, `sign`, `verify`, `rotate`, `list_keys`. Every call is gated by IAM against the agent's allowlist, audited under the agent's identity, and joined back to the parent human in the audit log. Scopes the agent doesn't have produce a hard `403 AccessDenied` — the LLM sees a clear error and the audit log records the denial.

### As a storage / database / backup vendor — KMIP

Point your existing KMIP client at Aegis-KMS — no code changes.

```
Host:      aegis.your-org.internal
Port:      5696
TLS:       1.3, mTLS (client cert via `aegis cert issue --cn <name>`)
Versions:  KMIP 1.4 / 2.0 / 2.1 / 2.2 / 3.0 (auto-negotiated)
```

Standard `Create`, `Get`, `Activate`, `Encrypt`, `Decrypt`, `Register`, `Destroy` all work. Your storage array, database TDE deployment, or backup product talks to Aegis-KMS the same way it talks to any KMIP-conformant KMS.

## How it compares

A short comparison against the alternatives an OSS-leaning team would already be evaluating. Deeper writeup in [docs/ARCHITECTURE.md §10](docs/ARCHITECTURE.md#10-how-aegis-kms-compares).

| Capability | Cloud KMS<br/>(AWS / GCP / Azure) | Vault Enterprise | OpenBao | **Aegis-KMS** |
| --- | --- | --- | --- | --- |
| License | Proprietary | BSL | MPL-2.0 | **Apache-2.0** |
| Self-hostable / air-gapped | No | Yes | Yes | **Yes** |
| KMIP 1.4 / 2.x wire protocol | No | Enterprise only | No | **Yes** |
| MCP server for AI agents | No | No | No | **Yes** |
| Agent identity tied to a human operator | No | No | No | **Yes** |
| Embeddable as a JVM library | No | No | No | **Yes** |
| Pluggable root of trust (AWS / GCP / Azure / Vault / PKCS#11) | Single only | Enterprise | Limited | **Yes** |
| Per-operation cost | $$ per API call | License + ops | Ops only | **Ops only** |

## Modules

| Module | Purpose | Depends on Pekko? |
|--------|---------|--------------------|
| `aegis-core` | Pure domain (DTOs, `KeyService[F]` algebra) | No |
| `aegis-crypto` | Root-of-trust SPI + provider impls | No |
| `aegis-iam` | Principals, policies, JWT/OIDC, agent identity | No |
| `aegis-audit` | Append-only audit log SPI | No |
| `aegis-persistence` | Doobie-based store + Postgres/MySQL drivers | No |
| `aegis-sdk-scala` | Scala client SDK | No |
| `aegis-sdk-java` | Java client SDK | No |
| `aegis-kmip` | KMIP codec + TCP server | Yes |
| `aegis-http` | pekko-http REST + OpenAPI | Yes |
| `aegis-agent-ai` | Policy/anomaly AI + NL admin | Yes |
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
    alice  <- IO.pure(Principal.Human("alice", Set("admins")))
    k      <- keys.create(KeySpec.aes256("invoice-signing"), alice)
    got    <- keys.get(k.id, alice)
  yield println(got)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the list of good-first-issue labels
on the issue tracker.

## License

Apache-2.0. See [LICENSE](LICENSE).
