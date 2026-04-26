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
