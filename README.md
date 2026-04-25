# Aegis-KMS

An open-source, KMIP-compliant Key Management Service — usable as an embeddable
library or as a standalone server, with first-class support for AI agents.

**Status:** pre-alpha. Scaffold only; no functionality yet.

**Architecture:** [written overview](docs/ARCHITECTURE.md) · [animated request walkthrough](https://sharma-bhaskar.github.io/aegis-kms/architecture.html)

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
git clone https://github.com/aegis-kms/aegis-kms.git
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
