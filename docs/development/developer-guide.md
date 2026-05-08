# Developer Guide

The full local-development workflow for Aegis-KMS — from cloning the repo to shipping a PR. If
you only want to *use* Aegis, [Quickstart](../getting-started/quickstart.md) is the better entry
point. This document is for people writing code.

## 1. Prerequisites

| Tool | Version | Why |
| --- | --- | --- |
| JDK | 21 (recommended) or 17 | Aegis is Scala 3.3.x; CI matrix tests both 17 and 21 |
| sbt | 1.10+ | Build tool; the repo ships an sbt wrapper but a system install is fine |
| Docker | any recent | Required for Testcontainers-based persistence tests |
| Git | 2.30+ | DCO sign-off uses `git commit -s` |
| GPG | optional | Only needed if you cut a release that publishes to Maven Central |

We strongly recommend [SDKMAN](https://sdkman.io/) for managing the JDK / sbt versions:

```bash
sdk install java 21.0.5-tem
sdk install sbt
```

If you're on macOS and prefer Homebrew: `brew install temurin sbt`.

## 2. First build

```bash
git clone https://github.com/sharma-bhaskar/aegis-kms.git
cd aegis-kms
sbt compile
```

The first compile downloads ~400MB of dependencies and takes 3-5 minutes on a cold cache. Every
subsequent compile is incremental and finishes in seconds.

Verify the build:

```bash
sbt test                   # 160+ tests across all modules
sbt scalafmtCheckAll       # formatting gate
sbt "scalafixAll --check"  # lint gate
```

If `sbt test` fails on a clean checkout, file an issue — that's a real bug.

## 3. Project layout

Aegis is a multi-project Scala build with **strictly enforced two-tier module split**. This is
the most important rule in the codebase.

```
aegis-kms/
├── modules/
│   ├── aegis-core/             ← Library tier (NO Pekko)
│   ├── aegis-iam/              ← Library tier
│   ├── aegis-audit/            ← Library tier
│   ├── aegis-crypto/           ← Library tier
│   ├── aegis-persistence/      ← Library tier
│   ├── aegis-sdk-scala/        ← Library tier
│   ├── aegis-sdk-java/         ← Library tier
│   ├── aegis-http/             ← Server tier (Pekko-aware)
│   ├── aegis-agent-ai/         ← Server tier
│   ├── aegis-server/           ← Server tier (Docker image)
│   ├── aegis-cli/              ← Server-tier-adjacent (no Pekko, packaged app)
│   ├── aegis-kmip/             ← Server tier (skeleton)
│   └── aegis-mcp-server/       ← Server tier (skeleton)
├── docs/                       ← Rendered docs source (this site)
├── deploy/
│   ├── docker/                 ← docker-compose.yml + Dockerfile context
│   └── helm/                   ← Placeholder, v0.3.0
├── project/
│   ├── build.properties        ← sbt version
│   ├── plugins.sbt             ← sbt plugins (sbt-ci-release, sbt-mima, ...)
│   └── Dependencies.scala      ← Pinned dependency versions
└── build.sbt                   ← Module definitions, settings, dependency overrides
```

### The two-tier split, explained

**Library tier modules MUST NOT depend on Pekko.** They're embeddable in any JVM app — a Spring
Boot service, a Lambda function, a sbt-launched script. Adding a `pekko` import to any of them
will fail to compile because `aegis-core` and friends literally don't have Pekko on their
classpath.

**Server tier modules add concurrency, HTTP, and runtime.** They depend on Pekko Typed for
actor-based state, pekko-http via Tapir for the REST plane, and a small handful of server-only
deps (Micrometer for Prometheus, OpenTelemetry SDK, etc.).

Why this matters:

- The split lets enterprise users embed Aegis as a library without taking on the full
  server-tier dependency closure.
- It makes property tests in `aegis-core` cheap — no actor system to spin up, no HTTP server.
- It prevents vendor coupling from leaking into the core algebras.

If you're unsure which tier a piece of new code belongs to, ask in the PR. The default for
library-tier additions is *no I/O, no Pekko, no vendor SDK calls.*

### Module names — sbt vs. directory

The directory `modules/aegis-core/` defines a **sbt module named `core`** (camelCase, no
prefix). This is unfortunate but intentional — sbt modules can't have hyphens, and the directory
prefix communicates the project name to humans browsing the repo.

| Directory | sbt module | Run a test |
| --- | --- | --- |
| `modules/aegis-core/` | `core` | `sbt "core / test"` |
| `modules/aegis-persistence/` | `persistence` | `sbt "persistence / test"` |
| `modules/aegis-crypto/` | `crypto` | `sbt "crypto / test"` |
| `modules/aegis-sdk-scala/` | `sdkScala` | `sbt "sdkScala / test"` |
| `modules/aegis-sdk-java/` | `sdkJava` | `sbt "sdkJava / test"` |
| `modules/aegis-mcp-server/` | `mcpServer` | `sbt "mcpServer / test"` |
| `modules/aegis-agent-ai/` | `agentAi` | `sbt "agentAi / test"` |
| `modules/aegis-http/` | `http` | `sbt "http / test"` |
| `modules/aegis-server/` | `server` | `sbt "server / test"` |
| `modules/aegis-cli/` | `cli` | `sbt "cli / test"` |

## 4. Build & test cheatsheet

```bash
# Compile everything
sbt compile

# Run all tests
sbt test

# Run one module's tests
sbt "core / test"

# Run one suite
sbt "http / testOnly *HttpRoutesSpec"

# Run one test by name substring
sbt "http / testOnly *HttpRoutesSpec -- -z 'creates a key'"

# Format gate (CI runs this)
sbt scalafmtCheckAll scalafmtSbtCheck

# Lint gate (CI runs this)
sbt "scalafixAll --check"

# Auto-format
sbt scalafmtAll

# Auto-fix lint
sbt scalafixAll

# Run the server (forks a JVM; in-memory journal by default)
sbt "server / run"

# Build the local Docker image
sbt "server / Docker / publishLocal"

# Build the CLI tarball
sbt "cli / Universal / packageZipTarball"

# Binary-compat check vs. the previous release
sbt mimaReportBinaryIssues
```

`Test / fork := true` is set globally, and `run / fork := true` is set on `server`
specifically (Pekko's user-guardian dispatcher hangs in sbt's in-process classloader otherwise —
do not remove these settings).

## 5. Testing

### Unit tests

We use [Scalatest](https://www.scalatest.org/) with the `AnyFlatSpec` style. Tests follow the
naming convention `<ClassName>Spec.scala` and live next to the code under
`modules/<module>/src/test/scala/<package>/`.

The canonical reference is [`KeyServiceSpec`](https://github.com/sharma-bhaskar/aegis-kms/blob/main/modules/aegis-core/src/test/scala/dev/aegiskms/core/KeyServiceSpec.scala) —
copy its shape when adding a new test for the algebra. For decorators, see
[`AuditingKeyServiceSpec`](https://github.com/sharma-bhaskar/aegis-kms/blob/main/modules/aegis-audit/src/test/scala/dev/aegiskms/audit/AuditingKeyServiceSpec.scala).

### Integration tests with Testcontainers

Some `aegis-persistence` tests spin up a real Postgres container via
[Testcontainers](https://www.testcontainers.org/). They `assume(...)` away gracefully when
Docker isn't available, so `sbt test` succeeds on workstations without Docker — but in CI we
always run them.

If a persistence test silently passes when you expect it to fail, check whether Docker is
running. The test output will say `[info] Skipped (Docker unavailable)`.

### Property tests

`aegis-core` algebra invariants (state-machine completeness, idempotence) are tested with
ScalaCheck. New algebra changes should add a property test — see `KeySpecGenSpec` for the
canonical pattern.

## 6. Code style & quality gates

Hard rules enforced by the build:

- **Scala 3.** No Scala 2 idioms. Use `enum`, `given/using`, `extension`, contextual abstractions.
- **`-Xfatal-warnings`** + **`-Wunused:all`** — every warning fails the build.
- **scalafmt** on every file. CI runs `scalafmtCheckAll` and `scalafmtSbtCheck`.
- **scalafix** for lint and import organization. CI runs `scalafixAll --check`.

Soft rules (PR review will surface these):

- Prefer immutable data; mutable state lives only in actor `Behavior` closures.
- `Option` / `Either` over null / exceptions for control flow. Exceptions are reserved for
  truly exceptional events (driver crashes, JVM-level failures).
- ADTs over boolean flags. If you have two booleans on a class, you probably want a 4-arm enum.
- Actor behaviors are **always** typed (`Behavior[T]` over a sealed command ADT). Untyped
  actors are not used anywhere in the codebase.
- DCO sign-off: every commit must be signed off (`git commit -s`).

### Imports

scalafmt's `AsciiSortImports` rule and scalafix's `OrganizeImports` rule are deliberately
configured to agree on import order. **Don't change the import order config in either tool
without verifying both still produce the same output** — they used to disagree, and the disagreement
caused a long-running CI flake.

## 7. Architecture — what you need to know to navigate

(For the full architecture writeup see [Concepts → Architecture](../ARCHITECTURE.md). This
section is the contributor's-eye summary.)

### The decorator stack

Every request through `aegis-server` flows through six decorators in this order:

```
HTTP → Audit → Tracing → Metrics → Authorize → Actor → Persistence + RoT
```

Each decorator wraps the same `KeyService[F[_]]` algebra and adds one orthogonal concern:

| Decorator | Adds | Module |
| --- | --- | --- |
| `AuditingKeyService` | Append-only audit log on every state change | `aegis-audit` |
| `TracingKeyService` | OpenTelemetry spans per operation | `aegis-server` |
| `MeteredKeyService` | Prometheus counters + latency histograms | `aegis-server` |
| `AuthorizingKeyService` | IAM allowlist check, returns `PermissionDenied` on miss | `aegis-iam` |
| `ActorBackedKeyService` | Single-writer state via Pekko Typed actor | `aegis-server` |
| `PostgresEventJournal` (or in-memory) | Persistent event log + RoT calls | `aegis-persistence` |

The order matters:

- **Audit is outermost** so it sees the *final* outcome including the IAM denial. Moving audit
  inside `AuthorizingKeyService` would cause denied requests to silently disappear from audit.
- **Authorize is inside metrics** so denies are countable as `aegis_keys_op_errors_total{code="PermissionDenied"}`
  rather than disappearing.
- **The actor is innermost** so all state-mutating calls serialize through one mailbox per
  process. Concurrent reads bypass the actor and hit the journal directly.

When adding a new concern, decide which layer it belongs to and slot a new decorator. Don't add
the concern to an existing decorator — that's how this codebase becomes Vault.

### Pekko Typed actor pattern (load-bearing)

`aegis-server` uses one core actor: `KeyOpsActor`. The pattern is unusual:

```scala
val system = ActorSystem(KeyOpsActor.behavior(deps), "aegis")
// system IS the actor — no user-guardian dance
val keyService = ActorBackedKeyService(system, ...)
```

This works because in Pekko Typed, `ActorSystem[T] <: ActorRef[T]`. The actor system *is* the
user guardian. Earlier versions used the more conventional `Behaviors.setup { ctx => ... }` +
`Promise` + `Await.result` pattern to expose an `ActorRef` to the main thread; that pattern
**hangs on cold start on JDK 21 + sbt's classloader** because the user guardian's setup block
is never dispatched.

If you see boot-time hangs, check whether someone has reintroduced the user-guardian +
Promise pattern. The fix is in [PR #45](https://github.com/sharma-bhaskar/aegis-kms/pull/45)
and there's a regression test (`ServerWiringSpec`) that asserts the actor system itself is the
actor.

### Resource[IO] boot scope

`Server.scala` uses `IOApp.Simple` + a single composed `Resource[IO, Unit]` chain to acquire
and release every long-lived dependency:

```scala
def run: IO[Unit] =
  (for
    metricsRegistry <- MetricsRegistry.make
    journal         <- PostgresEventJournal.make(config.jdbc, metricsRegistry)
    actorSystem     <- ActorSystemResource.make(...)
    httpBinding     <- HttpServer.bind(...)
  yield ()).useForever
```

SIGTERM unwinds the stack in reverse — HTTP unbind (5 s grace) → actor system terminate →
journal pool close → meter registry close. **Don't replace this with `unsafeRunSync` calls** —
the previous pattern leaked the journal connection pool until JVM exit.

### Vendor isolation via SPIs

`aegis-core` MUST NOT contain vendor-specific code. Three SPIs in the library tier handle
adapter pluggability:

| SPI | Module | Today | v0.2.0 |
| --- | --- | --- | --- |
| `RootOfTrust` | `aegis-crypto` | AWS KMS | + GCP KMS, Azure Key Vault, HashiCorp Vault, PKCS#11 |
| `EventJournal` | `aegis-persistence` | Postgres + in-memory | + MySQL, SQLite |
| `AuditSink` | `aegis-audit` | stdout | + Kafka, S3, Webhook, OTel logs |

If you're adding a vendor adapter, the right place is one of these modules — never `aegis-core`.

## 8. Adding a new feature — walked example

Imagine adding a new crypto operation `mac(id, message)`. The places you'd touch, in order:

1. **`aegis-core/src/main/scala/dev/aegiskms/core/KeyService.scala`** — add `def mac(...)` to
   the algebra, implement in the in-memory reference impl.
2. **`aegis-core/src/main/scala/dev/aegiskms/core/Operation.scala`** — add `Operation.Mac` to
   the IAM allowlist enum.
3. **`aegis-iam/src/main/scala/dev/aegiskms/iam/AuthorizingKeyService.scala`** — route
   `mac` through the policy check.
4. **`aegis-audit/src/main/scala/dev/aegiskms/audit/AuditingKeyService.scala`** — record a
   `Success` / `Failed` audit row carrying the relevant metadata (operation, principal,
   message length, *not* the message content).
5. **`aegis-crypto/src/main/scala/dev/aegiskms/crypto/RootOfTrust.scala`** — add `mac` to the
   SPI.
6. **`aegis-crypto/src/main/scala/dev/aegiskms/crypto/aws/AwsKmsRootOfTrust.scala`** — implement
   via the AWS KMS `GenerateMac` API.
7. **`aegis-server/src/main/scala/dev/aegiskms/app/ActorBackedKeyService.scala`** — route through
   the actor mailbox if state-mutating, or bypass it if read-only.
8. **`aegis-http/src/main/scala/dev/aegiskms/http/Endpoints.scala`** — add the Tapir endpoint
   `POST /v1/keys/{id}/mac`.
9. **`aegis-http/src/main/scala/dev/aegiskms/http/HttpRoutes.scala`** — wire the endpoint to
   the route.
10. **`aegis-cli/src/main/scala/dev/aegiskms/cli/{Cli,Commands}.scala`** — add the
    `aegis keys mac` verb.
11. **Tests across all of the above.** Aim for at least: an algebra test, a decorator test, a
    REST integration test, a CLI parser test.
12. **`CHANGELOG.md`** — under `## Unreleased`, an entry describing what shipped.

The existing `sign` / `verify` PR ([#5](https://github.com/sharma-bhaskar/aegis-kms/pull/5))
is the canonical reference for this pattern. Read its diff before opening a similar PR.

## 9. Adding a new RootOfTrust adapter

The minimum viable shape is a class that implements the SPI:

```scala
class GcpKmsRootOfTrust(client: KeyManagementServiceClient) extends RootOfTrust[IO]:
  def generateDataKey(spec: KeySpec): IO[Either[KmsError, WrappedKey]] = ???
  def unwrap(wrapped: WrappedKey): IO[Either[KmsError, RawKey]] = ???
  def sign(id: KeyId, message: Array[Byte], alg: SigAlgorithm): IO[Either[KmsError, Signature]] = ???
  // ... and the rest of the SPI
```

Then add a config-driven boot path in `Server.scala` so `AEGIS_ROT_KIND=gcp` selects it. New
adapters should ship with:

- A unit test using a fake / mock client
- A live integration test gated on env vars (skipped on CI without credentials)
- An entry in `docs/operations/security.md` describing the IAM permissions required
- A new line in the comparison table in `docs/about/comparison.md`

## 10. Adding a new audit sink

Implement `AuditSink`:

```scala
trait AuditSink:
  def emit(record: AuditRecord): IO[Unit]
```

Wire into `Server.scala` selectable by `AEGIS_AUDIT_KIND=stdout|kafka|s3|...`. The
`AuditingKeyService` decorator does not care which sink is on the other end — keep that
invariant.

## 11. Common debugging patterns

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `sbt server / run` hangs at boot | Pekko user-guardian + Promise pattern reintroduced | Make the ActorSystem be the actor (`ActorSystem[T] <: ActorRef[T]`) |
| `[error] No source compatibility issues found, but binary compatibility issues exist` | A change broke MiMa | Either restore binary compat, or add a justified entry to `mimaBinaryIssueFilters` |
| Test passes locally, fails on CI | Likely a Testcontainers test that runs on CI's Docker but skips locally without Docker | Run with Docker locally to repro |
| `[error] Imports are not in scalafmt order` | scalafmt and scalafix disagree on import sort | Run `sbt scalafmtAll` then `sbt scalafixAll`; if they fight each other, see §6 |
| Postgres test fails with `connection refused` on CI | Testcontainers couldn't pull the postgres image | Look at CI logs for image-pull rate-limiting; pin to a specific Postgres tag |
| `[error] -Wunused:all` flags an import as unused | Probably a `given` import that scalafix doesn't see used | Use `import x.y.given` style; if it's still flagged, add `// scalafix:ok ImportsRule` |
| Audit row missing context.source.ip | The HTTP layer doesn't yet populate `AuditRecord.context` | Known v0.1.1 limitation; tracked as a follow-up to issue #13 |

## 12. Pull request flow

1. Open or claim an issue. State your design before writing 500 lines.
2. Branch: `feat/<thing>` for features, `fix/<thing>` for bugs, `docs/<thing>` for docs.
3. Make commits small and atomic — one logical change per commit, DCO-signed.
4. CHANGELOG entry under `## Unreleased` lands in the same PR as the change.
5. Run the full local gate before pushing:
   ```bash
   sbt test scalafmtCheckAll scalafmtSbtCheck "scalafixAll --check" mimaReportBinaryIssues
   ```
6. Push, open the PR, link the issue.
7. CI runs the same gate against JDK 17 and JDK 21. Both must be green.
8. At least one maintainer review; design-impacting PRs need two.
9. Squash or rebase merge — the project keeps a linear history.

## 13. Releasing

Releases are tag-driven. The maintainer-facing runbook is in [RELEASING.md](https://github.com/sharma-bhaskar/aegis-kms/blob/main/RELEASING.md).
The short version:

```bash
# Promote ## Unreleased to ## X.Y.Z — date in CHANGELOG.md
git commit -s -m "chore(release): cut vX.Y.Z"
git push origin main
git tag -a vX.Y.Z -m "vX.Y.Z — short description"
git push origin vX.Y.Z
```

The tag push triggers `.github/workflows/release.yml`, which runs the full CI gate, then
publishes:

- Library jars to Maven Central (if PGP / Sonatype secrets are configured)
- `aegis-server` Docker image to GHCR
- CLI universal tarball to a GitHub Release with auto-generated notes

If Maven secrets aren't configured, the workflow logs `::notice::Skipping Maven Central
publish` and ships Docker + CLI only — that's the correct semantics for a non-publishing
maintainer.

## 14. Where to ask for help

- **GitHub Discussions** — design questions, "is this a good idea?", "how do I…?"
- **GitHub Issues** — bugs, feature requests, anything actionable
- **Email** — see [SECURITY.md](https://github.com/sharma-bhaskar/aegis-kms/blob/main/SECURITY.md) for security disclosures only
- **PRs** — best place to ask "would you accept this change?" by opening it as a draft

## 15. Reference docs in this repo

- [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) — the canonical architecture writeup, including
  the per-capability status table and how Aegis compares to AWS KMS / Vault / OpenBao.
- [`docs/USAGE.md`](../USAGE.md) — per-backend semantics, key lifecycle in practice.
- [`ROADMAP.md`](https://github.com/sharma-bhaskar/aegis-kms/blob/main/ROADMAP.md) —
  per-release delivery plan and capability tracks.
- [`CHANGELOG.md`](https://github.com/sharma-bhaskar/aegis-kms/blob/main/CHANGELOG.md) — under
  `## Unreleased`, update before opening a PR.
- [`CONTRIBUTING.md`](https://github.com/sharma-bhaskar/aegis-kms/blob/main/CONTRIBUTING.md) —
  the short-form ground rules.
- [`SECURITY.md`](https://github.com/sharma-bhaskar/aegis-kms/blob/main/SECURITY.md) —
  responsible disclosure + deploy-time configuration matrix.

---

*This guide is a living document. If anything here is wrong, out of date, or missing — open a
PR. The fastest way to make Aegis better for the next contributor is to fix what tripped you
up.*
