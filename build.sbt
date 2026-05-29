import Dependencies._

ThisBuild / scalaVersion     := "3.3.4"
ThisBuild / organization     := "dev.aegiskms"
ThisBuild / organizationName := "Aegis-KMS"
ThisBuild / homepage         := Some(url("https://aegiskms.dev"))
ThisBuild / licenses         := Seq("Apache-2.0" -> url("https://www.apache.org/licenses/LICENSE-2.0"))
// Maven Central staging requires a non-empty description on every published artifact. Each module
// overrides this in its own `.settings(...)` block with its specific summary; this `ThisBuild`
// fallback prevents an unnamed jar from failing the staging gate if a per-module override is ever
// removed by accident.
ThisBuild / description :=
  "Aegis-KMS — agent-native key management. Identity, intelligence, and real-time control in front of your existing KMS."
ThisBuild / developers := List(
  Developer("bhaskar", "Bhaskar Sharma", "sharma.b6@gmail.com", url("https://github.com/sharma-bhaskar"))
)
ThisBuild / scmInfo := Some(
  ScmInfo(
    browseUrl = url("https://github.com/sharma-bhaskar/aegis-kms"),
    connection = "scm:git:https://github.com/sharma-bhaskar/aegis-kms.git"
  )
)
// Versioning is delegated to sbt-dynver (pulled in by sbt-ci-release): on a `v<X.Y.Z>` tag the
// version becomes `<X.Y.Z>`; between tags it's `<base>+<n>-<sha>-SNAPSHOT`. Setting `version :=`
// here would OVERRIDE the dynver-derived value and break Maven Central publishing — we'd push
// every tag as `0.1.0-SNAPSHOT` regardless of the tag name. Don't reintroduce a `version :=`.
ThisBuild / sonatypeCredentialHost := "s01.oss.sonatype.org"
ThisBuild / scalacOptions ++= Seq(
  "-deprecation",
  "-feature",
  "-Xfatal-warnings",
  "-Wunused:all"
)

inThisBuild(
  List(
    scalaVersion      := "3.3.4",
    semanticdbEnabled := true,
    semanticdbVersion := scalafixSemanticdb.revision
  )
)

// Force every Pekko artifact to the same version. Pekko's ManifestInfo runtime check refuses to start an
// ActorSystem if mixed versions are detected — Tapir's transitive deps pull a newer pekko-stream than our
// pinned pekko-actor-typed otherwise.
ThisBuild / dependencyOverrides ++= Seq(
  "org.apache.pekko" %% "pekko-actor"               % Dependencies.V.pekko,
  "org.apache.pekko" %% "pekko-actor-typed"         % Dependencies.V.pekko,
  "org.apache.pekko" %% "pekko-actor-testkit-typed" % Dependencies.V.pekko,
  "org.apache.pekko" %% "pekko-stream"              % Dependencies.V.pekko,
  "org.apache.pekko" %% "pekko-stream-testkit"      % Dependencies.V.pekko,
  "org.apache.pekko" %% "pekko-protobuf-v3"         % Dependencies.V.pekko,
  "org.apache.pekko" %% "pekko-slf4j"               % Dependencies.V.pekko
)

lazy val commonSettings = Seq(
  libraryDependencies ++= logging ++ Dependencies.testing,
  Test / fork := true
)

// ── Library-safe tier: no Pekko, usable as a dependency by anyone ──
lazy val core = (project in file("modules/aegis-core"))
  .settings(
    commonSettings,
    name := "aegis-core",
    description :=
      "Pure-Scala domain layer: KeyService[F[_]] algebra, ManagedKey, KmsError, Principal, KeyEvent.",
    libraryDependencies ++= Dependencies.core
  )

lazy val persistence = (project in file("modules/aegis-persistence"))
  .dependsOn(core)
  .settings(
    commonSettings,
    name := "aegis-persistence",
    description :=
      "Doobie-backed event journal for Aegis-KMS. Postgres / MySQL / SQLite impls + an in-memory variant for tests.",
    libraryDependencies ++= Dependencies.persistence ++ Dependencies.testcontainersPostgres ++ Dependencies.testcontainersMysql
  )

lazy val crypto = (project in file("modules/aegis-crypto"))
  .dependsOn(core)
  .settings(
    commonSettings,
    name := "aegis-crypto",
    description :=
      "Root-of-Trust SPI for Aegis-KMS plus the AWS KMS adapter (layered-mode key generation, sign / verify, encrypt / decrypt, wrap / unwrap).",
    libraryDependencies ++= Dependencies.crypto
  )

lazy val iam = (project in file("modules/aegis-iam"))
  .dependsOn(core, persistence)
  .settings(
    commonSettings,
    name := "aegis-iam",
    description :=
      "Identity + authorization for Aegis-KMS: Principal model, role-based policy engine, JWT issuer/verifier, agent-token issuance.",
    libraryDependencies ++= Dependencies.jwt
  )

lazy val audit = (project in file("modules/aegis-audit"))
  .dependsOn(core, persistence)
  .settings(
    commonSettings,
    name := "aegis-audit",
    description :=
      "Append-only audit sink SPI for Aegis-KMS plus the stdout / in-memory / Postgres implementations.",
    // Doobie is available transitively via `persistence`, but the Postgres audit sink (#19) reads
    // doobie types in its own .scala file — declaring them explicitly here makes the dependency
    // load-bearing rather than incidental.
    libraryDependencies ++= Dependencies.persistence ++ Dependencies.testcontainersPostgres
  )

lazy val sdkScala = (project in file("modules/aegis-sdk-scala"))
  .dependsOn(core)
  .settings(
    commonSettings,
    name        := "aegis-sdk-scala",
    description := "Scala client SDK for the Aegis-KMS REST surface. No Pekko / pekko-http dependency."
  )

lazy val sdkJava = (project in file("modules/aegis-sdk-java"))
  .dependsOn(sdkScala)
  .settings(
    commonSettings,
    name := "aegis-sdk-java",
    description := "Java-friendly facade over `aegis-sdk-scala`. Pure JDK; no Scala in the consumer's classpath beyond the runtime.",
    autoScalaLibrary := false
  )

// ── Server tier: depends on Pekko ──
lazy val kmip = (project in file("modules/aegis-kmip"))
  .dependsOn(core, crypto, iam, audit)
  .settings(
    commonSettings,
    name := "aegis-kmip",
    description :=
      "KMIP TTLV codec + TLS 1.3 server for Aegis-KMS. Storage vendors, database TDE, backup products. (skeleton in v0.1.x; full implementation in v0.4.0)",
    libraryDependencies ++= pekkoHttp
  )

lazy val http = (project in file("modules/aegis-http"))
  .dependsOn(core, crypto, iam, audit)
  .settings(
    commonSettings,
    name := "aegis-http",
    description :=
      "REST plane for Aegis-KMS: Tapir endpoint definitions + pekko-http interpreter, OpenAPI 3.1 + Swagger UI on /docs.",
    libraryDependencies ++= pekkoHttp ++ Dependencies.tapir
  )

lazy val agentAi = (project in file("modules/aegis-agent-ai"))
  .dependsOn(core, iam, audit)
  .settings(
    commonSettings,
    name := "aegis-agent-ai",
    description :=
      "Risk scorer / anomaly detector / auto-responder / LLM advisor for Aegis-KMS. Drives the agent-governance wedge.",
    libraryDependencies ++= pekkoHttp
  )

lazy val mcpServer = (project in file("modules/aegis-mcp-server"))
  .dependsOn(core, iam, http)
  .settings(
    commonSettings,
    name := "aegis-mcp-server",
    description :=
      "Model Context Protocol server exposing Aegis-KMS as a curated tool surface for LLM clients (Claude, GPT, …). (skeleton in v0.1.x; full implementation in v0.4.0)",
    libraryDependencies ++= pekkoHttp
  )

lazy val server = (project in file("modules/aegis-server"))
  .dependsOn(kmip, http, mcpServer, agentAi, iam, audit, persistence, crypto)
  .enablePlugins(JavaAppPackaging, DockerPlugin)
  .settings(
    commonSettings,
    name := "aegis-server",
    description :=
      "Standalone Aegis-KMS server: wires HTTP / KMIP / MCP / Agent-AI planes around the audited KeyService. Published as a Docker image, not a Maven library.",
    publish / skip := true, // server is shipped as a Docker image, not a Maven artifact
    libraryDependencies ++=
      pekkoHttp ++ Dependencies.tapir ++ Dependencies.metrics ++ Dependencies.tracing ++
        Dependencies.redis ++ Dependencies.testcontainersRedis,
    Docker / packageName := "aegis-server",
    dockerBaseImage      := "eclipse-temurin:21-jre",
    // Fork `sbt 'server/run'` into its own JVM. Without this, sbt's in-process classloader and
    // thread group interfere with Pekko's user-guardian dispatcher and the `Await.result` on the
    // initialization promise hangs indefinitely on cold start.
    run / fork         := true,
    run / connectInput := true,
    run / javaOptions ++= Seq("-Xms256m", "-Xmx1g")
  )

lazy val cli = (project in file("modules/aegis-cli"))
  .dependsOn(sdkScala)
  .enablePlugins(JavaAppPackaging, BuildInfoPlugin)
  .settings(
    commonSettings,
    name := "aegis-cli",
    description :=
      "`aegis` admin CLI for Aegis-KMS. Distributed as a tarball attached to GitHub Releases, not a Maven library.",
    publish / skip := true, // CLI is shipped as a Universal tarball, not a Maven artifact
    // The published launcher should be `bin/aegis`, matching the README and the way users will
    // invoke it (`aegis keys create ...`). sbt-native-packager defaults to `bin/<name>` which
    // would produce `bin/aegis-cli`.
    executableScriptName      := "aegis",
    buildInfoKeys             := Seq[BuildInfoKey](version, scalaVersion),
    buildInfoPackage          := "dev.aegiskms.cli",
    buildInfoObject           := "BuildInfo",
    buildInfoUsePackageAsPath := true
  )

lazy val root = (project in file("."))
  .aggregate(
    core,
    persistence,
    crypto,
    iam,
    audit,
    sdkScala,
    sdkJava,
    kmip,
    http,
    agentAi,
    mcpServer,
    server,
    cli
  )
  .settings(
    publish / skip := true,
    name           := "aegis-kms"
  )
