import Dependencies._

ThisBuild / scalaVersion     := "3.3.4"
ThisBuild / organization     := "dev.aegiskms"
ThisBuild / organizationName := "Aegis-KMS"
ThisBuild / homepage         := Some(url("https://aegiskms.dev"))
ThisBuild / licenses         := Seq("Apache-2.0" -> url("https://www.apache.org/licenses/LICENSE-2.0"))
ThisBuild / developers := List(
  Developer("bhaskar", "Bhaskar Sharma", "sharma.b6@gmail.com", url("https://github.com/sharma-bhaskar"))
)
ThisBuild / version := "0.1.0-SNAPSHOT"
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
  .settings(commonSettings, name := "aegis-core", libraryDependencies ++= Dependencies.core)

lazy val persistence = (project in file("modules/aegis-persistence"))
  .dependsOn(core)
  .settings(
    commonSettings,
    name := "aegis-persistence",
    libraryDependencies ++= Dependencies.persistence ++ Dependencies.testcontainersPostgres
  )

lazy val crypto = (project in file("modules/aegis-crypto"))
  .dependsOn(core)
  .settings(commonSettings, name := "aegis-crypto", libraryDependencies ++= Dependencies.crypto)

lazy val iam = (project in file("modules/aegis-iam"))
  .dependsOn(core, persistence)
  .settings(commonSettings, name := "aegis-iam", libraryDependencies ++= Dependencies.jwt)

lazy val audit = (project in file("modules/aegis-audit"))
  .dependsOn(core, persistence)
  .settings(commonSettings, name := "aegis-audit")

lazy val sdkScala = (project in file("modules/aegis-sdk-scala"))
  .dependsOn(core)
  .settings(commonSettings, name := "aegis-sdk-scala")

lazy val sdkJava = (project in file("modules/aegis-sdk-java"))
  .dependsOn(sdkScala)
  .settings(commonSettings, name := "aegis-sdk-java", autoScalaLibrary := false)

// ── Server tier: depends on Pekko ──
lazy val kmip = (project in file("modules/aegis-kmip"))
  .dependsOn(core, crypto, iam, audit)
  .settings(commonSettings, name := "aegis-kmip", libraryDependencies ++= pekkoHttp)

lazy val http = (project in file("modules/aegis-http"))
  .dependsOn(core, crypto, iam, audit)
  .settings(
    commonSettings,
    name := "aegis-http",
    libraryDependencies ++= pekkoHttp ++ Dependencies.tapir
  )

lazy val agentAi = (project in file("modules/aegis-agent-ai"))
  .dependsOn(core, iam, audit)
  .settings(commonSettings, name := "aegis-agent-ai", libraryDependencies ++= pekkoHttp)

lazy val mcpServer = (project in file("modules/aegis-mcp-server"))
  .dependsOn(core, iam, http)
  .settings(commonSettings, name := "aegis-mcp-server", libraryDependencies ++= pekkoHttp)

lazy val server = (project in file("modules/aegis-server"))
  .dependsOn(kmip, http, mcpServer, agentAi, iam, audit, persistence, crypto)
  .enablePlugins(JavaAppPackaging, DockerPlugin)
  .settings(
    commonSettings,
    name := "aegis-server",
    libraryDependencies ++= pekkoHttp ++ Dependencies.tapir,
    Docker / packageName := "aegis-server",
    dockerBaseImage      := "eclipse-temurin:21-jre"
  )

lazy val cli = (project in file("modules/aegis-cli"))
  .dependsOn(sdkScala)
  .enablePlugins(JavaAppPackaging)
  .settings(commonSettings, name := "aegis-cli")

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
