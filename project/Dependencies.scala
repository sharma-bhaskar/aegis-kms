import sbt._

object Dependencies {

  object V {
    val pekko          = "1.1.2"
    val pekkoHttp      = "1.1.0"
    val tapir          = "1.11.10"
    val circe          = "0.14.9"
    val cats           = "3.5.4"
    val doobie         = "1.0.0-RC12"
    val aws            = "2.28.10"
    val gcpKms         = "2.55.0"
    val azureKeyVault  = "4.9.2"
    val azureIdentity  = "1.14.2"
    val jjwt           = "0.12.6"
    val logback        = "1.5.8"
    val slf4j          = "2.0.16"
    val scalatest      = "3.2.19"
    val testcontainers = "0.41.4"
    val micrometer     = "1.13.6"
    val otel           = "1.42.1"
  }

  val core: Seq[ModuleID] = Seq(
    "org.typelevel" %% "cats-effect"   % V.cats,
    "io.circe"      %% "circe-core"    % V.circe,
    "io.circe"      %% "circe-generic" % V.circe,
    "io.circe"      %% "circe-parser"  % V.circe,
    "org.slf4j"      % "slf4j-api"     % V.slf4j
  )

  val pekkoHttp: Seq[ModuleID] = Seq(
    "org.apache.pekko" %% "pekko-actor-typed" % V.pekko,
    "org.apache.pekko" %% "pekko-stream"      % V.pekko,
    "org.apache.pekko" %% "pekko-http"        % V.pekkoHttp,
    "org.apache.pekko" %% "pekko-slf4j"       % V.pekko
  )

  /** Pekko Connectors Kafka (the Pekko fork of Alpakka Kafka) — server-tier only. Used by `KafkaAuditSink`
    * (#22). The transitive `kafka-clients` dependency drives the wire compat with the broker; we pin Pekko
    * Connectors Kafka 1.1.0 which is the release line that pairs with pekko 1.1.x.
    */
  val pekkoConnectorsKafka: Seq[ModuleID] = Seq(
    "org.apache.pekko" %% "pekko-connectors-kafka" % "1.1.0"
  )

  /** Official Java NATS client (`io.nats:jnats`) — used by `NatsAuditSink` (#23). JetStream support is in the
    * same jar; no separate dep.
    */
  val nats: Seq[ModuleID] = Seq(
    "io.nats" % "jnats" % "2.21.1"
  )

  /** Test-only deps for spinning up real Kafka / NATS brokers in Docker during integration tests. Same
    * skip-on-no-Docker pattern as `testcontainersPostgres`. Used by `KafkaAuditSinkSpec` (#22) and
    * `NatsAuditSinkSpec` (#23).
    */
  val testcontainersKafka: Seq[ModuleID] = Seq(
    "com.dimafeng" %% "testcontainers-scala-scalatest" % V.testcontainers % Test,
    "com.dimafeng" %% "testcontainers-scala-kafka"     % V.testcontainers % Test
  )

  val testcontainersNats: Seq[ModuleID] = Seq(
    "com.dimafeng" %% "testcontainers-scala-scalatest" % V.testcontainers % Test
  )

  /** Tapir endpoint definitions, JSON support, Pekko-HTTP interpreter, OpenAPI + Swagger UI. Used by the
    * server tier (`aegis-http`, `aegis-server`, `aegis-mcp-server`).
    */
  val tapir: Seq[ModuleID] = Seq(
    "com.softwaremill.sttp.tapir" %% "tapir-core"              % V.tapir,
    "com.softwaremill.sttp.tapir" %% "tapir-json-circe"        % V.tapir,
    "com.softwaremill.sttp.tapir" %% "tapir-pekko-http-server" % V.tapir,
    "com.softwaremill.sttp.tapir" %% "tapir-openapi-docs"      % V.tapir,
    "com.softwaremill.sttp.tapir" %% "tapir-swagger-ui-bundle" % V.tapir
  )

  val persistence: Seq[ModuleID] = Seq(
    "org.tpolecat" %% "doobie-core"           % V.doobie,
    "org.tpolecat" %% "doobie-postgres"       % V.doobie,
    "org.tpolecat" %% "doobie-postgres-circe" % V.doobie,
    "org.tpolecat" %% "doobie-hikari"         % V.doobie,
    // Drivers for the alternative SQL backends (#49 MySQL, #50 SQLite). The drivers are loaded
    // reflectively via `Class.forName` inside HikariCP / DriverManager when the corresponding
    // journal kind is wired in `Server.boot`; pure-Postgres deployments incur no runtime cost.
    "com.mysql"  % "mysql-connector-j" % "8.4.0",
    "org.xerial" % "sqlite-jdbc"       % "3.46.1.3"
  )

  /** Test-only dep for spinning up a real Postgres in Docker during integration tests. Pulls in
    * `org.testcontainers:postgresql` transitively. Tests using this should skip via `assume(...)` when Docker
    * isn't available so workstation runs of `sbt test` don't fail.
    */
  val testcontainersPostgres: Seq[ModuleID] = Seq(
    "com.dimafeng" %% "testcontainers-scala-scalatest"  % V.testcontainers % Test,
    "com.dimafeng" %% "testcontainers-scala-postgresql" % V.testcontainers % Test
  )

  /** Test-only dep for spinning up a real MySQL in Docker. Same skip-on-no-Docker pattern as
    * `testcontainersPostgres`. Used by `MysqlEventJournalSpec` (#49).
    */
  val testcontainersMysql: Seq[ModuleID] = Seq(
    "com.dimafeng" %% "testcontainers-scala-scalatest" % V.testcontainers % Test,
    "com.dimafeng" %% "testcontainers-scala-mysql"     % V.testcontainers % Test
  )

  /** Lettuce is the Java async Redis client. Single-jar dep — we use the lower-level `RedisCommands` (sync)
    * wrapped via `IO.blocking` so we don't bring in Reactor or Project Loom. Used by the Redis JWT revocation
    * list (#24) wired in `aegis-server`.
    */
  val redis: Seq[ModuleID] = Seq(
    "io.lettuce" % "lettuce-core" % "6.4.0.RELEASE"
  )

  /** Test-only dep for spinning up a real Redis in Docker during integration tests. */
  val testcontainersRedis: Seq[ModuleID] = Seq(
    "com.dimafeng" %% "testcontainers-scala-scalatest" % V.testcontainers % Test
  )

  val crypto: Seq[ModuleID] = Seq(
    "software.amazon.awssdk" % "kms" % V.aws
  )

  /** Google Cloud KMS client, for the `aegis-crypto-gcp` adapter.
    *
    * Deliberately NOT in [[crypto]]. `google-cloud-kms` pulls ~52 transitive jars (~45 MB of gRPC, protobuf,
    * Guava, and the GAX stack) — roughly doubling `aegis-crypto`, which is a library-tier module meant to
    * embed in any JVM app. Someone embedding it for the software or AWS backend should not ship the entire
    * Google Cloud client stack. Each vendor adapter therefore gets its own artifact; the SPI stays in
    * `aegis-crypto` and consumers depend only on the backends they actually use.
    */
  val cryptoGcp: Seq[ModuleID] = Seq(
    "com.google.cloud" % "google-cloud-kms" % V.gcpKms
  )

  /** Azure Key Vault client + credential chain, for the `aegis-crypto-azure` adapter. Same reasoning as
    * [[cryptoGcp]]: ~55 transitive jars (~28 MB), so it stays out of `aegis-crypto`.
    */
  val cryptoAzure: Seq[ModuleID] = Seq(
    "com.azure" % "azure-security-keyvault-keys" % V.azureKeyVault,
    "com.azure" % "azure-identity"               % V.azureIdentity
  )

  /** Deliberately empty. Vault's Transit engine is plain HTTP + JSON, so `aegis-crypto-vault` is built on the
    * JDK's own `HttpClient` and the circe already present via `aegis-core` — mirroring how `aegis-agent-ai`'s
    * `LlmHttp` talks to LLM providers. Adding a Vault driver would cost transitive weight for an API surface
    * of six endpoints that we would still have to wrap in a port seam for testing.
    */
  val cryptoVault: Seq[ModuleID] = Seq.empty

  /** Micrometer + Prometheus exposition. Server-tier only — wired into `aegis-server` by the metrics
    * decorator + `/metrics` route. The library-safe modules (`aegis-core`, `aegis-iam`, `aegis-audit`,
    * `aegis-persistence`, SDKs) MUST NOT pull this in: that would force any embedder to ship a metrics
    * library they may not want.
    */
  val metrics: Seq[ModuleID] = Seq(
    "io.micrometer" % "micrometer-core"                % V.micrometer,
    "io.micrometer" % "micrometer-registry-prometheus" % V.micrometer
  )

  /** OpenTelemetry SDK + OTLP exporter + autoconfigure. Server-tier only. The autoconfigure module reads
    * `OTEL_*` env vars and system properties to pick a sampler, exporter, resource attributes, etc. — so the
    * operator can wire to Jaeger / Tempo / OTel Collector without code changes. The
    * `opentelemetry-sdk-testing` artifact is test-scope and gives us `InMemorySpanExporter` for deterministic
    * span assertions.
    */
  val tracing: Seq[ModuleID] = Seq(
    "io.opentelemetry" % "opentelemetry-api"                         % V.otel,
    "io.opentelemetry" % "opentelemetry-sdk"                         % V.otel,
    "io.opentelemetry" % "opentelemetry-exporter-otlp"               % V.otel,
    "io.opentelemetry" % "opentelemetry-sdk-extension-autoconfigure" % V.otel,
    "io.opentelemetry" % "opentelemetry-sdk-testing"                 % V.otel % Test
  )

  /** JJWT (Java JWT) suite for issuing and verifying JWS tokens. Used by `aegis-iam` for the JWT bearer
    * `PrincipalResolver` and (in later PRs) for agent-token issuance.
    *
    * `jjwt-impl` and `jjwt-jackson` are loaded reflectively by jjwt-api at runtime; they MUST be on the
    * classpath. We declare them at Compile scope (rather than Runtime) so downstream test classpaths in other
    * modules pick them up via inter-project dependency — sbt's `Runtime` scope is local to the owning
    * project's test classpath only.
    */
  val jwt: Seq[ModuleID] = Seq(
    "io.jsonwebtoken" % "jjwt-api"     % V.jjwt,
    "io.jsonwebtoken" % "jjwt-impl"    % V.jjwt,
    "io.jsonwebtoken" % "jjwt-jackson" % V.jjwt
  )

  val logging: Seq[ModuleID] = Seq(
    "ch.qos.logback" % "logback-classic" % V.logback
  )

  val testing: Seq[ModuleID] = Seq(
    "org.scalatest"    %% "scalatest"                 % V.scalatest % Test,
    "org.apache.pekko" %% "pekko-actor-testkit-typed" % V.pekko     % Test,
    "org.apache.pekko" %% "pekko-stream-testkit"      % V.pekko     % Test,
    "org.apache.pekko" %% "pekko-http-testkit"        % V.pekkoHttp % Test
  )
}
