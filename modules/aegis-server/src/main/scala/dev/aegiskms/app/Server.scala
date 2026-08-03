package dev.aegiskms.app

import cats.effect.unsafe.IORuntime
import cats.effect.{IO, IOApp, IOLocal, Resource}
import cats.syntax.all.*
import com.typesafe.config.{Config, ConfigFactory}
import dev.aegiskms.agent.{
  AdvisorService,
  AutoResponder,
  BaselineDetector,
  BaselineRiskScorer,
  HoneyKeyRegistry,
  InMemoryRecommendationSink,
  LlmClient,
  LlmHttp,
  TappedAuditSink,
  ThresholdDecisionEngine
}
import dev.aegiskms.audit.{
  AuditQuery,
  AuditSink,
  AuditingKeyService,
  FanOutAuditSink,
  PostgresAuditSink,
  RequestContext,
  StdoutAuditSink
}
import dev.aegiskms.crypto.RootOfTrust
import dev.aegiskms.crypto.aws.AwsKmsRootOfTrust
import dev.aegiskms.crypto.software.SoftwareRootOfTrust
import dev.aegiskms.http.HttpRoutes
import dev.aegiskms.iam.{
  AgentTokenIssuer,
  AuthorizingKeyService,
  JwtIssuer,
  JwtVerifier,
  OidcJwtVerifier,
  PolicyEngine,
  PrincipalResolver,
  RevocationAwareJwtVerifier,
  RevocationList,
  RoleBasedPolicyEngine
}
import dev.aegiskms.persistence.{
  EventJournal,
  MysqlEventJournal,
  MysqlJournalConfig,
  PostgresEventJournal,
  PostgresJournalConfig,
  SqliteEventJournal,
  SqliteJournalConfig
}
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import org.apache.pekko.actor.typed.{ActorSystem, Scheduler}
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.Http.ServerBinding
import org.apache.pekko.http.scaladsl.server.Directives.concat
import org.apache.pekko.util.Timeout
import org.slf4j.LoggerFactory

import java.nio.file.Paths
import scala.concurrent.duration.*

/** Standalone entry point for Aegis-KMS.
  *
  * The wiring stack from outermost to innermost is:
  *   - `HttpRoutes` — extracts `Principal` from `X-Aegis-User`, parses path params
  *   - `AuditingKeyService` — writes one `AuditRecord` per call (incl. denies + errors)
  *   - `MeteredKeyService` — records counter + latency timer + error counter per operation
  *   - `AuthorizingKeyService` — consults the configured `PolicyEngine` ([[DevPolicyEngine]] or
  *     [[dev.aegiskms.iam.RoleBasedPolicyEngine]] per `aegis.policy.kind`) before delegating
  *   - `ActorBackedKeyService` — adapts ask-pattern → `KeyService[IO]`
  *   - `KeyOpsActor` — the single actor that owns the live state map
  *   - `EventJournal` — append-only log; replayed on boot to rebuild state
  *
  * Decorator order matters: audit OUTSIDE auth so denied calls still produce audit records. Audit OUTSIDE the
  * actor so audit writes never block on the actor's mailbox. Metrics sit between audit and auth so the
  * per-operation error counter surfaces denies tagged `code=PermissionDenied`.
  *
  * The audit sink is composed: every record is fanned out to `StdoutAuditSink` (so `aegis-server` produces
  * the README's demo transcript on stdout) and through a `TappedAuditSink` to drive the W1 anomaly detector.
  * The detector publishes recommendations into an `InMemoryRecommendationSink` for now; later PRs (W3, W3.b)
  * replace that with the auto-responder + webhook fan-out.
  *
  * **Boot scope.** The whole server is composed as a single `Resource[IO, ServerHandle]`. Each acquired piece
  * — meter registry, journal connection pool, actor system, HTTP binding — has a matching finalizer that runs
  * in reverse acquisition order on cancellation. On SIGTERM / SIGINT the cats-effect runtime cancels
  * `IO.never`, which walks the finalizer chain: HTTP unbind → actor system terminate → journal pool close →
  * meter registry close. This replaces the v0.1.0 boot path that called `unsafeRunSync` on the journal
  * Resource and discarded its finalizer (i.e. relied on JVM exit to release the pool).
  *
  * Productionising checklist (deferred to later PRs):
  *   - Bind KMIP TTLV + MCP servers in addition to HTTP (PRs K1, A1)
  */
object Server extends IOApp.Simple:

  private val logger = LoggerFactory.getLogger(getClass)

  private given Timeout = 5.seconds

  /** `IOApp.Simple` runs `program` and registers a SIGTERM/SIGINT handler that cancels it. The `Resource`
    * chain inside `boot` walks finalizers in reverse on cancellation, so the binding unbinds before the actor
    * terminates before the journal pool closes.
    */
  def run: IO[Unit] =
    // `IOApp.Simple` exposes the cats-effect `IORuntime` as `protected def runtime`. We thread it
    // into implicit scope so `boot`'s `using IORuntime` parameter resolves — the actor's
    // `appendOr` helper still calls `journal.append(event).unsafeRunSync()` and needs a runtime.
    given IORuntime = runtime
    IO(ConfigFactory.load()).flatMap(rootConfig => boot(rootConfig).useForever)

  /** The composed boot scope. Each acquisition is paired with its finalizer; `IOApp` cancels this whole
    * `Resource` on SIGTERM/SIGINT, and the cats-effect runtime walks the chain in reverse.
    */
  def boot(rootConfig: Config)(using IORuntime): Resource[IO, Unit] =
    val host = rootConfig.getString("aegis.http.host")
    val port = rootConfig.getInt("aegis.http.port")

    for
      // 0. Production preflight (#99): cross-checks the bind address against dev-grade settings
      //    (dev auth, dev policy, in-memory crypto/journal). `warn` (default) prints a banner;
      //    `enforce` aborts the boot before any resource is acquired.
      _ <- Resource.eval(Preflight.run(rootConfig))

      // 1. Meter registry. Standard JVM binders are AutoCloseable (the JvmGcMetrics binder installs JMX
      //    listeners) so we close it on shutdown.
      metricsRegistry <- meterRegistryResource

      // 1b. OpenTelemetry SDK from `OTEL_*` env vars / system properties. With no exporter configured
      //     the autoconfigure default (`otlp`) silently buffers and drops; set
      //     `OTEL_TRACES_EXPORTER=none` for unambiguous local-dev silence. See `TracingRegistry`'s doc
      //     for the full env-var matrix. The SDK is an `OpenTelemetrySdk` (`AutoCloseable`), so the
      //     Resource finalizer flushes pending spans on shutdown.
      openTelemetry <- tracingResource
      tracer = TracingRegistry.tracerFor(openTelemetry)

      // 2. Journal connection pool (or in-memory ref). Closing returns the Postgres pool to its
      //    finalizer; in-memory has no finalizer.
      journal <- journalResource(rootConfig)

      // 3. Actor system. Pekko Typed's `ActorSystem[T]` itself implements `ActorRef[T]` for the user
      //    guardian — see KeyOpsActor docs. `terminate()` returns a Future[Terminated]; we bridge.
      system <- actorSystemResource(journal, rootConfig)
      given ActorSystem[KeyOpsActor.Command] = system
      given Scheduler                        = system.scheduler

      // 3b. Root of Trust. `aegis.crypto.kind=in-memory` (default) uses the deterministic-MAC
      //     dev backend — NOT a real KMS. `aegis.crypto.kind=aws-kms` uses `AwsKmsRootOfTrust`
      //     with a Resource-managed `KmsClient` (closed on SIGTERM). The choice happens here so
      //     ActorBackedKeyService stays unaware of which backend it's talking to.
      rootOfTrust <- rootOfTrustResource(rootConfig)

      // 4. Decorate. Auth → metrics → tracing → audit; see the class docstring for why this order
      //    matters. Tracing sits between metrics and audit so the trace span measures auth + actor
      //    + journal as one unit; metrics record their own (smaller) timer next to it; audit stays
      //    the outermost layer so the audit row reflects the post-trace outcome.
      actorBacked = new ActorBackedKeyService(system, rootOfTrust)
      // Policy engine (#77): `aegis.policy.kind=dev` (default) keeps the permissive
      // `DevPolicyEngine` so the workstation demo + existing tests keep working unchanged.
      // `aegis.policy.kind=role-based` activates `RoleBasedPolicyEngine` with bindings loaded
      // from HOCON; boot fails fast if both binding maps are empty so a misconfigured
      // production deployment can't silently become "deny-all" or accidentally "allow-all".
      policyEngine <- Resource.eval(buildPolicyEngine(rootConfig))
      authorizing = new AuthorizingKeyService(actorBacked, policyEngine)
      metered     = new MeteredKeyService(authorizing, metricsRegistry)
      traced      = new TracingKeyService(metered, tracer)
      recStore <- Resource.eval(InMemoryRecommendationSink.make)
      // Honey key (canary) registry (#26). Parsed from `aegis.security.honey-keys` HOCON list
      // (or AEGIS_HONEY_KEYS comma-separated env override). Empty by default — production
      // deployments opt in explicitly. Threaded into BaselineDetector.make so the 6th detector
      // can short-circuit any agent op against a marked key into a High-severity Revoke.
      honeyKeys = buildHoneyKeyRegistry(rootConfig)
      detector <- Resource.eval(BaselineDetector.make(honeyKeys = honeyKeys))
      // Audit sink (#19): `aegis.audit.kind=stdout` (default) writes to console; `postgres`
      // persists to the indexed `aegis_audit_events` table backing the audit-read API (#20).
      // `stdoutSink` is kept as the variable name across both modes so the existing references
      // downstream (auto-responder, HttpRoutes auditSink) stay readable — only the impl changes.
      primarySink <- auditSinkResource(rootConfig)
      // Optional streaming audit fan-outs: SIEM webhook (#21), Kafka (#22), NATS JetStream
      // (#23). Each kind opts in via its own `aegis.audit.<kind>.enabled=true` flag. Primary
      // failures still propagate (durability); secondary failures are bounded by per-sink
      // retry + dead-letter (best-effort). `FanOutAuditSink.of` returns the primary as-is when
      // the secondaries list is empty, so the non-fan-out path stays zero-cost.
      webhookSinks <- webhookAuditSinkResource(rootConfig)
      kafkaSinks   <- kafkaAuditSinkResource(rootConfig)
      natsSinks    <- natsAuditSinkResource(rootConfig)
      stdoutSink = FanOutAuditSink.of(primarySink, webhookSinks ++ kafkaSinks ++ natsSinks)
      // Auto-responder (#17 / W3): decorates the recommendation sink. Every recommendation is first
      // persisted to `recStore` (full alert history retained), then matched against `DefaultRules`
      // (High → Revoke, Medium → Alert), then executed with a per-(actor,action) 60 s cooldown. The
      // responder calls `traced` directly — bypassing the outer Auditing decorator on purpose so a
      // revoke action doesn't recurse through the detector. It writes its own audit row to
      // `stdoutSink` with `actor = AutoResponder.SystemPrincipal` so operators can grep the timeline.
      autoResponder <- Resource.eval(
        AutoResponder.make(
          rules = AutoResponder.DefaultRules,
          inner = recStore,
          keyService = traced,
          auditSink = stdoutSink
        )
      )
      sink = TappedAuditSink(stdoutSink, detector, autoResponder)
      // Risk scorer (#15 / W2): reads the same baseline state the tapped sink writes into. Every audit
      // record gets `risk.score` + `risk.factors` stamped.
      riskScorer = BaselineRiskScorer.make(detector)
      // Decision adapter (#16 / W2.b): translates score → Allow / StepUp / Deny. Default thresholds
      // (deny=0.85, stepUp=0.60, destructiveOpOffset=0.15) mean a single high-weight factor trips
      // step-up, a composite trips deny, and destructive ops (Rotate / Compromise / Destroy / Revoke)
      // are gated harder by 0.15. Operator-tuned thresholds via HOCON land later.
      decisionEngine = ThresholdDecisionEngine.make()
      // Per-request context bag (#78). The HTTP layer stamps `source.ip` onto this IOLocal as
      // the first IO step of each request; `AuditingKeyService` reads it back via `current` and
      // merges it into `AuditRecord.context`, activating the `SourceIpBaseline` detector. Both
      // ends MUST share the same `IOLocal` — separate locals would leave the read empty.
      sourceContextLocal <- Resource.eval(IOLocal(Map.empty[String, String]))
      reqContext = RequestContext.fromIOLocal(sourceContextLocal)
      auditing = new AuditingKeyService(
        traced,
        sink,
        Some(riskScorer),
        Some(decisionEngine),
        reqContext
      )

      // JWT revocation list (#24). Selected by `aegis.iam.revocation.kind`:
      //   - `none`      → no-op; tokens revoke only when they expire naturally.
      //   - `in-memory` → process-local Ref-backed list; suits dev/single-node, lost on restart.
      //   - `redis`     → durable, multi-node. Closes the auto-responder's kill-switch story.
      // The list is wrapped around whatever inner verifier `buildResolver` constructs (HMAC /
      // OIDC) via `RevocationAwareJwtVerifier`. Dev resolver (no JWT) bypasses the list.
      revocation <- revocationListResource(rootConfig)
      resolver   <- Resource.eval(buildResolver(rootConfig, revocation))
      // Agent-token issuer (#18). Needs a JwtIssuer with the HMAC secret. We share the same secret
      // the verifier uses when `aegis.auth.kind=hmac`; in dev mode we mint a stable per-boot secret
      // (logged below) so the demo can issue + verify agent tokens within a single server lifetime.
      // The "dev mode self-issued tokens" approach is deliberate — it lets newcomers exercise the
      // wedge demo with real Agent principals without standing up an OIDC IDP. PR #25 replaces this
      // with proper OIDC + JWKS rotation.
      agentIssuer <- Resource.eval(buildAgentIssuer(rootConfig))

      // Audit-read capability (#20) + advisor scan (#28) both ride on the `AuditQuery` SPI, which only the
      // *primary* postgres sink satisfies. Match on `primarySink`, not `stdoutSink`, because the latter may
      // be wrapped in a `FanOutAuditSink` for the webhook fan-out (#21) that doesn't carry the capability.
      auditReader = primarySink match
        case q: AuditQuery[IO @unchecked] => Some(q)
        case _                            => None

      // Advisor LLM provider (#30): selected from `aegis.advisor.llm.*` (provider=none disables narration).
      // `advisor explain` (#29) uses it; `advisor scan` is deterministic and ignores it.
      llmClient = buildLlmClient(rootConfig)

      // 5. HTTP binding. Acquire = bind; release = unbind with the configured grace period (5s) so
      //    in-flight requests finish before the socket closes.
      appRoute =
        concat(
          // `auditSink = Some(stdoutSink)` so `/v1/agents/issue` records a forensic trail of every
          // agent credential minted (the keys surface is already covered by `AuditingKeyService`
          // wrapping `traced`, but agent issuance is not on the `KeyService` algebra and would
          // otherwise be invisible to operators).
          // Audit-read endpoint (#20): only wired when the *primary* sink is a `PostgresAuditSink`
          // (the only impl that satisfies the `AuditQuery` SPI). Match on `primarySink`, not
          // `stdoutSink`, because `stdoutSink` may have been wrapped in `FanOutAuditSink` for the
          // webhook fan-out (#21) and that wrapper does NOT carry the AuditQuery capability.
          HttpRoutes(
            auditing,
            resolver,
            Some(agentIssuer),
            Some(stdoutSink),
            auditReader,
            reqContext,
            auditReader.map(r => AdvisorService.deterministic(r, llmClient))
          ).routes,
          MetricsRoutes.route(metricsRegistry)
        )
      _ <- httpBindingResource(host, port, appRoute)
      _ <- Resource.eval(IO {
        logger.info(s"aegis-server listening on http://$host:$port (try POST /v1/keys)")
        logger.info(s"docs:    http://$host:$port/docs/  (Swagger UI; OpenAPI YAML at /docs/docs.yaml)")
        logger.info(s"metrics: http://$host:$port/metrics (Prometheus exposition format)")
        logger.info(
          "tracing: OTel SDK initialised (configure via OTEL_* env vars; OTEL_TRACES_EXPORTER=none disables)"
        )
        logger.info("audit feed → stdout; recommendations → in-memory sink (visible via /admin in PR W1.b)")
      })
    yield ()

  // ── Resource builders ──────────────────────────────────────────────────────

  /** Meter registry as a Resource. The standard JVM binders attached by `MetricsRegistry.make` keep JMX
    * listeners alive; closing the registry releases them.
    */
  private def meterRegistryResource: Resource[IO, PrometheusMeterRegistry] =
    Resource.make(IO(MetricsRegistry.make()))(r => IO(r.close()))

  /** OpenTelemetry SDK as a Resource. `AutoConfiguredOpenTelemetrySdk` returns an `OpenTelemetrySdk` which is
    * `AutoCloseable`; closing it flushes pending spans + shuts down the exporter so SIGTERM doesn't drop
    * in-flight traces. We pattern-match the returned `OpenTelemetry` to recover the SDK instance — it's
    * always the SDK, but the API type is widened.
    */
  private def tracingResource: Resource[IO, io.opentelemetry.api.OpenTelemetry] =
    Resource.make(IO(TracingRegistry.make())) {
      case sdk: io.opentelemetry.sdk.OpenTelemetrySdk =>
        IO(sdk.close()).handleErrorWith(t =>
          IO(logger.warn(s"OpenTelemetry SDK shutdown reported error: ${t.getMessage}", t))
        )
      case _ => IO.unit
    }

  /** Journal as a Resource. The Postgres/MySQL/SQLite paths return real `Resource[IO, EventJournal[IO]]`
    * whose finalizers close the connection pool. The in-memory path has nothing to close, so we lift it with
    * `Resource.eval`.
    */
  private def journalResource(config: Config): Resource[IO, EventJournal[IO]] =
    config.getString("aegis.persistence.journal.kind") match
      case "in-memory" =>
        Resource.eval(IO {
          logger.info(
            "journal: in-memory (state is non-durable; set aegis.persistence.journal.kind=postgres for production)"
          )
        }) *> Resource.eval(EventJournal.inMemory)
      case "postgres" =>
        val pgConfig = readPostgresJournalConfig(config)
        Resource.eval(IO {
          logger.info(s"journal: postgres at ${pgConfig.jdbcUrl} (pool-size=${pgConfig.poolSize})")
        }) *> PostgresEventJournal.make(pgConfig)
      case "mysql" =>
        val myConfig = readMysqlJournalConfig(config)
        Resource.eval(IO {
          logger.info(s"journal: mysql at ${myConfig.jdbcUrl} (pool-size=${myConfig.poolSize})")
        }) *> MysqlEventJournal.make(myConfig)
      case "sqlite" =>
        val sqlConfig = readSqliteJournalConfig(config)
        Resource.eval(IO {
          logger.info(s"journal: sqlite at ${sqlConfig.jdbcUrl} (pool-size=1, forced)")
        }) *> SqliteEventJournal.make(sqlConfig)
      case other =>
        Resource.eval(IO.raiseError(new IllegalArgumentException(
          s"Unknown aegis.persistence.journal.kind=$other " +
            "(expected 'in-memory', 'postgres', 'mysql', or 'sqlite')"
        )))

  /** Root-of-Trust as a Resource — the crypto backend that does the actual sign / verify / wrap / unwrap work
    * behind `KeyService`.
    *
    *   - `aegis.crypto.kind=in-memory` (default) — deterministic-MAC dev backend. **Not a real KMS** —
    *     signatures are HMAC(KeyId, msg), encryption is XOR-with-stream. Suitable for local development, the
    *     wedge demo, and integration tests; never for production data.
    *   - `aegis.crypto.kind=software` — `SoftwareRootOfTrust`: real AES-256-GCM / RSA-PSS / ECDSA from the
    *     JDK's own JCE providers, keyed from a PKCS#12 keystore. Real cryptography with no cloud account, so
    *     it is the right choice for CI and for evaluating Aegis without AWS credentials. **Still not
    *     production** — key material lives in this JVM's heap; `Preflight` flags it accordingly.
    *   - `aegis.crypto.kind=aws-kms` — `AwsKmsRootOfTrust` against the configured AWS region with a
    *     Resource-managed `KmsClient` (closed on SIGTERM). Requires `aegis.crypto.aws-kms.region` and
    *     `aegis.crypto.aws-kms.kek-arn` to be set; the AWS SDK's default credential provider chain handles
    *     authentication (env vars, instance metadata, SSO, etc. — see the AWS SDK docs).
    *
    * GCP / Azure / Vault / PKCS#11 adapters are roadmapped for v0.3.0 / v0.4.0; until they ship, this method
    * only knows about `in-memory`, `software`, and `aws-kms`. Misconfiguration fails fast at boot — silent
    * fallback to a dev backend would be a security hole.
    */
  private def rootOfTrustResource(config: Config): Resource[IO, RootOfTrust[IO]] =
    config.getString("aegis.crypto.kind") match
      case "in-memory" =>
        Resource.eval(IO {
          logger.warn(
            "crypto: in-memory (deterministic-MAC dev backend — NOT a real KMS). " +
              "Set aegis.crypto.kind=aws-kms (with aegis.crypto.aws-kms.{region,kek-arn}) for production."
          )
          RootOfTrust.inMemory
        })
      case "software" =>
        val path     = config.getString("aegis.crypto.software.keystore-path").trim
        val password = config.getString("aegis.crypto.software.keystore-password")
        if path.nonEmpty && password.isEmpty then
          Resource.eval(IO.raiseError(new IllegalArgumentException(
            "aegis.crypto.software.keystore-path is set but keystore-password is empty " +
              "(set AEGIS_CRYPTO_SOFTWARE_KEYSTORE_PASSWORD)"
          )))
        else
          val cfg = SoftwareRootOfTrust.Config(
            keystorePath = Option.when(path.nonEmpty)(Paths.get(path)),
            keystorePassword = password
          )
          Resource.eval(IO(logger.info(
            s"crypto: software (keystore=${if path.isEmpty then "ephemeral" else path})"
          ))) *> SoftwareRootOfTrust.resource(cfg).widen
      case "aws-kms" =>
        val region = config.getString("aegis.crypto.aws-kms.region")
        val kekArn = config.getString("aegis.crypto.aws-kms.kek-arn")
        if region.isEmpty then
          Resource.eval(IO.raiseError(new IllegalArgumentException(
            "aegis.crypto.kind=aws-kms requires aegis.crypto.aws-kms.region (set AEGIS_CRYPTO_AWS_KMS_REGION)"
          )))
        else if kekArn.isEmpty then
          Resource.eval(IO.raiseError(new IllegalArgumentException(
            "aegis.crypto.kind=aws-kms requires aegis.crypto.aws-kms.kek-arn (set AEGIS_CRYPTO_AWS_KMS_KEK_ARN)"
          )))
        else
          Resource.eval(IO(logger.info(
            s"crypto: aws-kms (region=$region, kek-arn=$kekArn)"
          ))) *> AwsKmsRootOfTrust.resource(AwsKmsRootOfTrust.Config(region, kekArn)).widen
      case other =>
        Resource.eval(IO.raiseError(new IllegalArgumentException(
          s"Unknown aegis.crypto.kind=$other (expected 'in-memory', 'software', or 'aws-kms')"
        )))

  /** Actor system as a Resource. `terminate()` returns `Future[Terminated]`; we bridge to `IO` so the
    * finalizer can wait deterministically. The user guardian *is* the `KeyOpsActor` (see KeyOpsActor doc for
    * why).
    */
  private def actorSystemResource(
      journal: EventJournal[IO],
      rootConfig: Config
  )(using IORuntime): Resource[IO, ActorSystem[KeyOpsActor.Command]] =
    Resource.make(
      IO(ActorSystem(KeyOpsActor.fromJournal(journal), "aegis-server", rootConfig))
    ) { system =>
      IO.fromFuture(IO {
        system.terminate()
        system.whenTerminated
      }).void.handleErrorWith(t =>
        IO(logger.warn(s"actor system shutdown reported error: ${t.getMessage}", t))
      )
    }

  /** HTTP binding as a Resource. `unbind` honours pekko-http's `terminate(grace)` semantics — we give
    * in-flight requests up to 5 seconds to finish before the socket is forced closed.
    */
  private def httpBindingResource(
      host: String,
      port: Int,
      route: org.apache.pekko.http.scaladsl.server.Route
  )(using ActorSystem[?]): Resource[IO, ServerBinding] =
    Resource.make(
      IO.fromFuture(IO(Http().newServerAt(host, port).bind(route)))
    ) { binding =>
      IO.fromFuture(IO(binding.terminate(hardDeadline = 5.seconds))).void
        .handleErrorWith(t =>
          IO(logger.warn(s"HTTP binding shutdown reported error: ${t.getMessage}", t))
        )
    }

  /** HOCON loader for `aegis.persistence.journal.postgres`. Lives in the server module rather than the
    * persistence library so the library stays dependency-free of typesafe-config.
    */
  private def readPostgresJournalConfig(c: Config): PostgresJournalConfig =
    val pg = c.getConfig("aegis.persistence.journal.postgres")
    PostgresJournalConfig(
      jdbcUrl = pg.getString("jdbc-url"),
      username = pg.getString("username"),
      password = pg.getString("password"),
      poolSize = pg.getInt("pool-size")
    )

  /** HOCON loader for `aegis.persistence.journal.mysql` (#49). Same shape as the Postgres loader. */
  private def readMysqlJournalConfig(c: Config): MysqlJournalConfig =
    val my = c.getConfig("aegis.persistence.journal.mysql")
    MysqlJournalConfig(
      jdbcUrl = my.getString("jdbc-url"),
      username = my.getString("username"),
      password = my.getString("password"),
      poolSize = my.getInt("pool-size")
    )

  /** HOCON loader for `aegis.persistence.journal.sqlite` (#50). Narrower than the others — SQLite has no auth
    * model; pool size is hardcoded to 1 inside `SqliteEventJournal.make`.
    */
  private def readSqliteJournalConfig(c: Config): SqliteJournalConfig =
    val sql = c.getConfig("aegis.persistence.journal.sqlite")
    SqliteJournalConfig(jdbcUrl = sql.getString("jdbc-url"))

  /** Build the audit sink (#19). Resource-scoped so a Postgres-backed sink's connection pool is released
    * cleanly on shutdown. Also starts the retention fiber if the sink supports `pruneBefore` (Postgres does;
    * stdout doesn't).
    *
    *   - `aegis.audit.kind=stdout` — `StdoutAuditSink` writes to console. No retention.
    *   - `aegis.audit.kind=postgres` — `PostgresAuditSink` against the configured journal credentials (the
    *     audit table lives in the same database as the event journal). A daily retention fiber prunes rows
    *     older than `aegis.audit.retention.days`.
    */
  private def auditSinkResource(config: Config): Resource[IO, AuditSink[IO]] =
    config.getString("aegis.audit.kind") match
      case "stdout" =>
        Resource.eval(IO {
          logger.info("audit: stdout (set aegis.audit.kind=postgres to enable indexed audit storage)")
          StdoutAuditSink()
        })
      case "postgres" =>
        val pgConfig   = readPostgresJournalConfig(config)
        val retentionD = config.getInt("aegis.audit.retention.days")
        for
          _ <- Resource.eval(IO(logger.info(
            s"audit: postgres at ${pgConfig.jdbcUrl} (retention=${retentionD}d)"
          )))
          sink <- PostgresAuditSink.make(pgConfig)
          // Retention fiber: every 24h, delete rows older than `retentionD` days. Skip when
          // retentionD <= 0 (operator opt-out — audit grows unbounded). The fiber lives for the
          // life of the boot Resource and is cancelled when the server shuts down.
          _ <- retentionFiberResource(sink, retentionD)
        yield sink
      case other =>
        Resource.eval(IO.raiseError(new IllegalArgumentException(
          s"Unknown aegis.audit.kind=$other (expected 'stdout' or 'postgres')"
        )))

  /** Build the optional SIEM webhook fan-out sink list (#21). Returns an empty list when
    * `aegis.audit.webhook.enabled=false` so `FanOutAuditSink.of` collapses to the primary sink with no
    * overhead. When enabled, returns a single-element list containing the configured `WebhookAuditSink`. The
    * webhook sink owns its background drain fiber and retry loop; this builder just constructs and lifts it
    * into the Resource scope.
    *
    * Fails fast at boot on misconfigured webhook (empty URL or empty secret) so production deployments don't
    * run with a half-wired SIEM that drops every record.
    */
  private def webhookAuditSinkResource(config: Config)(using
      org.apache.pekko.actor.typed.ActorSystem[?]
  ): Resource[IO, List[AuditSink[IO]]] =
    if !config.getBoolean("aegis.audit.webhook.enabled") then
      Resource.pure(Nil)
    else
      val webhookCfg = config.getConfig("aegis.audit.webhook")
      val url        = webhookCfg.getString("url")
      val secret     = webhookCfg.getString("secret")
      if url.isEmpty then
        Resource.eval(IO.raiseError(new IllegalArgumentException(
          "aegis.audit.webhook.enabled=true requires aegis.audit.webhook.url " +
            "(set AEGIS_AUDIT_WEBHOOK_URL; e.g. https://siem.example.com/aegis)"
        )))
      else if secret.isEmpty then
        Resource.eval(IO.raiseError(new IllegalArgumentException(
          "aegis.audit.webhook.enabled=true requires aegis.audit.webhook.secret " +
            "(set AEGIS_AUDIT_WEBHOOK_SECRET; ≥32 bytes recommended)"
        )))
      else
        val sinkCfg = WebhookAuditSink.Config(
          url = org.apache.pekko.http.scaladsl.model.Uri(url),
          secret = secret,
          maxRetries = webhookCfg.getInt("max-retries"),
          initialBackoff = scala.concurrent.duration.FiniteDuration(
            webhookCfg.getLong("initial-backoff-ms"),
            scala.concurrent.duration.MILLISECONDS
          ),
          maxBackoff = scala.concurrent.duration.FiniteDuration(
            webhookCfg.getLong("max-backoff-ms"),
            scala.concurrent.duration.MILLISECONDS
          ),
          deadLetterFile = java.nio.file.Paths.get(webhookCfg.getString("dead-letter-file")),
          queueCapacity = webhookCfg.getInt("queue-capacity")
        )
        WebhookAuditSink.make(sinkCfg).map(s => List[AuditSink[IO]](s))

  /** Build the optional Kafka audit fan-out (#22). Returns an empty list when
    * `aegis.audit.kafka.enabled=false`. When enabled, validates bootstrap-servers + topic are non-empty
    * (fails fast on misconfig) and constructs a `KafkaAuditSink` Resource that lives for the duration of the
    * server boot scope.
    */
  private def kafkaAuditSinkResource(config: Config)(using
      org.apache.pekko.actor.typed.ActorSystem[?]
  ): Resource[IO, List[AuditSink[IO]]] =
    if !config.getBoolean("aegis.audit.kafka.enabled") then
      Resource.pure(Nil)
    else
      val kafkaCfg         = config.getConfig("aegis.audit.kafka")
      val bootstrapServers = kafkaCfg.getString("bootstrap-servers")
      val topic            = kafkaCfg.getString("topic")
      if bootstrapServers.isEmpty then
        Resource.eval(IO.raiseError(new IllegalArgumentException(
          "aegis.audit.kafka.enabled=true requires aegis.audit.kafka.bootstrap-servers " +
            "(set AEGIS_AUDIT_KAFKA_BOOTSTRAP_SERVERS; e.g. broker1:9092,broker2:9092)"
        )))
      else if topic.isEmpty then
        Resource.eval(IO.raiseError(new IllegalArgumentException(
          "aegis.audit.kafka.enabled=true requires aegis.audit.kafka.topic " +
            "(set AEGIS_AUDIT_KAFKA_TOPIC)"
        )))
      else
        val sinkCfg = KafkaAuditSink.Config(
          bootstrapServers = bootstrapServers,
          topic = topic,
          clientId = kafkaCfg.getString("client-id"),
          maxRetries = kafkaCfg.getInt("max-retries"),
          initialBackoff = scala.concurrent.duration.FiniteDuration(
            kafkaCfg.getLong("initial-backoff-ms"),
            scala.concurrent.duration.MILLISECONDS
          ),
          maxBackoff = scala.concurrent.duration.FiniteDuration(
            kafkaCfg.getLong("max-backoff-ms"),
            scala.concurrent.duration.MILLISECONDS
          ),
          deadLetterFile = java.nio.file.Paths.get(kafkaCfg.getString("dead-letter-file")),
          queueCapacity = kafkaCfg.getInt("queue-capacity"),
          maxBlockMs = kafkaCfg.getLong("max-block-ms")
        )
        KafkaAuditSink.make(sinkCfg).map(s => List[AuditSink[IO]](s))

  /** Build the optional NATS JetStream audit fan-out (#23). Returns an empty list when
    * `aegis.audit.nats.enabled=false`. When enabled, validates servers + stream + subject are non-empty
    * (fails fast on misconfig) and constructs a `NatsAuditSink` Resource. Optional `credentials-file` (.creds
    * file from `nsc add user --csv`) is honoured if supplied.
    */
  private def natsAuditSinkResource(config: Config): Resource[IO, List[AuditSink[IO]]] =
    if !config.getBoolean("aegis.audit.nats.enabled") then
      Resource.pure(Nil)
    else
      val natsCfg = config.getConfig("aegis.audit.nats")
      val servers = natsCfg.getString("servers")
      val stream  = natsCfg.getString("stream")
      val subject = natsCfg.getString("subject")
      if servers.isEmpty then
        Resource.eval(IO.raiseError(new IllegalArgumentException(
          "aegis.audit.nats.enabled=true requires aegis.audit.nats.servers " +
            "(set AEGIS_AUDIT_NATS_SERVERS; e.g. nats://broker1:4222,nats://broker2:4222)"
        )))
      else if stream.isEmpty then
        Resource.eval(IO.raiseError(new IllegalArgumentException(
          "aegis.audit.nats.enabled=true requires aegis.audit.nats.stream " +
            "(set AEGIS_AUDIT_NATS_STREAM)"
        )))
      else if subject.isEmpty then
        Resource.eval(IO.raiseError(new IllegalArgumentException(
          "aegis.audit.nats.enabled=true requires aegis.audit.nats.subject " +
            "(set AEGIS_AUDIT_NATS_SUBJECT)"
        )))
      else
        val credentialsPath = natsCfg.getString("credentials-file")
        val sinkCfg = NatsAuditSink.Config(
          servers = servers,
          stream = stream,
          subject = subject,
          autoCreateStream = natsCfg.getBoolean("auto-create-stream"),
          credentialsFile =
            if credentialsPath.isEmpty then None
            else Some(java.nio.file.Paths.get(credentialsPath)),
          maxRetries = natsCfg.getInt("max-retries"),
          initialBackoff = scala.concurrent.duration.FiniteDuration(
            natsCfg.getLong("initial-backoff-ms"),
            scala.concurrent.duration.MILLISECONDS
          ),
          maxBackoff = scala.concurrent.duration.FiniteDuration(
            natsCfg.getLong("max-backoff-ms"),
            scala.concurrent.duration.MILLISECONDS
          ),
          deadLetterFile = java.nio.file.Paths.get(natsCfg.getString("dead-letter-file")),
          queueCapacity = natsCfg.getInt("queue-capacity")
        )
        NatsAuditSink.make(sinkCfg).map(s => List[AuditSink[IO]](s))

  /** Background fiber that prunes audit rows older than `retentionDays` once a day. No-op when `retentionDays
    * <= 0`. Cancellation on Resource release stops the fiber cleanly.
    */
  private def retentionFiberResource(
      sink: PostgresAuditSink,
      retentionDays: Int
  ): Resource[IO, Unit] =
    if retentionDays <= 0 then
      Resource.eval(IO(logger.warn(
        "audit retention disabled (aegis.audit.retention.days=0) — table will grow unbounded"
      )))
    else
      val loop: IO[Unit] =
        val tick: IO[Unit] =
          for
            now <- IO.realTimeInstant
            cutoff = now.minus(java.time.Duration.ofDays(retentionDays.toLong))
            deleted <- sink.pruneBefore(cutoff).handleErrorWith { t =>
              IO(logger.warn(s"audit retention prune failed: ${t.getMessage}", t)).as(0L)
            }
            _ <- IO(logger.info(s"audit retention: pruned $deleted rows older than $cutoff"))
          yield ()
        // Forever loop: 24h sleep, then prune. Initial delay so the first prune doesn't compete
        // with the rest of boot.
        (IO.sleep(scala.concurrent.duration.FiniteDuration(24L, scala.concurrent.duration.HOURS))
          *> tick).foreverM
      Resource.make(loop.start)(fiber => fiber.cancel).void

  /** Build the `AgentTokenIssuer` that backs `POST /v1/agents/issue`.
    *
    *   - `aegis.auth.kind=hmac` — reuses the configured HMAC secret so issued agent tokens validate against
    *     the same verifier.
    *   - `aegis.auth.kind=dev` — mints a per-boot ephemeral 48-byte HMAC secret. Dev-mode tokens are valid
    *     only against this server instance and only until the next restart. Logged with a clear warning so
    *     operators don't accidentally rely on them in production.
    *
    * Both modes return a `Resource.eval`-friendly `IO[AgentTokenIssuer]`; the issuer itself holds no closable
    * resource, but lifting it via `IO` keeps the boot composition uniform.
    */
  /** Parse `aegis.security.honey-keys` (#26). Accepts either a HOCON list or — when overridden via
    * `AEGIS_HONEY_KEYS` — a comma-separated string (HOCON happily coerces a single string into a singleton
    * list, but `,`-separated values look like one element to it; we split on `,` ourselves to handle that
    * env-var shape).
    *
    * Unknown / malformed `KeyId` strings fail fast at boot rather than being silently ignored — a typo'd
    * canary that doesn't catch the agent is the opposite of what an operator wanted.
    */
  private def buildHoneyKeyRegistry(config: Config): HoneyKeyRegistry =
    import scala.jdk.CollectionConverters.*
    val raw = config.getValue("aegis.security.honey-keys").unwrapped() match
      case s: String             => s.split(',').toList.map(_.trim).filter(_.nonEmpty)
      case xs: java.util.List[?] => xs.asScala.toList.map(_.toString.trim).filter(_.nonEmpty)
      case other =>
        throw new IllegalArgumentException(
          s"aegis.security.honey-keys must be a list or comma-separated string, got: $other"
        )
    val parsed = raw.map { s =>
      dev.aegiskms.core.KeyId.fromString(s).fold(
        msg =>
          throw new IllegalArgumentException(
            s"aegis.security.honey-keys: invalid KeyId '$s': $msg"
          ),
        identity
      )
    }.toSet
    if parsed.isEmpty then
      logger.info("honey keys: none registered (set aegis.security.honey-keys to opt in)")
    else
      logger.info(s"honey keys: ${parsed.size} registered for canary auto-revoke")
    HoneyKeyRegistry.fromSet(parsed)

  /** Build the advisor's LLM provider from `aegis.advisor.llm.*`, or `None` when `provider=none`/absent. The
    * provider only narrates `advisor explain` (#29); `advisor scan` is deterministic and never calls it. A
    * bad provider name throws from `LlmClient.fromConfig`, failing the boot rather than silently disabling.
    */
  private def buildLlmClient(config: Config): Option[LlmClient[IO]] =
    def str(path: String): Option[String] =
      if config.hasPath(path) then Some(config.getString(path).trim).filter(_.nonEmpty) else None
    val llmConfig = LlmClient.Config(
      provider = str("aegis.advisor.llm.provider").getOrElse("none"),
      apiKey = str("aegis.advisor.llm.api-key"),
      baseUrl = str("aegis.advisor.llm.base-url"),
      model = str("aegis.advisor.llm.model"),
      maxTokens = if config.hasPath("aegis.advisor.llm.max-tokens") then
        config.getInt("aegis.advisor.llm.max-tokens")
      else 1024
    )
    val client = LlmClient.fromConfig(llmConfig, LlmHttp.jdk())
    client match
      case Some(_) =>
        logger.info(
          s"advisor LLM: provider=${llmConfig.provider}, model=${llmConfig.model.getOrElse("(provider default)")}"
        )
      case None =>
        logger.info(
          "advisor LLM: disabled (set aegis.advisor.llm.provider=anthropic|openai|ollama to enable narration)"
        )
    client

  private def buildAgentIssuer(config: Config): IO[AgentTokenIssuer] = IO {
    config.getString("aegis.auth.kind") match
      case "hmac" =>
        val secret = config.getString("aegis.auth.hmac.secret")
        if secret.isEmpty then
          throw new IllegalArgumentException(
            "aegis.auth.kind=hmac requires aegis.auth.hmac.secret (also used to sign issued agent tokens)"
          )
        logger.info("agent-issue: reusing aegis.auth.hmac.secret for issued agent JWTs")
        new AgentTokenIssuer(JwtIssuer.hmac(secret))
      case _ =>
        // Dev mode: ephemeral per-boot secret. 48 random bytes (>32 byte HS256 minimum).
        val randomSecret = java.util.Base64.getEncoder
          .encodeToString(java.security.SecureRandom.getInstanceStrong.generateSeed(48))
        logger.warn(
          "agent-issue: DEV MODE — issuing agent JWTs signed with a per-boot ephemeral secret. " +
            "Tokens are valid only against this server instance and only until restart. Do not " +
            "rely on dev-issued tokens beyond a workstation."
        )
        new AgentTokenIssuer(JwtIssuer.hmac(randomSecret))
  }

  /** Build the policy engine from `aegis.policy.kind` (#77). Misconfiguration fails fast at boot — silent
    * fallback to dev would defeat the purpose of opting in to role-based.
    *
    *   - `dev` — `DevPolicyEngine` (every Human + Service allowed; agent recursion still gates).
    *   - `role-based` — `RoleBasedPolicyEngine` with bindings loaded from HOCON
    *     (`aegis.policy.role-based.role-bindings` and `aegis.policy.role-based.subject-bindings`). Both maps
    *     must not be simultaneously empty — that would render every Human / Service request denied, which is
    *     almost certainly a misconfiguration rather than an explicit choice.
    *
    * Unknown operation names in bindings fail fast at boot with a clear error rather than being silently
    * ignored (a typo'd `"sgn"` would otherwise grant nothing instead of `Sign`).
    */
  private def buildPolicyEngine(config: Config): IO[PolicyEngine[IO]] = IO {
    config.getString("aegis.policy.kind") match
      case "dev" =>
        logger.warn(
          "policy: DEV MODE — DevPolicyEngine grants every Human and Service full access. " +
            "Set aegis.policy.kind=role-based (with role-bindings / subject-bindings) for production."
        )
        new DevPolicyEngine
      case "role-based" =>
        val cfg             = config.getConfig("aegis.policy.role-based")
        val roleBindings    = parseBindings(cfg, "role-bindings")
        val subjectBindings = parseBindings(cfg, "subject-bindings")
        if roleBindings.isEmpty && subjectBindings.isEmpty then
          throw new IllegalArgumentException(
            "aegis.policy.kind=role-based requires at least one binding in role-bindings or " +
              "subject-bindings; both are empty (set them in HOCON, or use kind=dev for a permissive boot)"
          )
        val totalRoles    = roleBindings.size
        val totalSubjects = subjectBindings.size
        logger.info(
          s"policy: role-based — $totalRoles role binding(s), $totalSubjects subject binding(s)"
        )
        new RoleBasedPolicyEngine(roleBindings, subjectBindings)
      case other =>
        throw new IllegalArgumentException(
          s"Unknown aegis.policy.kind=$other (expected 'dev' or 'role-based')"
        )
  }

  /** Parse a HOCON object of `name -> [op, op, ...]` into `Map[String, Set[Operation]]`. Unknown operation
    * names fail fast with the offending key + offending value so misconfigured bindings surface at boot, not
    * at the first denied request.
    */
  private def parseBindings(
      cfg: Config,
      key: String
  ): Map[String, Set[dev.aegiskms.core.Operation]] =
    import scala.jdk.CollectionConverters.*
    val inner = cfg.getConfig(key)
    inner.root().keySet().asScala.toList.map { binding =>
      // `ConfigUtil.joinPath` quotes the binding so subject keys like `"bob@org"` (containing
      // reserved chars like `@`, `.`, `:`) round-trip safely through HOCON path resolution.
      val path    = com.typesafe.config.ConfigUtil.joinPath(binding)
      val opNames = inner.getStringList(path).asScala.toList
      val ops = opNames.map { name =>
        dev.aegiskms.core.Operation.values
          .find(_.toString == name)
          .getOrElse(throw new IllegalArgumentException(
            s"aegis.policy.role-based.$key.$binding: unknown operation '$name' " +
              s"(expected one of: ${dev.aegiskms.core.Operation.values.map(_.toString).mkString(", ")})"
          ))
      }
      binding -> ops.toSet
    }.toMap

  /** Build the principal resolver from `aegis.auth.kind`. Misconfiguration fails fast at boot — silent
    * fallback to dev would be a security hole. Returns `IO` because the OIDC path needs to hit the network
    * during boot (discovery document + initial JWKS warm-up).
    *
    *   - `dev` — `PrincipalResolver.dev` (workstation-only).
    *   - `hmac` — `JwtVerifier.hmac(secret)` (single-secret HS256 — embedder / self-issued path).
    *   - `oidc` — `OidcJwtVerifier` against the configured issuer with JWKS caching (production path; closes
    *     #25).
    */
  private def buildResolver(
      config: Config,
      revocation: RevocationList[IO]
  )(using IORuntime): IO[PrincipalResolver] =
    config.getString("aegis.auth.kind") match
      case "dev" =>
        IO {
          logger.warn(
            "auth: DEV MODE — accepting X-Aegis-User as the principal. " +
              "Do not expose this server to a network you do not control."
          )
          PrincipalResolver.dev
        }
      case "hmac" =>
        IO {
          val secret = config.getString("aegis.auth.hmac.secret")
          if secret.isEmpty then
            throw new IllegalArgumentException(
              "aegis.auth.kind=hmac requires aegis.auth.hmac.secret (set AEGIS_AUTH_HMAC_SECRET)"
            )
          logger.info("auth: hmac (HS256) — verifying Authorization: Bearer <jwt>")
          val base    = JwtVerifier.hmac(secret)
          val wrapped = new RevocationAwareJwtVerifier(base, revocation)
          PrincipalResolver.jwt(wrapped)
        }
      case "oidc" =>
        val issuerUri = config.getString("aegis.auth.oidc.issuer-uri")
        val audience =
          Option(config.getString("aegis.auth.oidc.audience")).filter(_.nonEmpty)
        val ttlSecs = config.getLong("aegis.auth.oidc.jwks-cache-ttl-seconds")
        if issuerUri.isEmpty then
          IO.raiseError(new IllegalArgumentException(
            "aegis.auth.kind=oidc requires aegis.auth.oidc.issuer-uri (set AEGIS_AUTH_OIDC_ISSUER_URI)"
          ))
        else
          IO(logger.info(
            s"auth: oidc — issuer=$issuerUri, audience=${audience.getOrElse("(any)")}, " +
              s"jwks-cache-ttl=${ttlSecs}s"
          )) *>
            OidcJwtVerifier
              .fromIssuer(
                issuerUri,
                audience,
                scala.concurrent.duration.FiniteDuration(ttlSecs, scala.concurrent.duration.SECONDS)
              )
              .map { base =>
                val wrapped = new RevocationAwareJwtVerifier(base, revocation)
                PrincipalResolver.jwt(wrapped)
              }
      case other =>
        IO.raiseError(new IllegalArgumentException(
          s"Unknown aegis.auth.kind=$other (expected 'dev', 'hmac', or 'oidc')"
        ))

  /** Build the JWT revocation list (#24). Selection by `aegis.iam.revocation.kind`:
    *
    *   - `none` — `RevocationList.noop`. Nothing is ever revoked; tokens expire naturally.
    *   - `in-memory` — process-local Ref-backed list. Suits single-node dev / testing.
    *   - `redis` — `RedisRevocationList` against the configured Redis URI. Production path.
    */
  private def revocationListResource(config: Config): Resource[IO, RevocationList[IO]] =
    config.getString("aegis.iam.revocation.kind") match
      case "none" =>
        Resource.eval(IO {
          logger.info("revocation: none — no JTI kill-switch (tokens expire naturally)")
          RevocationList.noop
        })
      case "in-memory" =>
        Resource.eval(IO(logger.info(
          "revocation: in-memory (process-local; set aegis.iam.revocation.kind=redis for production)"
        ))) *> Resource.eval(RevocationList.inMemory)
      case "redis" =>
        val uri = config.getString("aegis.iam.revocation.redis.uri")
        if uri.isEmpty then
          Resource.eval(IO.raiseError(new IllegalArgumentException(
            "aegis.iam.revocation.kind=redis requires aegis.iam.revocation.redis.uri " +
              "(set AEGIS_REVOCATION_REDIS_URI; e.g. redis://localhost:6379)"
          )))
        else
          val prefix = config.getString("aegis.iam.revocation.redis.key-prefix")
          Resource.eval(IO(logger.info(s"revocation: redis at $uri (key-prefix=$prefix)"))) *>
            RedisRevocationList.make(uri, prefix).map(impl => impl: RevocationList[IO])
      case other =>
        Resource.eval(IO.raiseError(new IllegalArgumentException(
          s"Unknown aegis.iam.revocation.kind=$other (expected 'none', 'in-memory', or 'redis')"
        )))
