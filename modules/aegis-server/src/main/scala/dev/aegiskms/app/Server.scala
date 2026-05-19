package dev.aegiskms.app

import cats.effect.unsafe.IORuntime
import cats.effect.{IO, IOApp, Resource}
import cats.syntax.all.*
import com.typesafe.config.{Config, ConfigFactory}
import dev.aegiskms.agent.{
  AutoResponder,
  BaselineDetector,
  BaselineRiskScorer,
  InMemoryRecommendationSink,
  TappedAuditSink,
  ThresholdDecisionEngine
}
import dev.aegiskms.audit.{AuditingKeyService, StdoutAuditSink}
import dev.aegiskms.http.HttpRoutes
import dev.aegiskms.iam.{AgentTokenIssuer, AuthorizingKeyService, JwtIssuer, JwtVerifier, PrincipalResolver}
import dev.aegiskms.persistence.{EventJournal, PostgresEventJournal, PostgresJournalConfig}
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import org.apache.pekko.actor.typed.{ActorSystem, Scheduler}
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.Http.ServerBinding
import org.apache.pekko.http.scaladsl.server.Directives.concat
import org.apache.pekko.util.Timeout
import org.slf4j.LoggerFactory

import scala.concurrent.duration.*

/** Standalone entry point for Aegis-KMS.
  *
  * The wiring stack from outermost to innermost is:
  *   - `HttpRoutes` — extracts `Principal` from `X-Aegis-User`, parses path params
  *   - `AuditingKeyService` — writes one `AuditRecord` per call (incl. denies + errors)
  *   - `MeteredKeyService` — records counter + latency timer + error counter per operation
  *   - `AuthorizingKeyService` — consults the [[DevPolicyEngine]] before delegating
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
  *   - Replace `DevPolicyEngine` with `RoleBasedPolicyEngine` configured from OIDC claims (PR F3.b)
  *   - Add Postgres + Kafka audit sinks alongside stdout (PRs F2.b, F2.c)
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

      // 4. Decorate. Auth → metrics → tracing → audit; see the class docstring for why this order
      //    matters. Tracing sits between metrics and audit so the trace span measures auth + actor
      //    + journal as one unit; metrics record their own (smaller) timer next to it; audit stays
      //    the outermost layer so the audit row reflects the post-trace outcome.
      actorBacked = new ActorBackedKeyService(system)
      authorizing = new AuthorizingKeyService(actorBacked, new DevPolicyEngine)
      metered     = new MeteredKeyService(authorizing, metricsRegistry)
      traced      = new TracingKeyService(metered, tracer)
      recStore <- Resource.eval(InMemoryRecommendationSink.make)
      detector <- Resource.eval(BaselineDetector.make())
      stdoutSink = StdoutAuditSink()
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
      auditing       = new AuditingKeyService(traced, sink, Some(riskScorer), Some(decisionEngine))

      resolver = buildResolver(rootConfig)
      // Agent-token issuer (#18). Needs a JwtIssuer with the HMAC secret. We share the same secret
      // the verifier uses when `aegis.auth.kind=hmac`; in dev mode we mint a stable per-boot secret
      // (logged below) so the demo can issue + verify agent tokens within a single server lifetime.
      // The "dev mode self-issued tokens" approach is deliberate — it lets newcomers exercise the
      // wedge demo with real Agent principals without standing up an OIDC IDP. PR #25 replaces this
      // with proper OIDC + JWKS rotation.
      agentIssuer <- Resource.eval(buildAgentIssuer(rootConfig))

      _ <- Resource.eval(IO {
        logger.warn(
          "aegis-server starting in DEV MODE — DevPolicyEngine grants every Human full access. " +
            "Replace with OIDC + RoleBasedPolicyEngine before exposing this beyond a workstation."
        )
      })

      // 5. HTTP binding. Acquire = bind; release = unbind with the configured grace period (5s) so
      //    in-flight requests finish before the socket closes.
      appRoute =
        concat(
          // `auditSink = Some(stdoutSink)` so `/v1/agents/issue` records a forensic trail of every
          // agent credential minted (the keys surface is already covered by `AuditingKeyService`
          // wrapping `traced`, but agent issuance is not on the `KeyService` algebra and would
          // otherwise be invisible to operators).
          HttpRoutes(auditing, resolver, Some(agentIssuer), Some(stdoutSink)).routes,
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

  /** Journal as a Resource. The Postgres path returns a real `Resource[IO, EventJournal[IO]]` whose finalizer
    * closes the connection pool. The in-memory path has nothing to close, so we lift it with `Resource.eval`.
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
      case other =>
        Resource.eval(IO.raiseError(new IllegalArgumentException(
          s"Unknown aegis.persistence.journal.kind=$other (expected 'in-memory' or 'postgres')"
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

  /** Build the principal resolver from `aegis.auth.kind`. Misconfiguration fails fast at boot — silent
    * fallback to dev would be a security hole.
    */
  private def buildResolver(config: Config): PrincipalResolver =
    config.getString("aegis.auth.kind") match
      case "dev" =>
        logger.warn(
          "auth: DEV MODE — accepting X-Aegis-User as the principal. Do not expose this server to a network you do not control."
        )
        PrincipalResolver.dev
      case "hmac" =>
        val secret = config.getString("aegis.auth.hmac.secret")
        if secret.isEmpty then
          throw new IllegalArgumentException(
            "aegis.auth.kind=hmac requires aegis.auth.hmac.secret (set AEGIS_AUTH_HMAC_SECRET)"
          )
        logger.info("auth: hmac (HS256) — verifying Authorization: Bearer <jwt>")
        PrincipalResolver.jwt(JwtVerifier.hmac(secret))
      case other =>
        throw new IllegalArgumentException(
          s"Unknown aegis.auth.kind=$other (expected 'dev' or 'hmac')"
        )
