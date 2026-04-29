package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import com.typesafe.config.{Config, ConfigFactory}
import dev.aegiskms.agent.{BaselineDetector, InMemoryRecommendationSink, TappedAuditSink}
import dev.aegiskms.audit.{AuditingKeyService, StdoutAuditSink}
import dev.aegiskms.core.KeyService
import dev.aegiskms.http.HttpRoutes
import dev.aegiskms.iam.{AuthorizingKeyService, JwtVerifier, PrincipalResolver}
import dev.aegiskms.persistence.{EventJournal, PostgresEventJournal, PostgresJournalConfig}
import org.apache.pekko.actor.typed.scaladsl.Behaviors
import org.apache.pekko.actor.typed.{ActorRef, ActorSystem, Scheduler}
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.util.Timeout
import org.slf4j.LoggerFactory

import scala.concurrent.duration.*
import scala.concurrent.{Await, Promise}

/** Standalone entry point for Aegis-KMS.
  *
  * The wiring stack from outermost to innermost is:
  *   - `HttpRoutes` — extracts `Principal` from `X-Aegis-User`, parses path params
  *   - `AuditingKeyService` — writes one `AuditRecord` per call (incl. denies + errors)
  *   - `AuthorizingKeyService` — consults the [[DevPolicyEngine]] before delegating
  *   - `ActorBackedKeyService` — adapts ask-pattern → `KeyService[IO]`
  *   - `KeyOpsActor` — the single actor that owns the live state map
  *   - `EventJournal` — append-only log; replayed on boot to rebuild state
  *
  * Decorator order matters: audit OUTSIDE auth so denied calls still produce audit records. Audit OUTSIDE the
  * actor so audit writes never block on the actor's mailbox.
  *
  * The audit sink is composed: every record is fanned out to `StdoutAuditSink` (so `aegis-server` produces
  * the README's demo transcript on stdout) and through a `TappedAuditSink` to drive the W1 anomaly detector.
  * The detector publishes recommendations into an `InMemoryRecommendationSink` for now; later PRs (W3, W3.b)
  * replace that with the auto-responder + webhook fan-out.
  *
  * Productionising checklist (deferred to later PRs):
  *   - Replace `EventJournal.inMemory` with the Doobie/Postgres impl (PR F1.b)
  *   - Replace `DevPolicyEngine` with `RoleBasedPolicyEngine` configured from OIDC claims (PR F3.b)
  *   - Add Postgres + Kafka audit sinks alongside stdout (PRs F2.b, F2.c)
  *   - Bind KMIP TTLV + MCP servers in addition to HTTP (PRs K1, A1)
  */
object Server:

  private val logger = LoggerFactory.getLogger(getClass)

  private given Timeout = 5.seconds

  def main(args: Array[String]): Unit =
    given IORuntime = IORuntime.global

    val rootConfig = ConfigFactory.load()
    val host       = rootConfig.getString("aegis.http.host")
    val port       = rootConfig.getInt("aegis.http.port")

    // 1. Build the journal up front. The actor needs it at construction time to replay. The Postgres path
    //    leaks a Resource (connection pool) for the whole process lifetime — `aegis-server` is a long-running
    //    daemon, so on shutdown the JVM exit closes the pool. A future PR will tie this to a proper
    //    `cats.effect.Resource` boot scope.
    val journal: EventJournal[IO] = buildJournal(rootConfig)

    // 2. The guardian is a tiny setup behavior that spawns KeyOpsActor and hands its ref back to the main
    //    thread via a Promise. Pekko Typed has no `systemActorOf` for arbitrary children; the guardian is
    //    the only place we can spawn from. Once the actor is up, the guardian sits idle.
    val initialized = Promise[ActorRef[KeyOpsActor.Command]]()

    val guardian = Behaviors.setup[Nothing] { ctx =>
      val keyOps = ctx.spawn(KeyOpsActor.fromJournal(journal), "key-ops")
      initialized.success(keyOps)
      Behaviors.empty
    }

    given system: ActorSystem[Nothing] =
      ActorSystem[Nothing](guardian, "aegis-server", rootConfig)
    given Scheduler = system.scheduler

    val keyOpsRef = Await.result(initialized.future, 5.seconds)

    // 3. Decorate the actor-backed service with auth then audit. See the class docstring above for why this
    //    order matters.
    val actorBacked: KeyService[IO] = new ActorBackedKeyService(keyOpsRef)
    val authorizing: KeyService[IO] = new AuthorizingKeyService(actorBacked, new DevPolicyEngine)

    val resolver = buildResolver(rootConfig)

    val app: IO[Unit] =
      for
        recSink  <- InMemoryRecommendationSink.make
        detector <- BaselineDetector.make()
        // Demo wiring: the inner sink is stdout (visible to whoever boots `aegis-server`); the tap drives
        // the W1 anomaly detector and publishes recommendations into the in-memory sink.
        sink     = TappedAuditSink(StdoutAuditSink(), detector, recSink)
        auditing = new AuditingKeyService(authorizing, sink)
        _ <- IO {
          logger.warn(
            "aegis-server starting in DEV MODE — DevPolicyEngine grants every Human full access. " +
              "Replace with OIDC + RoleBasedPolicyEngine before exposing this beyond a workstation."
          )
        }
        _ <- IO.fromFuture(IO(Http().newServerAt(host, port).bind(HttpRoutes(auditing, resolver).routes)))
        _ <- IO {
          logger.info(s"aegis-server listening on http://$host:$port (try POST /v1/keys)")
          logger.info("audit feed → stdout; recommendations → in-memory sink (visible via /admin in PR W1.b)")
        }
        _ <- IO.never[Unit]
      yield ()

    app.unsafeRunSync()

  /** Choose the journal backend from configuration. `in-memory` (default for dev/tests) is built directly;
    * `postgres` allocates a connection pool via `Resource` and we lift the journal out for the lifetime of
    * the process. Any other value fails fast at boot — this is operator-facing and silent fallback would mask
    * a misconfigured deployment.
    */
  private def buildJournal(config: Config)(using IORuntime): EventJournal[IO] =
    config.getString("aegis.persistence.journal.kind") match
      case "in-memory" =>
        logger.info(
          "journal: in-memory (state is non-durable; set aegis.persistence.journal.kind=postgres for production)"
        )
        EventJournal.inMemory.unsafeRunSync()
      case "postgres" =>
        val pgConfig = readPostgresJournalConfig(config)
        logger.info(s"journal: postgres at ${pgConfig.jdbcUrl} (pool-size=${pgConfig.poolSize})")
        // `allocated` returns (resource, finalizer); we discard the finalizer because the JVM exit is the
        // process's only shutdown trigger today. A real `Resource[IO, Unit]` boot wrapper is on the F1.b
        // follow-up list; doing it now would pull every other component into the same Resource, which is a
        // larger refactor than this PR's scope.
        PostgresEventJournal.make(pgConfig).allocated.unsafeRunSync()._1
      case other =>
        throw new IllegalArgumentException(
          s"Unknown aegis.persistence.journal.kind=$other (expected 'in-memory' or 'postgres')"
        )

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
