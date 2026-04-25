package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import com.typesafe.config.ConfigFactory
import dev.aegiskms.core.KeyService
import dev.aegiskms.http.HttpRoutes
import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.actor.typed.scaladsl.Behaviors
import org.apache.pekko.http.scaladsl.Http
import org.slf4j.LoggerFactory

/** Standalone entry point for Aegis-KMS.
  *
  * Wires together a `KeyService[IO]` (currently the in-memory reference impl), the Tapir + pekko-http REST
  * surface, and a Pekko Typed `ActorSystem`. As more modules come online they get wired in here:
  *   - Doobie-backed `PersistenceStore` replaces the in-memory store (PR #3)
  *   - AWS KMS / local file-based `RootOfTrust` plugs into key generation (PR #4)
  *   - OIDC + JWT auth replaces the dev-mode `X-Aegis-User` header (PR #5)
  *   - MCP server, KMIP TTLV server, and agent-AI plane bind alongside HTTP (PRs #6+)
  */
object Server:

  private val logger = LoggerFactory.getLogger(getClass)

  def main(args: Array[String]): Unit =
    given IORuntime = IORuntime.global

    val rootConfig = ConfigFactory.load()
    val host       = rootConfig.getString("aegis.http.host")
    val port       = rootConfig.getInt("aegis.http.port")

    given system: ActorSystem[Nothing] =
      ActorSystem[Nothing](Behaviors.empty[Nothing], "aegis-server", rootConfig)

    val app: IO[Unit] =
      for
        svc <- KeyService.inMemory
        _ = logger.warn(
          "aegis-server starting with the in-memory KeyService — NOT for production. Swap in Doobie + Postgres before going live."
        )
        _ <- IO.fromFuture(IO(Http().newServerAt(host, port).bind(HttpRoutes(svc).routes)))
        _ = logger.info(s"aegis-server listening on http://$host:$port (try POST /v1/keys)")
        _ <- IO.never[Unit]
      yield ()

    app.unsafeRunSync()
