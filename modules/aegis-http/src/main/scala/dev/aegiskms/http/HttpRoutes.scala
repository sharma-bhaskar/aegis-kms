package dev.aegiskms.http

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import dev.aegiskms.core.*
import dev.aegiskms.http.JsonCodecs.*
import org.apache.pekko.http.scaladsl.server.Route
import sttp.model.StatusCode
import sttp.tapir.server.ServerEndpoint
import sttp.tapir.server.pekkohttp.PekkoHttpServerInterpreter

import scala.concurrent.{ExecutionContext, Future}

/** REST routes built on Tapir + pekko-http, backed by a `KeyService[IO]` from `aegis-core`.
  *
  * This adapter is the only place in the codebase that mixes Pekko, Future, and IO. It:
  *   - extracts a `Principal` from request headers,
  *   - validates path parameters into `KeyId`,
  *   - calls the pure `KeyService[IO]` algebra,
  *   - translates `KmsError` codes to HTTP status codes,
  *   - bridges `IO` to `Future` so Tapir's pekko-http interpreter can consume it.
  *
  * The `runtime` is taken implicitly; tests construct one explicitly so they can run synchronously. The
  * production server uses `IORuntime.global` from `cats.effect.unsafe`.
  */
final class HttpRoutes(svc: KeyService[IO])(using runtime: IORuntime):

  private given ExecutionContext = runtime.compute

  // ── Helpers ────────────────────────────────────────────────────────────────

  private def principalOf(headerVal: Option[String]): Principal =
    Principal.Human(headerVal.getOrElse("anonymous"), Set.empty)

  private def errorOut(err: KmsError): (StatusCode, KmsErrorDto) =
    val sc = err.code match
      case ErrorCode.ItemNotFound                => StatusCode.NotFound
      case ErrorCode.PermissionDenied            => StatusCode.Forbidden
      case ErrorCode.AuthenticationNotSuccessful => StatusCode.Unauthorized
      case ErrorCode.InvalidField | ErrorCode.MissingData | ErrorCode.InvalidMessage =>
        StatusCode.BadRequest
      case _ => StatusCode.InternalServerError
    sc -> KmsErrorDto.fromCore(err)

  private def parseId(raw: String): Either[(StatusCode, KmsErrorDto), KeyId] =
    KeyId.fromString(raw).left.map { msg =>
      StatusCode.BadRequest -> KmsErrorDto.of(ErrorCode.InvalidField, msg)
    }

  private def runIO[A](io: IO[A]): Future[A] = io.unsafeToFuture()

  // ── Server endpoints ───────────────────────────────────────────────────────

  private val createSE: ServerEndpoint[Any, Future] =
    Endpoints.createKey.serverLogic { case (userHdr, req) =>
      val principal = principalOf(userHdr)
      req.spec.toCore match
        case Left(msg) =>
          Future.successful(
            Left(StatusCode.BadRequest -> KmsErrorDto.of(ErrorCode.InvalidField, msg))
          )
        case Right(spec) =>
          runIO(svc.create(spec, principal)).map {
            case Left(err) => Left(errorOut(err))
            case Right(k)  => Right(ManagedKeyDto.fromCore(k))
          }
    }

  private val getSE: ServerEndpoint[Any, Future] =
    Endpoints.getKey.serverLogic { case (userHdr, idStr) =>
      val principal = principalOf(userHdr)
      parseId(idStr) match
        case Left(e) => Future.successful(Left(e))
        case Right(id) =>
          runIO(svc.get(id, principal)).map {
            case Left(err) => Left(errorOut(err))
            case Right(k)  => Right(ManagedKeyDto.fromCore(k))
          }
    }

  private val activateSE: ServerEndpoint[Any, Future] =
    Endpoints.activateKey.serverLogic { case (userHdr, idStr) =>
      val principal = principalOf(userHdr)
      parseId(idStr) match
        case Left(e) => Future.successful(Left(e))
        case Right(id) =>
          runIO(svc.activate(id, principal)).map {
            case Left(err) => Left(errorOut(err))
            case Right(k)  => Right(ManagedKeyDto.fromCore(k))
          }
    }

  private val destroySE: ServerEndpoint[Any, Future] =
    Endpoints.destroyKey.serverLogic { case (userHdr, idStr) =>
      val principal = principalOf(userHdr)
      parseId(idStr) match
        case Left(e) => Future.successful(Left(e))
        case Right(id) =>
          runIO(svc.destroy(id, principal)).map {
            case Left(err) => Left(errorOut(err))
            case Right(_)  => Right(())
          }
    }

  /** All server endpoints, for the OpenAPI generator and the test stub interpreter. */
  val serverEndpoints: List[ServerEndpoint[Any, Future]] =
    List(createSE, getSE, activateSE, destroySE)

  /** A pekko-http `Route` that mounts every endpoint. */
  def routes: Route = PekkoHttpServerInterpreter().toRoute(serverEndpoints)
