package dev.aegiskms.http

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import dev.aegiskms.core.*
import dev.aegiskms.http.JsonCodecs.*
import dev.aegiskms.iam.PrincipalResolver
import org.apache.pekko.http.scaladsl.server.Route
import sttp.model.StatusCode
import sttp.tapir.server.ServerEndpoint
import sttp.tapir.server.pekkohttp.PekkoHttpServerInterpreter

import scala.concurrent.{ExecutionContext, Future}

/** REST routes built on Tapir + pekko-http, backed by a `KeyService[IO]` from `aegis-core`.
  *
  * This adapter is the only place in the codebase that mixes Pekko, Future, and IO. It:
  *   - reads the `Authorization` and `X-Aegis-User` headers from each request,
  *   - hands them to a [[PrincipalResolver]] (configurable: dev / jwt-hmac) to obtain a `Principal`,
  *   - validates path parameters into `KeyId`,
  *   - calls the pure `KeyService[IO]` algebra,
  *   - translates `KmsError` codes to HTTP status codes,
  *   - bridges `IO` to `Future` so Tapir's pekko-http interpreter can consume it.
  *
  * The default resolver is the dev resolver so existing in-memory tests don't need to construct JWTs;
  * production wiring in `aegis-server` swaps in a JWT resolver when `aegis.auth.kind=hmac`.
  */
final class HttpRoutes(
    svc: KeyService[IO],
    resolver: PrincipalResolver = PrincipalResolver.dev
)(using runtime: IORuntime):

  private given ExecutionContext = runtime.compute

  // ── Helpers ────────────────────────────────────────────────────────────────

  private def principalOf(
      authHeader: Option[String],
      devHeader: Option[String]
  ): Either[(StatusCode, KmsErrorDto), Principal] =
    resolver.resolve(authHeader, devHeader).left.map(errorOut)

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
    Endpoints.createKey.serverLogic { case (auth, devHdr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
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
    Endpoints.getKey.serverLogic { case (auth, devHdr, idStr) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              runIO(svc.get(id, principal)).map {
                case Left(err) => Left(errorOut(err))
                case Right(k)  => Right(ManagedKeyDto.fromCore(k))
              }
    }

  private val activateSE: ServerEndpoint[Any, Future] =
    Endpoints.activateKey.serverLogic { case (auth, devHdr, idStr) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              runIO(svc.activate(id, principal)).map {
                case Left(err) => Left(errorOut(err))
                case Right(k)  => Right(ManagedKeyDto.fromCore(k))
              }
    }

  private val destroySE: ServerEndpoint[Any, Future] =
    Endpoints.destroyKey.serverLogic { case (auth, devHdr, idStr) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
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
