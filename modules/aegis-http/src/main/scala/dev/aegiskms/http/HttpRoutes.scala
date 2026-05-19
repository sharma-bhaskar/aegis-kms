package dev.aegiskms.http

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import dev.aegiskms.core.*
import dev.aegiskms.http.JsonCodecs.*
import dev.aegiskms.iam.{AgentTokenIssuer, IssueAgentRequest as IamIssueAgentRequest, PrincipalResolver}
import org.apache.pekko.http.scaladsl.server.Route
import sttp.apispec.openapi.circe.yaml.*
import sttp.model.StatusCode
import sttp.tapir.docs.openapi.OpenAPIDocsInterpreter
import sttp.tapir.server.ServerEndpoint
import sttp.tapir.server.pekkohttp.PekkoHttpServerInterpreter
import sttp.tapir.swagger.bundle.SwaggerInterpreter

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
    resolver: PrincipalResolver = PrincipalResolver.dev,
    agentIssuer: Option[AgentTokenIssuer] = None
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
      // StepUpRequired: the risk decision engine (#16) is asking for a stronger credential. The reason
      // string (carried in `err.message`) is the WWW-Authenticate challenge content; clients should
      // re-present with a freshly-minted / MFA-stepped token. A dedicated `WWW-Authenticate:
      // aegis-stepup ...` header lands in a follow-up that extends the endpoint signatures with header
      // outputs — for v0.2.0 the JSON body carries the challenge reason and is sufficient for SDK use.
      case ErrorCode.StepUpRequired => StatusCode.Unauthorized
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

  private val signSE: ServerEndpoint[Any, Future] =
    Endpoints.signKey.serverLogic { case (auth, devHdr, idStr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              decodeSignRequest(req) match
                case Left(e) => Future.successful(Left(e))
                case Right((message, alg)) =>
                  runIO(svc.sign(id, message, alg, principal)).map {
                    case Left(err)  => Left(errorOut(err))
                    case Right(sig) => Right(SignResponse.fromCore(sig))
                  }
    }

  private val verifySE: ServerEndpoint[Any, Future] =
    Endpoints.verifyKey.serverLogic { case (auth, devHdr, idStr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              decodeVerifyRequest(req) match
                case Left(e) => Future.successful(Left(e))
                case Right((message, signature)) =>
                  runIO(svc.verify(id, message, signature, principal)).map {
                    case Left(err) => Left(errorOut(err))
                    case Right(ok) => Right(VerifyResponse(ok, signature.algorithm.toString))
                  }
    }

  private val encryptSE: ServerEndpoint[Any, Future] =
    Endpoints.encryptKey.serverLogic { case (auth, devHdr, idStr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              decodeBase64(req.plaintextBase64, "plaintextBase64") match
                case Left(e) => Future.successful(Left(e))
                case Right(plaintext) =>
                  runIO(svc.encrypt(id, plaintext, req.context, principal)).map {
                    case Left(err) => Left(errorOut(err))
                    case Right(ct) => Right(EncryptResponse.of(ct, req.context))
                  }
    }

  private val decryptSE: ServerEndpoint[Any, Future] =
    Endpoints.decryptKey.serverLogic { case (auth, devHdr, idStr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              Ciphertext.fromBase64(req.ciphertextBase64) match
                case Left(msg) =>
                  Future.successful(
                    Left(StatusCode.BadRequest -> KmsErrorDto.of(ErrorCode.InvalidField, msg))
                  )
                case Right(ct) =>
                  runIO(svc.decrypt(id, ct, req.context, principal)).map {
                    case Left(err) => Left(errorOut(err))
                    case Right(pt) =>
                      Right(DecryptResponse(java.util.Base64.getEncoder.encodeToString(pt), req.context))
                  }
    }

  private val wrapSE: ServerEndpoint[Any, Future] =
    Endpoints.wrapKey.serverLogic { case (auth, devHdr, idStr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              decodeBase64(req.dekBase64, "dekBase64") match
                case Left(e) => Future.successful(Left(e))
                case Right(dek) =>
                  runIO(svc.wrap(id, dek, principal)).map {
                    case Left(err) => Left(errorOut(err))
                    case Right(w)  => Right(WrapResponse.of(w))
                  }
    }

  private val unwrapSE: ServerEndpoint[Any, Future] =
    Endpoints.unwrapKey.serverLogic { case (auth, devHdr, idStr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              WrappedDek.fromBase64(req.wrappedDekBase64) match
                case Left(msg) =>
                  Future.successful(
                    Left(StatusCode.BadRequest -> KmsErrorDto.of(ErrorCode.InvalidField, msg))
                  )
                case Right(w) =>
                  runIO(svc.unwrap(id, w, principal)).map {
                    case Left(err) => Left(errorOut(err))
                    case Right(dek) =>
                      Right(UnwrapResponse(java.util.Base64.getEncoder.encodeToString(dek)))
                  }
    }

  private val compromiseSE: ServerEndpoint[Any, Future] =
    Endpoints.compromiseKey.serverLogic { case (auth, devHdr, idStr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              if req.reason.trim.isEmpty then
                Future.successful(
                  Left(StatusCode.BadRequest -> KmsErrorDto.of(
                    ErrorCode.InvalidField,
                    "reason must be non-empty"
                  ))
                )
              else
                runIO(svc.compromise(id, req.reason, principal)).map {
                  case Left(err) => Left(errorOut(err))
                  case Right(k)  => Right(ManagedKeyDto.fromCore(k))
                }
    }

  private val rotateSE: ServerEndpoint[Any, Future] =
    Endpoints.rotateKey.serverLogic { case (auth, devHdr, idStr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              RotationPolicy.fromString(req.policy) match
                case Left(msg) =>
                  Future.successful(
                    Left(StatusCode.BadRequest -> KmsErrorDto.of(ErrorCode.InvalidField, msg))
                  )
                case Right(policy) =>
                  runIO(svc.rotate(id, policy, principal)).map {
                    case Left(err) => Left(errorOut(err))
                    case Right(k)  => Right(ManagedKeyDto.fromCore(k))
                  }
    }

  private val issueAgentSE: ServerEndpoint[Any, Future] =
    Endpoints.issueAgent.serverLogic { case (auth, devHdr, body) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          agentIssuer match
            case None =>
              // The agent-issue endpoint is wired in the public OpenAPI surface unconditionally so
              // clients always see it, but the implementation is opt-in (Server.boot wires it). When
              // not wired, return 501 NotImplemented rather than crashing.
              Future.successful(
                Left(
                  StatusCode.NotImplemented -> KmsErrorDto.of(
                    ErrorCode.FeatureNotSupported,
                    "agent-token issuance is not enabled on this server"
                  )
                )
              )
            case Some(issuer) =>
              val domainReq = IamIssueAgentRequest(
                label = body.label,
                scopes = body.scopes,
                ttl = scala.concurrent.duration.FiniteDuration(
                  body.ttlSeconds,
                  scala.concurrent.duration.SECONDS
                ),
                parent = body.parent,
                callerSubject = Some(principal.subject)
              )
              runIO(issuer.issue(principal, domainReq)).map {
                case Left(err) => Left(errorOut(err))
                case Right(token) =>
                  Right(
                    IssueAgentResponseDto(
                      agentId = token.agentId,
                      jwt = token.jwt,
                      jti = token.jti,
                      expiresAt = token.expiresAt
                    )
                  )
              }
    }

  private def decodeSignRequest(
      req: SignRequest
  ): Either[(StatusCode, KmsErrorDto), (Array[Byte], SigAlgorithm)] =
    for
      msg <- decodeBase64(req.messageBase64, "messageBase64")
      alg <- SigAlgorithm.fromString(req.algorithm).left.map { msg =>
        StatusCode.BadRequest -> KmsErrorDto.of(ErrorCode.InvalidField, msg)
      }
    yield (msg, alg)

  private def decodeVerifyRequest(
      req: VerifyRequest
  ): Either[(StatusCode, KmsErrorDto), (Array[Byte], Signature)] =
    for
      msg <- decodeBase64(req.messageBase64, "messageBase64")
      alg <- SigAlgorithm.fromString(req.algorithm).left.map { msg =>
        StatusCode.BadRequest -> KmsErrorDto.of(ErrorCode.InvalidField, msg)
      }
      sig <- Signature.fromBase64(req.signatureBase64, alg).left.map { msg =>
        StatusCode.BadRequest -> KmsErrorDto.of(ErrorCode.InvalidField, msg)
      }
    yield (msg, sig)

  private def decodeBase64(
      b64: String,
      field: String
  ): Either[(StatusCode, KmsErrorDto), Array[Byte]] =
    try Right(java.util.Base64.getDecoder.decode(b64))
    catch
      case e: IllegalArgumentException =>
        Left(StatusCode.BadRequest -> KmsErrorDto.of(ErrorCode.InvalidField, s"$field: ${e.getMessage}"))

  /** All server endpoints, for the OpenAPI generator and the test stub interpreter. */
  val serverEndpoints: List[ServerEndpoint[Any, Future]] =
    List(
      createSE,
      getSE,
      activateSE,
      destroySE,
      signSE,
      verifySE,
      encryptSE,
      decryptSE,
      wrapSE,
      unwrapSE,
      compromiseSE,
      rotateSE,
      issueAgentSE
    )

  /** Render the live endpoint set as an OpenAPI 3.1 document. The build-time guarantee here is the same one
    * that makes this module valuable: the doc is generated from the same `Endpoints.*` values the routes are
    * interpreted from, so the docs cannot drift from the wire shape. Title/version pin to `Aegis-KMS v0.1.x`
    * — the version string is informational only (sbt-dynver computes the real artifact version).
    */
  val openApiYaml: String =
    OpenAPIDocsInterpreter()
      .toOpenAPI(Endpoints.all, "Aegis-KMS REST API", "0.1.x")
      .toYaml

  /** Swagger UI server endpoints. Mounted at `/docs` (and the OpenAPI YAML at `/docs/docs.yaml`); this
    * mirrors the convention `swagger-ui-bundle` defaults to. The interpreter takes the same `AnyEndpoint`
    * list, so adding a new endpoint above automatically shows up in the UI on next boot.
    */
  private val swaggerEndpoints: List[ServerEndpoint[Any, Future]] =
    SwaggerInterpreter()
      .fromEndpoints[Future](Endpoints.all, "Aegis-KMS REST API", "0.1.x")

  /** A pekko-http `Route` that mounts every endpoint plus the Swagger UI / OpenAPI surface. */
  def routes: Route =
    PekkoHttpServerInterpreter().toRoute(serverEndpoints ++ swaggerEndpoints)
