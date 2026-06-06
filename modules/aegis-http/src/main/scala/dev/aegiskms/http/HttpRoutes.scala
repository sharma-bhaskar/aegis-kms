package dev.aegiskms.http

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import dev.aegiskms.agent.{AdvisorExplain, AdvisorScan, AdvisorService}
import dev.aegiskms.audit.{AuditQuery, AuditRecord, AuditSink, RequestContext}
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

import java.util.UUID
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
    agentIssuer: Option[AgentTokenIssuer] = None,
    /** Optional audit sink for non-`KeyService` endpoints. The keys surface is already audited by the
      * `AuditingKeyService` decorator wrapped around `svc`; `/v1/agents/issue` (and any future non-keys
      * endpoints) needs an explicit hookup because it bypasses that decorator. When `None`, agent issuances
      * are not recorded — operators who care about forensics MUST wire this in production.
      */
    auditSink: Option[AuditSink[IO]] = None,
    /** Optional `AuditQuery` backing the `GET /v1/audit` audit-read endpoint. Provided by `Server.boot` only
      * when `aegis.audit.kind=postgres` (the only sink that implements `AuditQuery`). When `None`, `GET
      * /v1/audit` returns `501 FeatureNotSupported`.
      */
    auditReader: Option[AuditQuery[IO]] = None,
    /** Per-request context bag shared with the same `AuditingKeyService` decorator wrapping `svc`. Every
      * `runIO` call writes `source.ip` to it as the first IO step, before the user-facing work runs, so the
      * downstream `AuditingKeyService.preflightContext` reads the IP back via `current` and stamps it into
      * `AuditRecord.context("source.ip")` (activates `SourceIpBaseline` — closes #78).
      *
      * Defaults to [[RequestContext.empty]] so existing tests that construct `HttpRoutes` without the IOLocal
      * compile unchanged — the production wiring in `Server.boot` swaps in the real one.
      */
    requestContext: RequestContext = RequestContext.empty,
    /** Optional advisor backing the `GET /v1/advisor/scan` endpoint. Wired by `Server.boot` over the same
      * `AuditQuery` that backs the audit-read endpoint — so it's present exactly when `auditReader` is. When
      * `None`, `GET /v1/advisor/scan` returns `501 FeatureNotSupported`.
      */
    advisor: Option[AdvisorService[IO]] = None
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

  /** Run an IO and bridge to Future for Tapir, stamping `source.ip` into the shared `RequestContext` as the
    * first IO step. Setting the IOLocal inside the IO chain (rather than the calling thread) is what makes
    * the value visible to deeper IO consumers — every subsequent `flatMap` in the fiber inherits it,
    * including the read inside `AuditingKeyService.preflightContext`.
    *
    * When `clientIp` is `None` the context is left untouched so background fibers and tests that never set it
    * observe an empty map (rather than a stale value from a prior request).
    */
  private def runIO[A](clientIp: Option[String])(io: IO[A]): Future[A] =
    val withCtx = clientIp match
      case Some(ip) => requestContext.set(Map("source.ip" -> ip)) *> io
      case None     => requestContext.set(Map.empty) *> io
    withCtx.unsafeToFuture()

  // ── Server endpoints ───────────────────────────────────────────────────────

  private val createSE: ServerEndpoint[Any, Future] =
    Endpoints.createKey.serverLogic { case (auth, devHdr, clientIp, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          req.spec.toCore match
            case Left(msg) =>
              Future.successful(
                Left(StatusCode.BadRequest -> KmsErrorDto.of(ErrorCode.InvalidField, msg))
              )
            case Right(spec) =>
              runIO(clientIp)(svc.create(spec, principal)).map {
                case Left(err) => Left(errorOut(err))
                case Right(k)  => Right(ManagedKeyDto.fromCore(k))
              }
    }

  private val getSE: ServerEndpoint[Any, Future] =
    Endpoints.getKey.serverLogic { case (auth, devHdr, clientIp, idStr) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              runIO(clientIp)(svc.get(id, principal)).map {
                case Left(err) => Left(errorOut(err))
                case Right(k)  => Right(ManagedKeyDto.fromCore(k))
              }
    }

  private val activateSE: ServerEndpoint[Any, Future] =
    Endpoints.activateKey.serverLogic { case (auth, devHdr, clientIp, idStr) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              runIO(clientIp)(svc.activate(id, principal)).map {
                case Left(err) => Left(errorOut(err))
                case Right(k)  => Right(ManagedKeyDto.fromCore(k))
              }
    }

  private val destroySE: ServerEndpoint[Any, Future] =
    Endpoints.destroyKey.serverLogic { case (auth, devHdr, clientIp, idStr) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              runIO(clientIp)(svc.destroy(id, principal)).map {
                case Left(err) => Left(errorOut(err))
                case Right(_)  => Right(())
              }
    }

  private val signSE: ServerEndpoint[Any, Future] =
    Endpoints.signKey.serverLogic { case (auth, devHdr, clientIp, idStr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              decodeSignRequest(req) match
                case Left(e) => Future.successful(Left(e))
                case Right((message, alg)) =>
                  runIO(clientIp)(svc.sign(id, message, alg, principal)).map {
                    case Left(err)  => Left(errorOut(err))
                    case Right(sig) => Right(SignResponse.fromCore(sig))
                  }
    }

  private val verifySE: ServerEndpoint[Any, Future] =
    Endpoints.verifyKey.serverLogic { case (auth, devHdr, clientIp, idStr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              decodeVerifyRequest(req) match
                case Left(e) => Future.successful(Left(e))
                case Right((message, signature)) =>
                  runIO(clientIp)(svc.verify(id, message, signature, principal)).map {
                    case Left(err) => Left(errorOut(err))
                    case Right(ok) => Right(VerifyResponse(ok, signature.algorithm.toString))
                  }
    }

  private val encryptSE: ServerEndpoint[Any, Future] =
    Endpoints.encryptKey.serverLogic { case (auth, devHdr, clientIp, idStr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              decodeBase64(req.plaintextBase64, "plaintextBase64") match
                case Left(e) => Future.successful(Left(e))
                case Right(plaintext) =>
                  runIO(clientIp)(svc.encrypt(id, plaintext, req.context, principal)).map {
                    case Left(err) => Left(errorOut(err))
                    case Right(ct) => Right(EncryptResponse.of(ct, req.context))
                  }
    }

  private val decryptSE: ServerEndpoint[Any, Future] =
    Endpoints.decryptKey.serverLogic { case (auth, devHdr, clientIp, idStr, req) =>
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
                  runIO(clientIp)(svc.decrypt(id, ct, req.context, principal)).map {
                    case Left(err) => Left(errorOut(err))
                    case Right(pt) =>
                      Right(DecryptResponse(java.util.Base64.getEncoder.encodeToString(pt), req.context))
                  }
    }

  private val wrapSE: ServerEndpoint[Any, Future] =
    Endpoints.wrapKey.serverLogic { case (auth, devHdr, clientIp, idStr, req) =>
      principalOf(auth, devHdr) match
        case Left(e) => Future.successful(Left(e))
        case Right(principal) =>
          parseId(idStr) match
            case Left(e) => Future.successful(Left(e))
            case Right(id) =>
              decodeBase64(req.dekBase64, "dekBase64") match
                case Left(e) => Future.successful(Left(e))
                case Right(dek) =>
                  runIO(clientIp)(svc.wrap(id, dek, principal)).map {
                    case Left(err) => Left(errorOut(err))
                    case Right(w)  => Right(WrapResponse.of(w))
                  }
    }

  private val unwrapSE: ServerEndpoint[Any, Future] =
    Endpoints.unwrapKey.serverLogic { case (auth, devHdr, clientIp, idStr, req) =>
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
                  runIO(clientIp)(svc.unwrap(id, w, principal)).map {
                    case Left(err) => Left(errorOut(err))
                    case Right(dek) =>
                      Right(UnwrapResponse(java.util.Base64.getEncoder.encodeToString(dek)))
                  }
    }

  private val compromiseSE: ServerEndpoint[Any, Future] =
    Endpoints.compromiseKey.serverLogic { case (auth, devHdr, clientIp, idStr, req) =>
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
                runIO(clientIp)(svc.compromise(id, req.reason, principal)).map {
                  case Left(err) => Left(errorOut(err))
                  case Right(k)  => Right(ManagedKeyDto.fromCore(k))
                }
    }

  private val rotateSE: ServerEndpoint[Any, Future] =
    Endpoints.rotateKey.serverLogic { case (auth, devHdr, clientIp, idStr, req) =>
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
                  runIO(clientIp)(svc.rotate(id, policy, principal)).map {
                    case Left(err) => Left(errorOut(err))
                    case Right(k)  => Right(ManagedKeyDto.fromCore(k))
                  }
    }

  private val issueAgentSE: ServerEndpoint[Any, Future] =
    Endpoints.issueAgent.serverLogic { case (auth, devHdr, clientIp, body) =>
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
                parent = body.parent
              )
              val issueAndAudit: IO[Either[KmsError, IssueAgentResponseDto]] =
                for
                  result <- issuer.issue(principal, domainReq)
                  _      <- writeAgentIssueAudit(principal, body, result)
                yield result.map(token =>
                  IssueAgentResponseDto(
                    agentId = token.agentId,
                    jwt = token.jwt,
                    jti = token.jti,
                    expiresAt = token.expiresAt
                  )
                )
              runIO(clientIp)(issueAndAudit).map(_.left.map(errorOut))
    }

  /** `GET /v1/audit` — paginated read of `aegis_audit_events`. Caller must be a `Principal.Human` (Service +
    * Agent return 403). When the server isn't wired with an `AuditQuery` (i.e. audit kind ≠ postgres), this
    * returns 501 NotImplemented.
    */
  private val queryAuditSE: ServerEndpoint[Any, Future] =
    Endpoints.queryAudit.serverLogic {
      case (auth, devHdr, clientIp, since, until, actor, key, op, limit, offset) =>
        principalOf(auth, devHdr) match
          case Left(e) => Future.successful(Left(e))
          case Right(principal) =>
            principal match
              case _: Principal.Human =>
                auditReader match
                  case None =>
                    // Audit-read isn't wired (e.g. aegis.audit.kind=stdout). Surface the same way
                    // we do for /agents/issue when its dependency is missing.
                    Future.successful(Left(
                      StatusCode.NotImplemented -> KmsErrorDto.of(
                        ErrorCode.FeatureNotSupported,
                        "audit query is not enabled on this server (set aegis.audit.kind=postgres)"
                      )
                    ))
                  case Some(reader) =>
                    // Parse the optional `op` filter. Unknown op names are user error → 400, not
                    // an empty result (silent empty would mask the typo).
                    val parsedOp: Either[(StatusCode, KmsErrorDto), Option[Operation]] = op match
                      case None => Right(None)
                      case Some(name) =>
                        Operation.values
                          .find(_.toString == name)
                          .toRight(StatusCode.BadRequest -> KmsErrorDto.of(
                            ErrorCode.InvalidField,
                            s"unknown op '$name'; expected one of: ${Operation.values.map(_.toString).mkString(", ")}"
                          ))
                          .map(Some(_))
                    parsedOp match
                      case Left(e) => Future.successful(Left(e))
                      case Right(opVal) =>
                        val filter = AuditQuery.Filter(
                          since = since,
                          until = until,
                          actor = actor,
                          resource = key,
                          operation = opVal,
                          limit = limit.getOrElse(AuditQuery.DefaultLimit),
                          offset = offset.getOrElse(0)
                        )
                        runIO(clientIp)(reader.query(filter)).map { page =>
                          Right(AuditQueryResponseDto(
                            records = page.records.map(AuditRecordDto.fromCore),
                            limit = page.limit,
                            offset = page.offset,
                            hasMore = page.hasMore
                          ))
                        }
              case _ =>
                // Service + Agent are refused. v0.2.0 simplification of the future
                // "audit:read permission via policy engine" model.
                Future.successful(Left(
                  StatusCode.Forbidden -> KmsErrorDto.of(
                    ErrorCode.PermissionDenied,
                    "audit read is restricted to human principals"
                  )
                ))
    }

  /** `GET /v1/advisor/scan` — deterministic, read-only triage over the audit window. Same access model as
    * `/v1/audit`: human principals only (Service + Agent return 403), and 501 when no advisor is wired (audit
    * kind ≠ postgres). Negative/zero query params fall back to the advisor defaults rather than erroring — a
    * scan with a nonsensical window is better served by sane defaults than a 400.
    */
  private val advisorScanSE: ServerEndpoint[Any, Future] =
    Endpoints.advisorScan.serverLogic {
      case (auth, devHdr, clientIp, lookbackDays, unusedDays, broadScope, top) =>
        principalOf(auth, devHdr) match
          case Left(e) => Future.successful(Left(e))
          case Right(_: Principal.Human) =>
            advisor match
              case None =>
                Future.successful(Left(
                  StatusCode.NotImplemented -> KmsErrorDto.of(
                    ErrorCode.FeatureNotSupported,
                    "advisor scan is not enabled on this server (set aegis.audit.kind=postgres)"
                  )
                ))
              case Some(svc) =>
                val scan =
                  for
                    now <- IO.realTimeInstant
                    report <- svc.scan(
                      AdvisorScan.Request(
                        now = now,
                        lookback = lookbackDays.filter(_ > 0).map(d => java.time.Duration.ofDays(d.toLong))
                          .getOrElse(AdvisorScan.DefaultLookback),
                        unusedAfter = unusedDays.filter(_ > 0).map(d => java.time.Duration.ofDays(d.toLong))
                          .getOrElse(AdvisorScan.DefaultUnusedAfter),
                        broadScopeThreshold =
                          broadScope.filter(_ > 0).getOrElse(AdvisorScan.DefaultBroadScopeThreshold),
                        topRiskiest = top.filter(_ > 0).getOrElse(AdvisorScan.DefaultTopRiskiest)
                      )
                    )
                  yield AdvisorScanResponseDto.fromCore(report)
                runIO(clientIp)(scan).map(Right(_))
          case Right(_) =>
            Future.successful(Left(
              StatusCode.Forbidden -> KmsErrorDto.of(
                ErrorCode.PermissionDenied,
                "advisor scan is restricted to human principals"
              )
            ))
    }

  /** `GET /v1/advisor/explain/{agentId}` — read-only agent-session timeline, narrated when an LLM provider is
    * configured. Same access model as the other advisor/audit endpoints: human-only, 501 when unwired.
    */
  private val advisorExplainSE: ServerEndpoint[Any, Future] =
    Endpoints.advisorExplain.serverLogic {
      case (auth, devHdr, clientIp, agentId, lookbackDays, maxEvents) =>
        principalOf(auth, devHdr) match
          case Left(e) => Future.successful(Left(e))
          case Right(_: Principal.Human) =>
            advisor match
              case None =>
                Future.successful(Left(
                  StatusCode.NotImplemented -> KmsErrorDto.of(
                    ErrorCode.FeatureNotSupported,
                    "advisor explain is not enabled on this server (set aegis.audit.kind=postgres)"
                  )
                ))
              case Some(svc) =>
                val explain =
                  for
                    now <- IO.realTimeInstant
                    report <- svc.explain(
                      AdvisorExplain.Request(
                        agentId = agentId,
                        now = now,
                        lookback = lookbackDays.filter(_ > 0).map(d => java.time.Duration.ofDays(d.toLong))
                          .getOrElse(AdvisorExplain.DefaultLookback),
                        maxEvents = maxEvents.filter(_ > 0).getOrElse(AdvisorExplain.DefaultMaxEvents)
                      )
                    )
                  yield AdvisorExplainResponseDto.fromCore(report)
                runIO(clientIp)(explain).map(Right(_))
          case Right(_) =>
            Future.successful(Left(
              StatusCode.Forbidden -> KmsErrorDto.of(
                ErrorCode.PermissionDenied,
                "advisor explain is restricted to human principals"
              )
            ))
    }

  /** Write one `AuditRecord` per `/v1/agents/issue` call — success OR failure — so operators have a forensic
    * trail of every agent credential ever minted. The audit row captures the caller (the human who issued),
    * the requested scopes + ttl + label (so reviewers can answer "what does this agent have access to"), and
    * on success the `agentId` + `jti` (so a later auto-revoke or audit search can join back to the issuance).
    * Bodies that *almost* contained a token never had one minted; their audit rows say "Failed code=...".
    *
    * The JWT itself is NEVER written — it's a bearer credential and recording it in plaintext defeats the
    * purpose of having one.
    *
    * No-op when no sink is configured; the keys surface is already covered by `AuditingKeyService` so this
    * method is only on the path for agent-issuance.
    */
  private def writeAgentIssueAudit(
      caller: Principal,
      body: IssueAgentRequestDto,
      result: Either[KmsError, dev.aegiskms.iam.AgentToken]
  ): IO[Unit] =
    auditSink match
      case None => IO.unit
      case Some(sink) =>
        for
          now <- IO.realTimeInstant
          corrId = UUID.randomUUID().toString
          outcome = result match
            case Right(token) =>
              s"Success agentId=${token.agentId} jti=${token.jti} ttlSeconds=${body.ttlSeconds} scopes=${body.scopes.mkString(",")}"
            case Left(err) =>
              s"Failed code=${err.code} ttlSeconds=${body.ttlSeconds} scopes=${body.scopes.mkString(",")}"
          record = AuditRecord(
            at = now,
            principal = caller,
            // `Create` is the closest KMIP-aligned operation for "mint a new thing"; the audit
            // row carries the agent-specific context in `outcome` + `context` so it's still
            // distinguishable from a key Create.
            operation = Operation.Create,
            resource = result.toOption
              .map(t => s"agent:${t.agentId}")
              .getOrElse(s"agent:label=${body.label}"),
            outcome = outcome,
            correlationId = corrId,
            context = Map(
              "agent.issue.label"      -> body.label,
              "agent.issue.scopes"     -> body.scopes.mkString(","),
              "agent.issue.ttlSeconds" -> body.ttlSeconds.toString
            ) ++ result.toOption
              .map(t => Map("agent.id" -> t.agentId, "agent.jti" -> t.jti))
              .getOrElse(Map.empty)
          )
          _ <- sink.write(record)
        yield ()

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
      issueAgentSE,
      queryAuditSE,
      advisorScanSE,
      advisorExplainSE
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
