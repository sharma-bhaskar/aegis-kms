package dev.aegiskms.cli

import dev.aegiskms.cli.WireFormats.*
import io.circe.Decoder
import io.circe.parser.*
import io.circe.syntax.*

/** Typed wrapper over `HttpPort` exposing the Aegis REST surface in the four shapes the CLI cares about:
  * create / get / activate / destroy. The methods return `Either[ClientError, A]` so the CLI's command layer
  * can map errors into exit codes without exception handling spread across every subcommand.
  *
  * Why not return `KmsErrorDto` directly? Because the failure could be a network blip, a JSON decode
  * mismatch, or the server returning HTML on a misconfigured ingress. We model those uniformly as
  * [[ClientError]] and let the command formatter render whichever variant happened.
  */
final class AegisHttpClient(http: HttpPort, baseUrl: String, principal: Option[String]):

  import AegisHttpClient.*

  private val baseHeaders: Map[String, String] =
    principal.fold(Map.empty[String, String])(p => Map("X-Aegis-User" -> p))

  def createKey(spec: KeySpecDto): Either[ClientError, ManagedKeyDto] =
    val body = CreateKeyRequest(spec).asJson.noSpaces
    val res  = http.execute(HttpPort.Request("POST", url("/v1/keys"), baseHeaders, Some(body)))
    res.status match
      case 201    => decodeBody[ManagedKeyDto](res.body)
      case status => Left(toError(status, res.body))

  def getKey(id: String): Either[ClientError, ManagedKeyDto] =
    val res = http.execute(HttpPort.Request("GET", url(s"/v1/keys/$id"), baseHeaders, None))
    res.status match
      case 200    => decodeBody[ManagedKeyDto](res.body)
      case status => Left(toError(status, res.body))

  def activateKey(id: String): Either[ClientError, ManagedKeyDto] =
    val res = http.execute(HttpPort.Request("POST", url(s"/v1/keys/$id/activate"), baseHeaders, None))
    res.status match
      case 200    => decodeBody[ManagedKeyDto](res.body)
      case status => Left(toError(status, res.body))

  def destroyKey(id: String): Either[ClientError, Unit] =
    val res = http.execute(HttpPort.Request("DELETE", url(s"/v1/keys/$id"), baseHeaders, None))
    res.status match
      case 204    => Right(())
      case status => Left(toError(status, res.body))

  def signKey(id: String, req: SignRequest): Either[ClientError, SignResponse] =
    val body    = req.asJson.noSpaces
    val headers = baseHeaders + ("Content-Type" -> "application/json")
    val res     = http.execute(HttpPort.Request("POST", url(s"/v1/keys/$id/sign"), headers, Some(body)))
    res.status match
      case 200    => decodeBody[SignResponse](res.body)
      case status => Left(toError(status, res.body))

  def verifyKey(id: String, req: VerifyRequest): Either[ClientError, VerifyResponse] =
    val body    = req.asJson.noSpaces
    val headers = baseHeaders + ("Content-Type" -> "application/json")
    val res     = http.execute(HttpPort.Request("POST", url(s"/v1/keys/$id/verify"), headers, Some(body)))
    res.status match
      case 200    => decodeBody[VerifyResponse](res.body)
      case status => Left(toError(status, res.body))

  def encryptKey(id: String, req: EncryptRequest): Either[ClientError, EncryptResponse] =
    val body    = req.asJson.noSpaces
    val headers = baseHeaders + ("Content-Type" -> "application/json")
    val res     = http.execute(HttpPort.Request("POST", url(s"/v1/keys/$id/encrypt"), headers, Some(body)))
    res.status match
      case 200    => decodeBody[EncryptResponse](res.body)
      case status => Left(toError(status, res.body))

  def decryptKey(id: String, req: DecryptRequest): Either[ClientError, DecryptResponse] =
    val body    = req.asJson.noSpaces
    val headers = baseHeaders + ("Content-Type" -> "application/json")
    val res     = http.execute(HttpPort.Request("POST", url(s"/v1/keys/$id/decrypt"), headers, Some(body)))
    res.status match
      case 200    => decodeBody[DecryptResponse](res.body)
      case status => Left(toError(status, res.body))

  def wrapKey(id: String, req: WrapRequest): Either[ClientError, WrapResponse] =
    val body    = req.asJson.noSpaces
    val headers = baseHeaders + ("Content-Type" -> "application/json")
    val res     = http.execute(HttpPort.Request("POST", url(s"/v1/keys/$id/wrap"), headers, Some(body)))
    res.status match
      case 200    => decodeBody[WrapResponse](res.body)
      case status => Left(toError(status, res.body))

  def unwrapKey(id: String, req: UnwrapRequest): Either[ClientError, UnwrapResponse] =
    val body    = req.asJson.noSpaces
    val headers = baseHeaders + ("Content-Type" -> "application/json")
    val res     = http.execute(HttpPort.Request("POST", url(s"/v1/keys/$id/unwrap"), headers, Some(body)))
    res.status match
      case 200    => decodeBody[UnwrapResponse](res.body)
      case status => Left(toError(status, res.body))

  def compromiseKey(id: String, req: CompromiseRequest): Either[ClientError, ManagedKeyDto] =
    val body    = req.asJson.noSpaces
    val headers = baseHeaders + ("Content-Type" -> "application/json")
    val res =
      http.execute(HttpPort.Request("POST", url(s"/v1/keys/$id/compromise"), headers, Some(body)))
    res.status match
      case 200    => decodeBody[ManagedKeyDto](res.body)
      case status => Left(toError(status, res.body))

  def rotateKey(id: String, req: RotateRequest): Either[ClientError, ManagedKeyDto] =
    val body    = req.asJson.noSpaces
    val headers = baseHeaders + ("Content-Type" -> "application/json")
    val res     = http.execute(HttpPort.Request("POST", url(s"/v1/keys/$id/rotate"), headers, Some(body)))
    res.status match
      case 200    => decodeBody[ManagedKeyDto](res.body)
      case status => Left(toError(status, res.body))

  /** POST /v1/agents/issue — mint an agent JWT for the calling human. */
  def issueAgent(req: IssueAgentRequestDto): Either[ClientError, IssueAgentResponseDto] =
    val body    = req.asJson.noSpaces
    val headers = baseHeaders + ("Content-Type" -> "application/json")
    val res     = http.execute(HttpPort.Request("POST", url("/v1/agents/issue"), headers, Some(body)))
    res.status match
      case 201    => decodeBody[IssueAgentResponseDto](res.body)
      case status => Left(toError(status, res.body))

  /** GET /v1/audit — paginated audit-read with filters. Each filter is encoded as a query param iff the
    * caller supplied it; absent filters are omitted entirely so the server's defaults kick in.
    */
  def queryAudit(
      since: Option[String] = None,
      until: Option[String] = None,
      actor: Option[String] = None,
      key: Option[String] = None,
      op: Option[String] = None,
      limit: Option[Int] = None,
      offset: Option[Int] = None
  ): Either[ClientError, AuditQueryResponseDto] =
    val params = List(
      since.map(v => "since" -> v),
      until.map(v => "until" -> v),
      actor.map(v => "actor" -> v),
      key.map(v => "key" -> v),
      op.map(v => "op" -> v),
      limit.map(v => "limit" -> v.toString),
      offset.map(v => "offset" -> v.toString)
    ).flatten
    val qs =
      if params.isEmpty then ""
      else
        params.map { case (k, v) =>
          s"$k=${java.net.URLEncoder.encode(v, java.nio.charset.StandardCharsets.UTF_8)}"
        }.mkString("?", "&", "")
    val res = http.execute(HttpPort.Request("GET", url(s"/v1/audit$qs"), baseHeaders, None))
    res.status match
      case 200    => decodeBody[AuditQueryResponseDto](res.body)
      case status => Left(toError(status, res.body))

  /** GET /v1/advisor/scan — deterministic read-only triage over the recent audit window (#28). Each tuning
    * knob is sent only when the caller overrides the default, so the server's defaults apply otherwise.
    */
  def advisorScan(
      lookbackDays: Option[Int] = None,
      unusedDays: Option[Int] = None,
      broadScope: Option[Int] = None,
      top: Option[Int] = None
  ): Either[ClientError, AdvisorScanResponseDto] =
    val params = List(
      lookbackDays.map(v => "lookbackDays" -> v.toString),
      unusedDays.map(v => "unusedDays" -> v.toString),
      broadScope.map(v => "broadScope" -> v.toString),
      top.map(v => "top" -> v.toString)
    ).flatten
    val qs =
      if params.isEmpty then ""
      else
        params.map { case (k, v) =>
          s"$k=${java.net.URLEncoder.encode(v, java.nio.charset.StandardCharsets.UTF_8)}"
        }.mkString("?", "&", "")
    val res = http.execute(HttpPort.Request("GET", url(s"/v1/advisor/scan$qs"), baseHeaders, None))
    res.status match
      case 200    => decodeBody[AdvisorScanResponseDto](res.body)
      case status => Left(toError(status, res.body))

  /** GET /v1/advisor/explain/{agentId} — read-only agent timeline, narrated when an LLM provider is
    * configured server-side (#29). Optional knobs are sent only when overridden.
    */
  def advisorExplain(
      agentId: String,
      lookbackDays: Option[Int] = None,
      maxEvents: Option[Int] = None
  ): Either[ClientError, AdvisorExplainResponseDto] =
    val params = List(
      lookbackDays.map(v => "lookbackDays" -> v.toString),
      maxEvents.map(v => "maxEvents" -> v.toString)
    ).flatten
    val qs =
      if params.isEmpty then ""
      else
        params.map { case (k, v) =>
          s"$k=${java.net.URLEncoder.encode(v, java.nio.charset.StandardCharsets.UTF_8)}"
        }.mkString("?", "&", "")
    val encodedId = java.net.URLEncoder.encode(agentId, java.nio.charset.StandardCharsets.UTF_8)
    val res =
      http.execute(HttpPort.Request("GET", url(s"/v1/advisor/explain/$encodedId$qs"), baseHeaders, None))
    res.status match
      case 200    => decodeBody[AdvisorExplainResponseDto](res.body)
      case status => Left(toError(status, res.body))

  // ── Helpers ────────────────────────────────────────────────────────────────

  private def url(path: String): String =
    val base = if baseUrl.endsWith("/") then baseUrl.dropRight(1) else baseUrl
    s"$base$path"

  private def decodeBody[A](body: String)(using Decoder[A]): Either[ClientError, A] =
    decode[A](body).left.map(e => ClientError.Decode(e.getMessage, body))

  /** Map a non-2xx response to a `ClientError`. We try to read the JSON `KmsErrorDto` shape first, falling
    * back to a raw error if the body isn't JSON (e.g. a load balancer's plain-text 502).
    */
  private def toError(status: Int, body: String): ClientError =
    decode[KmsErrorDto](body) match
      case Right(dto) => ClientError.Server(status, dto.code, dto.message)
      case Left(_)    => ClientError.Raw(status, body)

object AegisHttpClient:

  enum ClientError:
    case Server(status: Int, code: String, message: String)
    case Raw(status: Int, body: String)
    case Decode(message: String, body: String)

  /** Render an error for the CLI user. Single source of formatting so all commands print the same way. */
  def renderError(err: ClientError): String = err match
    case ClientError.Server(status, code, message) => s"server returned $status $code: $message"
    case ClientError.Raw(status, body) =>
      val snippet = if body.length > 240 then body.take(240) + "…" else body
      s"server returned $status with non-JSON body: $snippet"
    case ClientError.Decode(message, body) =>
      val snippet = if body.length > 240 then body.take(240) + "…" else body
      s"could not decode response: $message; body: $snippet"
