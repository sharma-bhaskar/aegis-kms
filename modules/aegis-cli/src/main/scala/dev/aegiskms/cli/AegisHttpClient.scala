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
