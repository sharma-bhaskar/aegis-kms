package dev.aegiskms.cli

import dev.aegiskms.cli.AegisHttpClient.ClientError
import dev.aegiskms.cli.WireFormats.*
import io.circe.syntax.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant

/** Tests for `AegisHttpClient` using a hand-rolled `HttpPort` stub. We're not asserting on JDK HTTP behaviour
  * here — just on the wire shape Aegis emits and how the client interprets responses.
  */
final class AegisHttpClientSpec extends AnyFunSuite with Matchers:

  private val baseUrl   = "http://localhost:8443"
  private val principal = Some("alice@org")
  private val sampleKey =
    ManagedKeyDto(
      id = "11111111-2222-3333-4444-555555555555",
      spec = KeySpecDto("invoice-2026", "AES", 256, "SymmetricKey"),
      createdAt = Instant.parse("2026-04-25T03:00:00Z"),
      state = "PreActive"
    )

  test("createKey POSTs to /v1/keys with the principal header and the JSON-encoded spec") {
    var seen: Option[HttpPort.Request] = None
    val port = new RecordingPort(req => {
      seen = Some(req)
      HttpPort.Response(201, sampleKey.asJson.noSpaces)
    })

    val client = new AegisHttpClient(port, baseUrl, principal)
    val res    = client.createKey(KeySpecDto("invoice-2026", "AES", 256, "SymmetricKey"))

    res shouldBe Right(sampleKey)
    seen.get.method shouldBe "POST"
    seen.get.url shouldBe s"$baseUrl/v1/keys"
    seen.get.headers.get("X-Aegis-User") shouldBe Some("alice@org")
    seen.get.body.get should include("invoice-2026")
    seen.get.body.get should include("\"sizeBits\":256")
  }

  test("getKey hits /v1/keys/{id} and decodes the response") {
    val port   = new RecordingPort(_ => HttpPort.Response(200, sampleKey.asJson.noSpaces))
    val client = new AegisHttpClient(port, baseUrl, principal)
    client.getKey(sampleKey.id) shouldBe Right(sampleKey)
  }

  test("activateKey POSTs to /v1/keys/{id}/activate") {
    var seen: Option[HttpPort.Request] = None
    val port = new RecordingPort(req => {
      seen = Some(req)
      HttpPort.Response(200, sampleKey.copy(state = "Active").asJson.noSpaces)
    })
    val client = new AegisHttpClient(port, baseUrl, principal)
    client.activateKey(sampleKey.id).map(_.state) shouldBe Right("Active")
    seen.get.url shouldBe s"$baseUrl/v1/keys/${sampleKey.id}/activate"
  }

  test("destroyKey DELETEs and treats 204 as success") {
    val port   = new RecordingPort(_ => HttpPort.Response(204, ""))
    val client = new AegisHttpClient(port, baseUrl, principal)
    client.destroyKey(sampleKey.id) shouldBe Right(())
  }

  test("server errors with a JSON KmsErrorDto body decode into ClientError.Server") {
    val errBody = KmsErrorDto("PermissionDenied", "agent has not been granted Get").asJson.noSpaces
    val port    = new RecordingPort(_ => HttpPort.Response(403, errBody))
    val client  = new AegisHttpClient(port, baseUrl, principal)
    client.getKey("k1") match
      case Left(ClientError.Server(403, "PermissionDenied", msg)) =>
        msg should include("not been granted")
      case other => fail(s"expected Server error, got $other")
  }

  test("non-JSON error bodies fall through to ClientError.Raw") {
    val port   = new RecordingPort(_ => HttpPort.Response(502, "<html>bad gateway</html>"))
    val client = new AegisHttpClient(port, baseUrl, principal)
    client.getKey("k1") match
      case Left(ClientError.Raw(502, body)) => body should include("bad gateway")
      case other                            => fail(s"expected Raw error, got $other")
  }

  test("missing principal omits the X-Aegis-User header — server applies its default") {
    var seen: Option[HttpPort.Request] = None
    val port = new RecordingPort(req => {
      seen = Some(req)
      HttpPort.Response(201, sampleKey.asJson.noSpaces)
    })
    val client = new AegisHttpClient(port, baseUrl, principal = None)
    client.createKey(KeySpecDto("k", "AES", 256, "SymmetricKey"))
    seen.get.headers.contains("X-Aegis-User") shouldBe false
  }

  test("trailing slash on baseUrl is normalised so paths don't double up") {
    var seenUrl: String = ""
    val port = new RecordingPort(req => {
      seenUrl = req.url
      HttpPort.Response(200, sampleKey.asJson.noSpaces)
    })
    val client = new AegisHttpClient(port, "http://localhost:8443/", principal)
    val _      = client.getKey("abc")
    seenUrl shouldBe "http://localhost:8443/v1/keys/abc"
  }

  // ── Stub ────────────────────────────────────────────────────────────────────

  final private class RecordingPort(handler: HttpPort.Request => HttpPort.Response) extends HttpPort:
    def execute(req: HttpPort.Request): HttpPort.Response = handler(req)
