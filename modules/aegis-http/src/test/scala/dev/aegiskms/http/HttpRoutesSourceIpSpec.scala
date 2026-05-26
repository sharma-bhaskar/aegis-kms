package dev.aegiskms.http

import cats.effect.unsafe.IORuntime
import dev.aegiskms.audit.{AuditingKeyService, InMemoryAuditSink, RequestContext}
import dev.aegiskms.core.KeyService
import org.apache.pekko.http.scaladsl.model.headers.RawHeader
import org.apache.pekko.http.scaladsl.model.{AttributeKeys, *}
import org.apache.pekko.http.scaladsl.server.Route
import org.apache.pekko.http.scaladsl.testkit.ScalatestRouteTest
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.net.InetAddress

/** Integration test for issue #78: a real HTTP request — driven through the same `Route` the server boots in
  * production — must produce an `AuditRecord` carrying `context("source.ip") = <remote IP>`. Closing the "1
  * of 5 anomaly detectors is dead in production" gap.
  *
  * The wiring under test is the full chain: pekko-http test-kit request → Tapir `extractFromRequest` →
  * `HttpRoutes.runIO(clientIp)` → IOLocal write → `AuditingKeyService.preflightContext` IOLocal read →
  * `AuditRecord.context`. The IOLocal instance is shared between `HttpRoutes` and `AuditingKeyService`,
  * exactly as `Server.boot` wires it.
  */
final class HttpRoutesSourceIpSpec extends AnyFunSuite with Matchers with ScalatestRouteTest:

  private given IORuntime = IORuntime.global

  /** Build a fully-wired stack: in-memory KeyService → AuditingKeyService(requestContext = rc) →
    * HttpRoutes(requestContext = rc) → Route. Returns (route, sink) so the test can both drive requests and
    * observe the audit log written by the decorator.
    */
  private def freshStack(): (Route, InMemoryAuditSink) =
    val local = cats.effect.IOLocal(Map.empty[String, String]).unsafeRunSync()
    val rc    = RequestContext.fromIOLocal(local)
    val sink  = InMemoryAuditSink.make.unsafeRunSync()
    val inner = KeyService.inMemory.unsafeRunSync()
    val svc   = AuditingKeyService(inner, sink, requestContext = rc)
    val route = HttpRoutes(svc, requestContext = rc).routes
    (route, sink)

  private val createBody =
    """{"spec":{"name":"ip-stamped","algorithm":"AES","sizeBits":256,"objectType":"SymmetricKey"}}"""

  private def jsonEntity(body: String): RequestEntity =
    HttpEntity(ContentTypes.`application/json`, body)

  /** Attach pekko-http's `remoteAddress` attribute to the request so Tapir's `req.connectionInfo.remote`
    * picks it up — this is the same key pekko-http sets automatically when
    * `pekko.http.server.remote-address-attribute = on` and a real socket is involved.
    */
  private def withRemoteIp(req: HttpRequest, ip: String): HttpRequest =
    req.addAttribute(
      AttributeKeys.remoteAddress,
      RemoteAddress(InetAddress.getByName(ip))
    )

  test("POST /v1/keys with a remote IP lands source.ip in the audit record") {
    val (route, sink) = freshStack()
    val req = withRemoteIp(Post("/v1/keys", jsonEntity(createBody)), "203.0.113.42")
      .withHeaders(RawHeader("X-Aegis-User", "alice"))

    req ~> route ~> check {
      status shouldBe StatusCodes.Created
    }

    val records = sink.all.unsafeRunSync()
    records.size shouldBe 1
    records.head.context.get("source.ip") shouldBe Some("203.0.113.42")
  }

  test("GET /v1/keys/{id} also carries source.ip on the read-side audit row") {
    val (route, sink) = freshStack()

    var id = ""
    withRemoteIp(Post("/v1/keys", jsonEntity(createBody)), "198.51.100.7")
      .withHeaders(RawHeader("X-Aegis-User", "alice")) ~> route ~> check {
      status shouldBe StatusCodes.Created
      id = io.circe.parser.parse(responseAs[String]).toOption
        .flatMap(_.hcursor.downField("id").as[String].toOption)
        .getOrElse(fail("missing id in create response"))
    }

    withRemoteIp(Get(s"/v1/keys/$id"), "198.51.100.7")
      .withHeaders(RawHeader("X-Aegis-User", "alice")) ~> route ~> check {
      status shouldBe StatusCodes.OK
    }

    val records = sink.all.unsafeRunSync()
    records.size shouldBe 2
    records.foreach(_.context.get("source.ip") shouldBe Some("198.51.100.7"))
  }

  test("request without a remote IP attribute → audit row has no source.ip key") {
    val (route, sink) = freshStack()

    // No `withRemoteIp(...)`: simulates a request the transport couldn't attribute (loopback bridges,
    // test stubs without the attribute). The detector then has nothing to fire on for this row.
    Post("/v1/keys", jsonEntity(createBody))
      .withHeaders(RawHeader("X-Aegis-User", "alice")) ~> route ~> check {
      status shouldBe StatusCodes.Created
    }

    val record = sink.all.unsafeRunSync().head
    record.context.contains("source.ip") shouldBe false
  }
