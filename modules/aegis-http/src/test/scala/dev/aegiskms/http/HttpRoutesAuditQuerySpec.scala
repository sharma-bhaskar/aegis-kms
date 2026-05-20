package dev.aegiskms.http

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import dev.aegiskms.audit.{AuditQuery, AuditRecord}
import dev.aegiskms.core.{KeyService, Operation, Principal}
import dev.aegiskms.iam.{JwtClaims, JwtIssuer, JwtVerifier, PrincipalResolver}
import io.circe.parser.parse
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.model.headers.RawHeader
import org.apache.pekko.http.scaladsl.server.Route
import org.apache.pekko.http.scaladsl.testkit.ScalatestRouteTest
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/** End-to-end HTTP tests for `GET /v1/audit` (#20). The query layer itself is exercised against real Postgres
  * in `PostgresAuditSinkSpec`; here we stub out `AuditQuery` and focus on the route's filter parsing, authz,
  * and response shape.
  */
final class HttpRoutesAuditQuerySpec extends AnyFunSuite with Matchers with ScalatestRouteTest:

  private given IORuntime = IORuntime.global

  // Captures the most recent `Filter` so we can assert on what the route sent to the query layer.
  final private class CapturingQuery extends AuditQuery[IO]:
    @volatile var lastFilter: Option[AuditQuery.Filter] = None
    @volatile var nextPage: AuditQuery.Page             = AuditQuery.Page(Nil, 100, 0, false)

    def query(filter: AuditQuery.Filter): IO[AuditQuery.Page] =
      IO {
        lastFilter = Some(filter)
        nextPage
      }

  private val secret   = "test-secret-test-secret-test-secret-12345"
  private val verifier = JwtVerifier.hmac(secret)
  private val issuer   = JwtIssuer.hmac(secret)

  private def routeWithReader(reader: AuditQuery[IO]): Route =
    HttpRoutes(KeyService.inMemory.unsafeRunSync(), auditReader = Some(reader)).routes

  private def routeWithoutReader(): Route =
    HttpRoutes(KeyService.inMemory.unsafeRunSync()).routes

  private def jwtRouteWithReader(reader: AuditQuery[IO]): Route =
    HttpRoutes(
      KeyService.inMemory.unsafeRunSync(),
      resolver = PrincipalResolver.jwt(verifier),
      auditReader = Some(reader)
    ).routes

  private def humanToken(subject: String): String =
    val now = Instant.now()
    issuer.issue(JwtClaims.Human(
      subject = subject,
      issuer = None,
      issuedAt = now,
      expiresAt = now.plus(1, ChronoUnit.HOURS),
      groups = Set.empty,
      jti = UUID.randomUUID().toString
    ))

  private def agentToken(subject: String): String =
    val now = Instant.now()
    issuer.issue(JwtClaims.Agent(
      subject = subject,
      issuer = None,
      issuedAt = now,
      expiresAt = now.plus(1, ChronoUnit.HOURS),
      parentSubject = "alice@org",
      purpose = "test",
      allowedOps = Set("Get"),
      jti = UUID.randomUUID().toString
    ))

  // ── Happy path + response shape ───────────────────────────────────────────

  test("GET /v1/audit with no filters returns 200 and an empty records array") {
    val reader = CapturingQuery()
    val req    = Get("/v1/audit").withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithReader(reader) ~> check {
      status shouldBe StatusCodes.OK
      val json = parse(responseAs[String]).toOption.get.hcursor
      json.downField("records").as[List[io.circe.Json]].toOption.get shouldBe empty
      json.downField("limit").as[Int].toOption shouldBe Some(100)
      json.downField("offset").as[Int].toOption shouldBe Some(0)
      json.downField("hasMore").as[Boolean].toOption shouldBe Some(false)
    }
  }

  test("records returned by the query layer round-trip through the wire DTO") {
    val reader = CapturingQuery()
    val sample = AuditRecord(
      at = Instant.parse("2026-05-20T10:00:00Z"),
      principal = Principal.Human("alice@org", Set("admins")),
      operation = Operation.Sign,
      resource = "key:abc",
      outcome = "Success alg=RsaPssSha256",
      correlationId = "corr-1",
      context = Map("risk.score" -> "0.42", "outcome.decision" -> "Allow")
    )
    reader.nextPage = AuditQuery.Page(List(sample), 100, 0, false)

    val req = Get("/v1/audit").withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithReader(reader) ~> check {
      status shouldBe StatusCodes.OK
      val rec = parse(responseAs[String]).toOption.get.hcursor.downField("records").downArray
      rec.downField("actor").as[String].toOption shouldBe Some("alice@org")
      rec.downField("actorKind").as[String].toOption shouldBe Some("Human")
      rec.downField("operation").as[String].toOption shouldBe Some("Sign")
      rec.downField("resource").as[String].toOption shouldBe Some("key:abc")
      rec.downField("correlationId").as[String].toOption shouldBe Some("corr-1")
      rec.downField("context").downField("risk.score").as[String].toOption shouldBe Some("0.42")
    }
  }

  // ── Filter parsing ────────────────────────────────────────────────────────

  test("query parameters land in AuditQuery.Filter with correct types") {
    val reader = CapturingQuery()
    val req = Get(
      "/v1/audit?since=2026-05-20T00:00:00Z&until=2026-05-21T00:00:00Z&actor=alice@org&key=key:abc&op=Sign&limit=50&offset=100"
    ).withHeaders(RawHeader("X-Aegis-User", "alice"))

    req ~> routeWithReader(reader) ~> check {
      status shouldBe StatusCodes.OK
      val f = reader.lastFilter.get
      f.since shouldBe Some(Instant.parse("2026-05-20T00:00:00Z"))
      f.until shouldBe Some(Instant.parse("2026-05-21T00:00:00Z"))
      f.actor shouldBe Some("alice@org")
      f.resource shouldBe Some("key:abc")
      f.operation shouldBe Some(Operation.Sign)
      f.limit shouldBe 50
      f.offset shouldBe 100
    }
  }

  test("unknown operation name rejects with 400 InvalidField (not silent empty result)") {
    val reader = CapturingQuery()
    val req    = Get("/v1/audit?op=NotAnOp").withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithReader(reader) ~> check {
      status shouldBe StatusCodes.BadRequest
      val body = responseAs[String]
      body should include(""""code":"InvalidField"""")
      body should include("NotAnOp")
      reader.lastFilter shouldBe None // query never invoked when op parse fails
    }
  }

  // ── Authz ─────────────────────────────────────────────────────────────────

  test("Human Bearer token successfully reads the audit log") {
    val reader = CapturingQuery()
    val token  = humanToken("alice@org")
    val req    = Get("/v1/audit").withHeaders(RawHeader("Authorization", s"Bearer $token"))
    req ~> jwtRouteWithReader(reader) ~> check {
      status shouldBe StatusCodes.OK
      reader.lastFilter shouldBe defined
    }
  }

  test("Agent principals are refused with 403 (audit-read is human-only in v0.2.0)") {
    val reader = CapturingQuery()
    val token  = agentToken("agent-7a3")
    val req    = Get("/v1/audit").withHeaders(RawHeader("Authorization", s"Bearer $token"))
    req ~> jwtRouteWithReader(reader) ~> check {
      status shouldBe StatusCodes.Forbidden
      responseAs[String] should include("audit read is restricted to human principals")
      reader.lastFilter shouldBe None
    }
  }

  test("no audit reader wired → 501 NotImplemented with FeatureNotSupported") {
    val req = Get("/v1/audit").withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithoutReader() ~> check {
      status shouldBe StatusCodes.NotImplemented
      responseAs[String] should include(""""code":"FeatureNotSupported"""")
    }
  }

  // ── Pagination ────────────────────────────────────────────────────────────

  test("hasMore=true from the query layer propagates to the wire response") {
    val reader = CapturingQuery()
    reader.nextPage = AuditQuery.Page(Nil, 50, 100, true)
    val req = Get("/v1/audit?limit=50&offset=100").withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithReader(reader) ~> check {
      status shouldBe StatusCodes.OK
      val json = parse(responseAs[String]).toOption.get.hcursor
      json.downField("hasMore").as[Boolean].toOption shouldBe Some(true)
      json.downField("limit").as[Int].toOption shouldBe Some(50)
      json.downField("offset").as[Int].toOption shouldBe Some(100)
    }
  }
