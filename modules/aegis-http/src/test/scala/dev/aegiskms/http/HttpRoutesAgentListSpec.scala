package dev.aegiskms.http

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import dev.aegiskms.agent.{AgentRecord, AgentRegistry, AgentStatus}
import dev.aegiskms.core.{KeyService, Operation}
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

/** HTTP-level tests for `GET /v1/agents` (#101). The registry's own semantics are covered by
  * `AgentRegistrySpec`; here we pin the route's filter parsing, authorization, and wire shape.
  */
final class HttpRoutesAgentListSpec extends AnyFunSuite with Matchers with ScalatestRouteTest:

  private given IORuntime = IORuntime.global

  private val now = Instant.parse("2026-08-04T12:00:00Z")

  /** Records the filter the route built, so we can assert query-param parsing without a real registry. */
  final private class CapturingRegistry extends AgentRegistry[IO]:
    @volatile var lastFilter: Option[AgentRegistry.Filter] = None
    @volatile var nextAgents: List[AgentRecord]            = Nil
    @volatile var nextActive: Int                          = 0

    def list(filter: AgentRegistry.Filter): IO[List[AgentRecord]] =
      IO { lastFilter = Some(filter); nextAgents }

    def activeCount: IO[Int] = IO(nextActive)

  private def sampleAgent(
      agentId: String = "agent-7a3",
      status: AgentStatus = AgentStatus.Active,
      lastSeenAt: Option[Instant] = None
  ): AgentRecord =
    AgentRecord(
      agentId = agentId,
      jti = s"jti-$agentId",
      label = "claude-invoice-batch",
      parent = "alice@org",
      scopes = Set(Operation.Sign, Operation.Get),
      issuedAt = now.minus(10, ChronoUnit.MINUTES),
      expiresAt = now.plus(50, ChronoUnit.MINUTES),
      lastSeenAt = lastSeenAt,
      status = status
    )

  private val secret   = "test-secret-test-secret-test-secret-12345"
  private val verifier = JwtVerifier.hmac(secret)
  private val issuer   = JwtIssuer.hmac(secret)

  private def routeWith(registry: AgentRegistry[IO]): Route =
    HttpRoutes(KeyService.inMemory.unsafeRunSync(), agentRegistry = Some(registry)).routes

  private def routeWithout(): Route =
    HttpRoutes(KeyService.inMemory.unsafeRunSync()).routes

  private def jwtRouteWith(registry: AgentRegistry[IO]): Route =
    HttpRoutes(
      KeyService.inMemory.unsafeRunSync(),
      resolver = PrincipalResolver.jwt(verifier),
      agentRegistry = Some(registry)
    ).routes

  private def tokenFor(claims: JwtClaims): String = issuer.issue(claims)

  private def humanToken(subject: String): String =
    tokenFor(JwtClaims.Human(
      subject = subject,
      issuer = None,
      issuedAt = Instant.now(),
      expiresAt = Instant.now().plus(1, ChronoUnit.HOURS),
      groups = Set.empty,
      jti = UUID.randomUUID().toString
    ))

  private def agentToken(subject: String): String =
    tokenFor(JwtClaims.Agent(
      subject = subject,
      issuer = None,
      issuedAt = Instant.now(),
      expiresAt = Instant.now().plus(1, ChronoUnit.HOURS),
      parentSubject = "alice@org",
      purpose = "test",
      allowedOps = Set("Sign"),
      jti = UUID.randomUUID().toString
    ))

  private def devUser(name: String) = RawHeader("X-Aegis-User", name)

  // ── Response shape ────────────────────────────────────────────────────────

  test("returns each agent with its scopes, status, and validity window") {
    val reg = new CapturingRegistry
    reg.nextAgents = List(sampleAgent(lastSeenAt = Some(now.minus(2, ChronoUnit.MINUTES))))
    reg.nextActive = 3

    Get("/v1/agents") ~> devUser("alice@org") ~> routeWith(reg) ~> check {
      status shouldBe StatusCodes.OK
      val json   = parse(responseAs[String]).toOption.get.hcursor
      val agents = json.downField("agents").values.get.toList
      agents should have size 1
      val a = agents.head.hcursor
      a.get[String]("agentId").toOption.get shouldBe "agent-7a3"
      a.get[String]("status").toOption.get shouldBe "Active"
      a.get[String]("parent").toOption.get shouldBe "alice@org"
      a.get[List[String]]("scopes").toOption.get shouldBe List("Get", "Sign")
      a.get[Option[String]]("lastSeenAt").toOption.get should not be empty
      json.get[Int]("activeCount").toOption.get shouldBe 3
    }
  }

  test("scopes are emitted in a stable sorted order, not Set iteration order") {
    val reg = new CapturingRegistry
    reg.nextAgents = List(
      sampleAgent().copy(scopes = Set(Operation.Sign, Operation.Encrypt, Operation.Get, Operation.Decrypt))
    )

    Get("/v1/agents") ~> devUser("alice@org") ~> routeWith(reg) ~> check {
      val a = parse(responseAs[String]).toOption.get.hcursor
        .downField("agents").downArray
      a.get[List[String]]("scopes").toOption.get shouldBe List("Decrypt", "Encrypt", "Get", "Sign")
    }
  }

  test("an agent that has never been used reports lastSeenAt as null, not as its issue time") {
    val reg = new CapturingRegistry
    reg.nextAgents = List(sampleAgent(lastSeenAt = None))

    Get("/v1/agents") ~> devUser("alice@org") ~> routeWith(reg) ~> check {
      val a = parse(responseAs[String]).toOption.get.hcursor.downField("agents").downArray
      a.get[Option[Instant]]("lastSeenAt").toOption.get shouldBe None
    }
  }

  test("an empty registry returns an empty list, not an error") {
    val reg = new CapturingRegistry

    Get("/v1/agents") ~> devUser("alice@org") ~> routeWith(reg) ~> check {
      status shouldBe StatusCodes.OK
      parse(responseAs[String]).toOption.get.hcursor
        .downField("agents").values.get shouldBe empty
    }
  }

  // ── Filter parsing ────────────────────────────────────────────────────────

  test("parent, status, limit and offset are all forwarded to the registry") {
    val reg = new CapturingRegistry

    Get("/v1/agents?parent=alice@org&status=Revoked&limit=25&offset=50") ~>
      devUser("alice@org") ~> routeWith(reg) ~> check {
        status shouldBe StatusCodes.OK
        val f = reg.lastFilter.get
        f.parent shouldBe Some("alice@org")
        f.status shouldBe Some(AgentStatus.Revoked)
        f.limit shouldBe 25
        f.offset shouldBe 50
      }
  }

  test("omitted filters fall back to the registry defaults") {
    val reg = new CapturingRegistry

    Get("/v1/agents") ~> devUser("alice@org") ~> routeWith(reg) ~> check {
      val f = reg.lastFilter.get
      f.parent shouldBe None
      f.status shouldBe None
      f.limit shouldBe AgentRegistry.DefaultLimit
      f.offset shouldBe 0
    }
  }

  test("status matching is case-insensitive so 'active' works as well as 'Active'") {
    val reg = new CapturingRegistry

    Get("/v1/agents?status=active") ~> devUser("alice@org") ~> routeWith(reg) ~> check {
      status shouldBe StatusCodes.OK
      reg.lastFilter.get.status shouldBe Some(AgentStatus.Active)
    }
  }

  test("an unknown status is a 400 naming the valid values, never a silently empty list") {
    val reg = new CapturingRegistry

    Get("/v1/agents?status=zombie") ~> devUser("alice@org") ~> routeWith(reg) ~> check {
      status shouldBe StatusCodes.BadRequest
      val body = responseAs[String]
      body should include("zombie")
      body should include("Active")
      // The registry must not have been consulted at all.
      reg.lastFilter shouldBe None
    }
  }

  // ── Authorization ─────────────────────────────────────────────────────────

  test("a human principal may list agents") {
    val reg = new CapturingRegistry

    val req = Get("/v1/agents").withHeaders(RawHeader("Authorization", s"Bearer ${humanToken("alice@org")}"))
    req ~> jwtRouteWith(reg) ~> check {
      status shouldBe StatusCodes.OK
    }
  }

  test("an agent principal is refused — a compromised agent must not get a map of its peers") {
    val reg = new CapturingRegistry

    val req = Get("/v1/agents").withHeaders(RawHeader("Authorization", s"Bearer ${agentToken("agent-evil")}"))
    req ~> jwtRouteWith(reg) ~> check {
      status shouldBe StatusCodes.Forbidden
      responseAs[String] should include("human principals")
      reg.lastFilter shouldBe None
    }
  }

  // ── Unconfigured server ───────────────────────────────────────────────────

  test("no registry wired → 501 NotImplemented pointing at the audit-sink setting") {
    Get("/v1/agents") ~> devUser("alice@org") ~> routeWithout() ~> check {
      status shouldBe StatusCodes.NotImplemented
      responseAs[String] should include("aegis.audit.kind=postgres")
    }
  }
