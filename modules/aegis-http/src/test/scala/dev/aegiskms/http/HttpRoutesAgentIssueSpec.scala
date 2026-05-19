package dev.aegiskms.http

import cats.effect.unsafe.IORuntime
import dev.aegiskms.audit.InMemoryAuditSink
import dev.aegiskms.core.{KeyService, Operation, Principal}
import dev.aegiskms.iam.{AgentTokenIssuer, JwtClaims, JwtIssuer, JwtVerifier, PrincipalResolver}

import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID
import io.circe.parser.parse
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.model.headers.RawHeader
import org.apache.pekko.http.scaladsl.server.Route
import org.apache.pekko.http.scaladsl.testkit.ScalatestRouteTest
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** End-to-end HTTP tests for `POST /v1/agents/issue` (#18). Exercises the full path:
  *   - Dev-mode `X-Aegis-User` resolution → Human principal
  *   - Validation (body shape, scopes, ttl)
  *   - Successful issuance + the response shape clients see
  *   - 501 Not Implemented when no issuer is wired
  */
final class HttpRoutesAgentIssueSpec extends AnyFunSuite with Matchers with ScalatestRouteTest:

  private given IORuntime = IORuntime.global

  // 32+ bytes for HS256. Same secret on issuer + verifier so issued tokens validate.
  private val secret      = "test-secret-test-secret-test-secret-12345"
  private val agentIssuer = new AgentTokenIssuer(JwtIssuer.hmac(secret))
  private val verifier    = JwtVerifier.hmac(secret)

  private def routeWithIssuer(): Route =
    HttpRoutes(KeyService.inMemory.unsafeRunSync(), agentIssuer = Some(agentIssuer)).routes

  private def routeWithIssuerAndSink(): (Route, InMemoryAuditSink) =
    val sink = InMemoryAuditSink.make.unsafeRunSync()
    val routes = HttpRoutes(
      KeyService.inMemory.unsafeRunSync(),
      agentIssuer = Some(agentIssuer),
      auditSink = Some(sink)
    ).routes
    (routes, sink)

  /** Routes wired with a JWT principal resolver (production-shape auth) — exercises the path where
    * `/agents/issue` runs with a real Bearer token instead of a dev `X-Aegis-User` header.
    */
  private def routeWithJwtAuth(): Route =
    HttpRoutes(
      KeyService.inMemory.unsafeRunSync(),
      resolver = PrincipalResolver.jwt(verifier),
      agentIssuer = Some(agentIssuer)
    ).routes

  private def routeWithoutIssuer(): Route =
    HttpRoutes(KeyService.inMemory.unsafeRunSync()).routes // agentIssuer defaults to None

  /** Mint a Human JWT for the JWT-mode auth tests. */
  private def humanToken(subject: String, groups: Set[String] = Set.empty): String =
    val now = Instant.now()
    JwtIssuer.hmac(secret).issue(
      JwtClaims.Human(subject, None, now, now.plus(1, ChronoUnit.HOURS), groups, UUID.randomUUID().toString)
    )

  /** Mint an Agent JWT — used to assert that an agent caller CANNOT use /agents/issue. */
  private def agentToken(subject: String, parent: String): String =
    val now = Instant.now()
    JwtIssuer.hmac(secret).issue(
      JwtClaims.Agent(
        subject = subject,
        issuer = None,
        issuedAt = now,
        expiresAt = now.plus(1, ChronoUnit.HOURS),
        parentSubject = parent,
        purpose = "test",
        allowedOps = Set("Get"),
        jti = UUID.randomUUID().toString
      )
    )

  private def jsonEntity(body: String): RequestEntity =
    HttpEntity(ContentTypes.`application/json`, body)

  private val happyBody =
    """{"label":"claude-invoice-batch-q2","scopes":["Sign","Get"],"ttlSeconds":3600}"""

  // ── Happy path ────────────────────────────────────────────────────────────

  test("POST /v1/agents/issue returns 201 with agentId, jwt, jti, expiresAt") {
    val req = Post("/v1/agents/issue", jsonEntity(happyBody))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.Created
      val json = parse(responseAs[String]).toOption.get.hcursor
      json.downField("agentId").as[String].toOption.get should startWith("agent-")
      json.downField("jwt").as[String].toOption.get should not be empty
      json.downField("jti").as[String].toOption.get should not be empty
      json.downField("expiresAt").as[String].toOption.get should not be empty
    }
  }

  // ── Validation ────────────────────────────────────────────────────────────

  test("missing label is rejected with 400 InvalidField") {
    val bad = """{"label":"","scopes":["Get"],"ttlSeconds":3600}"""
    val req = Post("/v1/agents/issue", jsonEntity(bad))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.BadRequest
      responseAs[String] should include(""""code":"InvalidField"""")
      responseAs[String] should include("label")
    }
  }

  test("empty scopes are rejected with 400 InvalidField") {
    val bad = """{"label":"x","scopes":[],"ttlSeconds":3600}"""
    val req = Post("/v1/agents/issue", jsonEntity(bad))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.BadRequest
      responseAs[String] should include("scopes")
    }
  }

  test("zero ttlSeconds is rejected with 400 InvalidField") {
    val bad = """{"label":"x","scopes":["Get"],"ttlSeconds":0}"""
    val req = Post("/v1/agents/issue", jsonEntity(bad))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.BadRequest
      responseAs[String] should include("ttl")
    }
  }

  test("unknown operation in scopes is rejected with 400 InvalidField") {
    val bad = """{"label":"x","scopes":["Sign","NotARealOp"],"ttlSeconds":3600}"""
    val req = Post("/v1/agents/issue", jsonEntity(bad))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.BadRequest
      responseAs[String] should include("NotARealOp")
    }
  }

  // ── Authn / authz ─────────────────────────────────────────────────────────

  test("the returned JWT round-trips through the verifier with the expected agent claims") {
    val req = Post("/v1/agents/issue", jsonEntity(happyBody))
      .withHeaders(RawHeader("X-Aegis-User", "alice@org"))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.Created
      val json    = parse(responseAs[String]).toOption.get.hcursor
      val agentId = json.downField("agentId").as[String].toOption.get
      val jwt     = json.downField("jwt").as[String].toOption.get
      val jti     = json.downField("jti").as[String].toOption.get

      val claims = verifier.verify(jwt).toOption.get.asInstanceOf[JwtClaims.Agent]
      claims.subject shouldBe agentId
      claims.parentSubject shouldBe "alice@org"
      claims.purpose shouldBe "claude-invoice-batch-q2"
      claims.allowedOps shouldBe Set("Sign", "Get")
      claims.jti shouldBe jti
    }
  }

  test("parent in body that doesn't match caller is rejected with 400") {
    val crossPrincipal =
      """{"label":"x","scopes":["Get"],"ttlSeconds":3600,"parent":"bob@org"}"""
    val req = Post("/v1/agents/issue", jsonEntity(crossPrincipal))
      .withHeaders(RawHeader("X-Aegis-User", "alice@org"))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.BadRequest
      responseAs[String] should include("cross-principal")
    }
  }

  test("TTL above the 24h default cap is rejected with 400") {
    val tooLong = """{"label":"x","scopes":["Get"],"ttlSeconds":172800}""" // 48h
    val req = Post("/v1/agents/issue", jsonEntity(tooLong))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.BadRequest
      responseAs[String] should include("exceeds maximum")
    }
  }

  test("dev-mode anonymous caller (no X-Aegis-User) is accepted — dev is permissive by design") {
    // The dev resolver maps a missing header to `Principal.Human("anonymous", Set.empty)`. Since
    // humans can issue agents, this works in dev — but the issued token's parent claim is the
    // useless `"anonymous"` subject. This is acceptable for dev (where the whole resolver is
    // explicitly "do not expose to a network you don't control"); production deployments must use
    // JWT auth, where the verifier rejects missing tokens at the boundary instead.
    val req = Post("/v1/agents/issue", jsonEntity(happyBody))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.Created
      val jwt    = parse(responseAs[String]).toOption.get.hcursor.downField("jwt").as[String].toOption.get
      val claims = verifier.verify(jwt).toOption.get.asInstanceOf[JwtClaims.Agent]
      claims.parentSubject shouldBe "anonymous"
    }
  }

  test("no agent-issuer wired in → 501 NotImplemented with FeatureNotSupported") {
    val req = Post("/v1/agents/issue", jsonEntity(happyBody))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithoutIssuer() ~> check {
      status shouldBe StatusCodes.NotImplemented
      responseAs[String] should include(""""code":"FeatureNotSupported"""")
    }
  }

  // ── Audit logging on issuance ─────────────────────────────────────────────

  test("successful issuance writes an audit record with agentId + jti context") {
    val (route, sink) = routeWithIssuerAndSink()
    val req = Post("/v1/agents/issue", jsonEntity(happyBody))
      .withHeaders(RawHeader("X-Aegis-User", "alice@org"))
    req ~> route ~> check {
      status shouldBe StatusCodes.Created

      val records = sink.all.unsafeRunSync()
      records.size shouldBe 1
      val record = records.head
      // Dev resolver adds groups = Set("admins") for any X-Aegis-User principal. We assert on the
      // subject specifically so this test isn't coupled to dev-resolver internals.
      record.principal shouldBe a[Principal.Human]
      record.principal.subject shouldBe "alice@org"
      record.operation shouldBe Operation.Create
      record.resource should startWith("agent:agent-")
      record.outcome should startWith("Success agentId=agent-")
      record.outcome should include("scopes=Sign,Get")
      record.outcome should include("ttlSeconds=3600")
      record.context("agent.issue.label") shouldBe "claude-invoice-batch-q2"
      record.context("agent.issue.scopes") shouldBe "Sign,Get"
      record.context("agent.issue.ttlSeconds") shouldBe "3600"
      record.context("agent.id") should startWith("agent-")
      record.context("agent.jti") should not be empty

      // Critically, the JWT itself MUST NOT appear in the audit log — recording a bearer credential
      // in plaintext defeats the purpose of having one.
      record.outcome should not include "ey" // JWTs start with "eyJ..."
      record.context.values.foreach { v =>
        // Sanity: no audit-context value should be a JWT-like string.
        v should not startWith "eyJ"
      }
    }
  }

  test("failed issuance (validation error) still writes an audit record with Failed outcome") {
    val (route, sink) = routeWithIssuerAndSink()
    val bad           = """{"label":"x","scopes":[],"ttlSeconds":3600}"""
    val req = Post("/v1/agents/issue", jsonEntity(bad))
      .withHeaders(RawHeader("X-Aegis-User", "alice@org"))
    req ~> route ~> check {
      status shouldBe StatusCodes.BadRequest

      val record = sink.all.unsafeRunSync().head
      record.outcome should startWith("Failed code=InvalidField")
      record.outcome should include("ttlSeconds=3600")
      record.context("agent.issue.label") shouldBe "x"
      record.context.contains("agent.id") shouldBe false // never minted
      record.context.contains("agent.jti") shouldBe false
    }
  }

  // ── Codec / malformed-JSON paths ──────────────────────────────────────────

  test("missing required `label` field is rejected by the codec with 400") {
    val noLabel = """{"scopes":["Get"],"ttlSeconds":3600}"""
    val req = Post("/v1/agents/issue", jsonEntity(noLabel))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.BadRequest
    }
  }

  test("wrong type for ttlSeconds (string) is rejected by the codec with 400") {
    val wrongType = """{"label":"x","scopes":["Get"],"ttlSeconds":"not-a-number"}"""
    val req = Post("/v1/agents/issue", jsonEntity(wrongType))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.BadRequest
    }
  }

  test("malformed JSON (unclosed brace) is rejected with 400") {
    val malformed = """{"label":"x","scopes":["Get"],"ttlSeconds":3600"""
    val req = Post("/v1/agents/issue", jsonEntity(malformed))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.BadRequest
    }
  }

  test("empty JSON body is rejected with 400") {
    val req = Post("/v1/agents/issue", jsonEntity("{}"))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.BadRequest
    }
  }

  // ── JWT-mode authn ────────────────────────────────────────────────────────

  test("JWT-mode: Human caller with a Bearer token successfully issues an agent token") {
    val token = humanToken("alice@org", Set("admins"))
    val req = Post("/v1/agents/issue", jsonEntity(happyBody))
      .withHeaders(RawHeader("Authorization", s"Bearer $token"))
    req ~> routeWithJwtAuth() ~> check {
      status shouldBe StatusCodes.Created
      val claims = verifier.verify(
        parse(responseAs[String]).toOption.get.hcursor.downField("jwt").as[String].toOption.get
      ).toOption.get.asInstanceOf[JwtClaims.Agent]
      claims.parentSubject shouldBe "alice@org"
    }
  }

  test("JWT-mode: Agent caller with a Bearer token is refused with 403 (agents cannot issue agents)") {
    val token = agentToken("agent-7a3", parent = "alice@org")
    val req = Post("/v1/agents/issue", jsonEntity(happyBody))
      .withHeaders(RawHeader("Authorization", s"Bearer $token"))
    req ~> routeWithJwtAuth() ~> check {
      status shouldBe StatusCodes.Forbidden
      responseAs[String] should include("agents cannot issue agents")
    }
  }

  test("JWT-mode: missing Bearer header is refused with 401") {
    val req = Post("/v1/agents/issue", jsonEntity(happyBody))
    req ~> routeWithJwtAuth() ~> check {
      status shouldBe StatusCodes.Unauthorized
    }
  }
