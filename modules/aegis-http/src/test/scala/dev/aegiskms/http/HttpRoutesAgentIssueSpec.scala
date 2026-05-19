package dev.aegiskms.http

import cats.effect.unsafe.IORuntime
import dev.aegiskms.core.KeyService
import dev.aegiskms.iam.{AgentTokenIssuer, JwtIssuer}
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

  private def routeWithIssuer(): Route =
    HttpRoutes(KeyService.inMemory.unsafeRunSync(), agentIssuer = Some(agentIssuer)).routes

  private def routeWithoutIssuer(): Route =
    HttpRoutes(KeyService.inMemory.unsafeRunSync()).routes // agentIssuer defaults to None

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

  test("missing X-Aegis-User in dev mode falls back to anonymous Human, who can still issue") {
    // Dev-mode resolver creates a `Principal.Human("anonymous", Set.empty)` when no header is set.
    // Since Humans can issue agents (per the spec), this is permitted — operators who care about
    // attribution must configure JWT auth, where the verifier rejects missing tokens.
    val req = Post("/v1/agents/issue", jsonEntity(happyBody))
    req ~> routeWithIssuer() ~> check {
      status shouldBe StatusCodes.Created
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
