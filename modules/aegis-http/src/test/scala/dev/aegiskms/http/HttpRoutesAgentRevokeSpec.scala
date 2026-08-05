package dev.aegiskms.http

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import dev.aegiskms.agent.{AgentKillSwitch, KillSwitchRequest, KillSwitchResult, KilledAgent}
import dev.aegiskms.core.{KeyService, Principal}
import dev.aegiskms.iam.{JwtClaims, JwtIssuer, JwtVerifier, PrincipalResolver, StepUpPolicy}
import io.circe.parser.parse
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.model.headers.{RawHeader, `WWW-Authenticate`}
import org.apache.pekko.http.scaladsl.server.Route
import org.apache.pekko.http.scaladsl.testkit.ScalatestRouteTest
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/** HTTP tests for `POST /v1/agents/revoke` (#102) — the step-up gate above all.
  *
  * This is the most destructive endpoint Aegis exposes, so the tests that matter most are the ones proving it
  * *refuses*: no step-up, stale step-up, wrong principal kind. The kill-switch's own behaviour is covered by
  * `AgentKillSwitchSpec`.
  */
final class HttpRoutesAgentRevokeSpec extends AnyFunSuite with Matchers with ScalatestRouteTest:

  private given IORuntime = IORuntime.global

  private val secret   = "test-secret-test-secret-test-secret-12345"
  private val verifier = JwtVerifier.hmac(secret)
  private val issuer   = JwtIssuer.hmac(secret)

  /** A kill-switch that records what it was asked to do and never actually revokes anything. */
  final private class SpyKillSwitch extends AgentKillSwitch:
    @volatile var lastRequest: Option[KillSwitchRequest] = None

    def revokeAll(
        caller: Principal,
        request: KillSwitchRequest
    ): IO[Either[dev.aegiskms.core.KmsError, KillSwitchResult]] =
      IO {
        lastRequest = Some(request)
        Right(KillSwitchResult(
          parent = request.parent,
          killed = List(KilledAgent("agent-1", "claude-batch", Instant.parse("2026-08-04T13:00:00Z"))),
          alreadyRevoked = 2,
          expired = 1
        ))
      }

  private def route(ks: AgentKillSwitch, policy: StepUpPolicy = StepUpPolicy()): Route =
    HttpRoutes(
      KeyService.inMemory.unsafeRunSync(),
      resolver = PrincipalResolver.jwt(verifier),
      agentKillSwitch = Some(ks),
      stepUpPolicy = policy
    ).routes

  private def routeWithout(): Route =
    HttpRoutes(KeyService.inMemory.unsafeRunSync(), resolver = PrincipalResolver.jwt(verifier)).routes

  private def humanToken(
      subject: String = "alice@org",
      amr: Set[String] = Set("mfa"),
      authTime: Option[Instant] = Some(Instant.now())
  ): String =
    issuer.issue(JwtClaims.Human(
      subject = subject,
      issuer = None,
      issuedAt = Instant.now(),
      expiresAt = Instant.now().plus(1, ChronoUnit.HOURS),
      groups = Set.empty,
      jti = UUID.randomUUID().toString,
      amr = amr,
      authTime = authTime
    ))

  private def agentToken(): String =
    issuer.issue(JwtClaims.Agent(
      subject = "agent-evil",
      issuer = None,
      issuedAt = Instant.now(),
      expiresAt = Instant.now().plus(1, ChronoUnit.HOURS),
      parentSubject = "alice@org",
      purpose = "test",
      allowedOps = Set("Sign"),
      jti = UUID.randomUUID().toString
    ))

  private def post(token: String, body: String = """{"parent":"alice@org"}""") =
    Post("/v1/agents/revoke", HttpEntity(ContentTypes.`application/json`, body))
      .withHeaders(RawHeader("Authorization", s"Bearer $token"))

  // ── The happy path ────────────────────────────────────────────────────────

  test("a human with fresh MFA can pull the kill-switch") {
    val ks = new SpyKillSwitch

    post(humanToken()) ~> route(ks) ~> check {
      status shouldBe StatusCodes.OK
      val json = parse(responseAs[String]).toOption.get.hcursor
      json.get[String]("parent").toOption.get shouldBe "alice@org"
      json.get[Int]("alreadyRevoked").toOption.get shouldBe 2
      json.get[Int]("expired").toOption.get shouldBe 1
      json.downField("killed").values.get should have size 1
      ks.lastRequest.get.parent shouldBe "alice@org"
    }
  }

  test("issuedAfter is forwarded to the kill-switch") {
    val ks     = new SpyKillSwitch
    val cutoff = "2026-08-04T11:00:00Z"

    post(humanToken(), s"""{"parent":"alice@org","issuedAfter":"$cutoff"}""") ~> route(ks) ~> check {
      status shouldBe StatusCodes.OK
      ks.lastRequest.get.issuedAfter shouldBe Some(Instant.parse(cutoff))
    }
  }

  test("omitting issuedAfter sweeps everything live under the parent") {
    val ks = new SpyKillSwitch

    post(humanToken()) ~> route(ks) ~> check {
      ks.lastRequest.get.issuedAfter shouldBe None
    }
  }

  // ── Step-up refusals ──────────────────────────────────────────────────────

  test("a password-only credential is refused with a real WWW-Authenticate challenge") {
    val ks = new SpyKillSwitch

    post(humanToken(amr = Set("pwd"))) ~> route(ks) ~> check {
      status shouldBe StatusCodes.Unauthorized
      val challenge = header("WWW-Authenticate").get.value
      challenge should startWith("aegis-stepup ")
      challenge should include("""realm="aegis"""")
      challenge should include("max_age=")
      // Nothing was killed.
      ks.lastRequest shouldBe None
    }
  }

  test("a credential with no amr is refused") {
    val ks = new SpyKillSwitch

    post(humanToken(amr = Set.empty)) ~> route(ks) ~> check {
      status shouldBe StatusCodes.Unauthorized
      ks.lastRequest shouldBe None
    }
  }

  test("a stale MFA login is refused even though the token is still valid") {
    val ks    = new SpyKillSwitch
    val stale = humanToken(authTime = Some(Instant.now().minus(1, ChronoUnit.HOURS)))

    post(stale) ~> route(ks) ~> check {
      status shouldBe StatusCodes.Unauthorized
      header("WWW-Authenticate") should not be empty
      ks.lastRequest shouldBe None
    }
  }

  test("a credential with no auth_time is refused") {
    val ks = new SpyKillSwitch

    post(humanToken(authTime = None)) ~> route(ks) ~> check {
      status shouldBe StatusCodes.Unauthorized
      ks.lastRequest shouldBe None
    }
  }

  test("the refusal body carries the same reason as the header, for SDKs that ignore headers") {
    val ks = new SpyKillSwitch

    post(humanToken(amr = Set("pwd"))) ~> route(ks) ~> check {
      val body = parse(responseAs[String]).toOption.get.hcursor
      body.get[String]("code").toOption.get shouldBe "StepUpRequired"
      body.get[String]("message").toOption.get should include("re-authentication")
    }
  }

  test("a server configured with stricter methods refuses a credential the default would accept") {
    val ks     = new SpyKillSwitch
    val strict = StepUpPolicy(requiredMethods = Set("hwk"))

    post(humanToken(amr = Set("mfa"))) ~> route(ks, strict) ~> check {
      status shouldBe StatusCodes.Unauthorized
      // pekko-http parses the challenge into a typed HttpChallenge and re-renders it, so param order
      // and optional quoting around token-shaped values are its choice, not ours. Assert the semantic
      // content rather than an exact byte sequence.
      val challenge = header("WWW-Authenticate").get.value
      challenge should include("acr=")
      challenge should include("hwk")
      challenge should not include "mfa"
    }
  }

  test("a reason containing a quote survives pekko's re-rendering without breaking the header") {
    val ks = new SpyKillSwitch
    // A policy whose method name embeds a quote — the nastiest thing that can reach the challenge,
    // since the reason string interpolates the required-method list verbatim.
    val nasty = StepUpPolicy(requiredMethods = Set("""ev"il"""))

    post(humanToken(amr = Set("mfa"))) ~> route(ks, nasty) ~> check {
      status shouldBe StatusCodes.Unauthorized
      // The header must still parse as exactly one challenge of our scheme — if the quote had escaped
      // its quoted-string, pekko would either fail to render it or emit something malformed.
      val challenges = header[`WWW-Authenticate`].get.challenges
      challenges should have size 1
      challenges.head.scheme shouldBe "aegis-stepup"
      challenges.head.realm shouldBe "aegis"
      ks.lastRequest shouldBe None
    }
  }

  // ── Principal-kind refusals ───────────────────────────────────────────────

  test("an agent cannot pull the kill-switch on its own fleet") {
    val ks = new SpyKillSwitch

    post(agentToken()) ~> route(ks) ~> check {
      status shouldBe StatusCodes.Forbidden
      responseAs[String] should include("human principals")
      ks.lastRequest shouldBe None
    }
  }

  test("a successful response carries no WWW-Authenticate header") {
    val ks = new SpyKillSwitch

    post(humanToken()) ~> route(ks) ~> check {
      status shouldBe StatusCodes.OK
      header("WWW-Authenticate") shouldBe None
    }
  }

  // ── Unconfigured server ───────────────────────────────────────────────────

  test("no kill-switch wired → 501, and the check happens before step-up is evaluated") {
    post(humanToken(amr = Set("pwd"))) ~> routeWithout() ~> check {
      status shouldBe StatusCodes.NotImplemented
      responseAs[String] should include("aegis.audit.kind=postgres")
    }
  }
