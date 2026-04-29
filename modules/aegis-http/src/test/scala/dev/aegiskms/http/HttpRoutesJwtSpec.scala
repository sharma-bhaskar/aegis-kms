package dev.aegiskms.http

import cats.effect.unsafe.IORuntime
import dev.aegiskms.core.KeyService
import dev.aegiskms.iam.{JwtClaims, JwtIssuer, JwtVerifier, PrincipalResolver}
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.model.headers.RawHeader
import org.apache.pekko.http.scaladsl.server.Route
import org.apache.pekko.http.scaladsl.testkit.ScalatestRouteTest
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import java.time.temporal.ChronoUnit

/** End-to-end tests for the JWT bearer auth path through the HTTP layer.
  *
  * Pairs `JwtIssuer.hmac` with `PrincipalResolver.jwt(JwtVerifier.hmac)` to mint a real token, hand it to the
  * routes, and assert the request lands as the right Principal. Mirror tests in `PrincipalResolverSpec` cover
  * the resolver in isolation; this suite adds the wire-level proof that the `Authorization` header makes it
  * through Tapir → routes → service.
  */
final class HttpRoutesJwtSpec extends AnyFunSuite with Matchers with ScalatestRouteTest:

  private given IORuntime = IORuntime.global

  // 32+ bytes — required for HS256
  private val secret   = "test-secret-test-secret-test-secret-12345"
  private val verifier = JwtVerifier.hmac(secret)
  private val issuer   = JwtIssuer.hmac(secret)

  private def jwtRoute(): Route =
    HttpRoutes(KeyService.inMemory.unsafeRunSync(), PrincipalResolver.jwt(verifier)).routes

  private val createBody =
    """{"spec":{"name":"invoice-signing","algorithm":"AES","sizeBits":256,"objectType":"SymmetricKey"}}"""

  private def jsonEntity(body: String): RequestEntity =
    HttpEntity(ContentTypes.`application/json`, body)

  private def humanToken(subject: String, groups: Set[String] = Set("admins")): String =
    val now = Instant.now()
    issuer.issue(JwtClaims.Human(subject, None, now, now.plus(1, ChronoUnit.HOURS), groups))

  test("POST /v1/keys with a valid Bearer token succeeds (201)") {
    val token = humanToken("alice@org")
    val req = Post("/v1/keys", jsonEntity(createBody))
      .withHeaders(RawHeader("Authorization", s"Bearer $token"))
    req ~> jwtRoute() ~> check {
      status shouldBe StatusCodes.Created
    }
  }

  test("POST /v1/keys with NO Authorization header returns 401") {
    Post("/v1/keys", jsonEntity(createBody)) ~> jwtRoute() ~> check {
      status shouldBe StatusCodes.Unauthorized
      val body = responseAs[String]
      body should include(""""code":"AuthenticationNotSuccessful"""")
    }
  }

  test("POST /v1/keys with a malformed bearer token returns 401") {
    val req = Post("/v1/keys", jsonEntity(createBody))
      .withHeaders(RawHeader("Authorization", "Bearer not.a.real.jwt"))
    req ~> jwtRoute() ~> check {
      status shouldBe StatusCodes.Unauthorized
    }
  }

  test("POST /v1/keys with an expired token returns 401") {
    val past   = Instant.now().minus(1, ChronoUnit.HOURS)
    val claims = JwtClaims.Human("alice", None, past.minus(1, ChronoUnit.HOURS), past, Set("admins"))
    val token  = issuer.issue(claims)
    val req = Post("/v1/keys", jsonEntity(createBody))
      .withHeaders(RawHeader("Authorization", s"Bearer $token"))
    req ~> jwtRoute() ~> check {
      status shouldBe StatusCodes.Unauthorized
    }
  }

  test("X-Aegis-User is silently ignored when the resolver is JWT") {
    val req = Post("/v1/keys", jsonEntity(createBody))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> jwtRoute() ~> check {
      status shouldBe StatusCodes.Unauthorized
    }
  }

  test("a token signed with a different secret is rejected") {
    val otherIssuer = JwtIssuer.hmac("a-different-32-byte-shared-secret-yo!")
    val now         = Instant.now()
    val token       = otherIssuer.issue(JwtClaims.Human("alice", None, now, now.plusSeconds(60), Set.empty))
    val req = Post("/v1/keys", jsonEntity(createBody))
      .withHeaders(RawHeader("Authorization", s"Bearer $token"))
    req ~> jwtRoute() ~> check {
      status shouldBe StatusCodes.Unauthorized
    }
  }
