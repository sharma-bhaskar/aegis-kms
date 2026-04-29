package dev.aegiskms.iam

import dev.aegiskms.core.{ErrorCode, Operation, Principal}
import org.scalatest.funsuite.AnyFunSuite

import java.time.Instant
import java.time.temporal.ChronoUnit

final class PrincipalResolverSpec extends AnyFunSuite:

  private val secret   = "test-secret-test-secret-test-secret-12345"
  private val issuer   = JwtIssuer.hmac(secret)
  private val verifier = JwtVerifier.hmac(secret)
  // jjwt evaluates exp against wall-clock; tokens minted with a fixed past `now` would already be expired.
  private val now = Instant.now()

  // ── dev resolver ─────────────────────────────────────────────────────────────

  test("dev resolver returns a Human with admins group from X-Aegis-User") {
    val res = PrincipalResolver.dev.resolve(authHeader = None, devUserHeader = Some("alice@org"))
    assert(res == Right(Principal.Human("alice@org", Set("admins"))))
  }

  test("dev resolver falls back to anonymous when X-Aegis-User is missing") {
    val res = PrincipalResolver.dev.resolve(authHeader = None, devUserHeader = None)
    assert(res == Right(Principal.Human("anonymous", Set("admins"))))
  }

  test("dev resolver ignores the Authorization header — it's dev-mode only") {
    val res = PrincipalResolver.dev.resolve(authHeader = Some("Bearer xyz"), devUserHeader = Some("alice"))
    assert(res == Right(Principal.Human("alice", Set("admins"))))
  }

  // ── jwt resolver — happy paths ───────────────────────────────────────────────

  test("jwt resolver verifies a Human token and returns Principal.Human with the carried groups") {
    val claims = JwtClaims.Human("alice@org", None, now, now.plus(1, ChronoUnit.HOURS), Set("admins"))
    val token  = issuer.issue(claims)
    val res    = PrincipalResolver.jwt(verifier).resolve(Some(s"Bearer $token"), devUserHeader = None)
    assert(res == Right(Principal.Human("alice@org", Set("admins"))))
  }

  test("jwt resolver verifies an Agent token and returns Principal.Agent with parent + allowedOps") {
    val claims = JwtClaims.Agent(
      subject = "claude-session-7a3",
      issuer = None,
      issuedAt = now,
      expiresAt = now.plus(1, ChronoUnit.HOURS),
      parentSubject = "alice@org",
      purpose = "claude-invoice-batch-q2",
      allowedOps = Set("Get", "Activate")
    )
    val token = issuer.issue(claims)
    val res   = PrincipalResolver.jwt(verifier).resolve(Some(s"Bearer $token"), devUserHeader = None)
    val agent = res.toOption.get.asInstanceOf[Principal.Agent]
    assert(agent.subject == "claude-session-7a3")
    assert(agent.operator == Principal.Human("alice@org", Set.empty))
    assert(agent.allowedOps == Set(Operation.Get, Operation.Activate))
    assert(agent.purpose == "claude-invoice-batch-q2")
  }

  test("jwt resolver silently ignores X-Aegis-User — no fallback to dev when JWT is missing") {
    val res = PrincipalResolver.jwt(verifier).resolve(authHeader = None, devUserHeader = Some("alice"))
    assert(res.left.toOption.map(_.code).contains(ErrorCode.AuthenticationNotSuccessful))
  }

  // ── jwt resolver — failure modes ─────────────────────────────────────────────

  test("missing Authorization header → AuthenticationNotSuccessful") {
    val res = PrincipalResolver.jwt(verifier).resolve(authHeader = None, devUserHeader = None)
    assert(res.left.toOption.map(_.code).contains(ErrorCode.AuthenticationNotSuccessful))
    assert(res.left.toOption.exists(_.message.contains("missing")))
  }

  test("malformed bearer header (wrong scheme) is rejected") {
    val res = PrincipalResolver.jwt(verifier).resolve(Some("Basic abc"), devUserHeader = None)
    assert(res.left.toOption.map(_.code).contains(ErrorCode.AuthenticationNotSuccessful))
  }

  test("expired JWT surfaces as AuthenticationNotSuccessful with reason") {
    val claims = JwtClaims.Human(
      subject = "alice",
      issuer = None,
      issuedAt = now.minus(2, ChronoUnit.HOURS),
      expiresAt = now.minus(1, ChronoUnit.HOURS),
      groups = Set.empty
    )
    val token = issuer.issue(claims)
    val res   = PrincipalResolver.jwt(verifier).resolve(Some(s"Bearer $token"), None)
    assert(res.left.toOption.exists(_.message.toLowerCase.contains("expired")))
  }

  test("token signed with a different secret is rejected") {
    val claims      = JwtClaims.Human("alice", None, now, now.plus(1, ChronoUnit.HOURS), Set.empty)
    val otherIssuer = JwtIssuer.hmac("an-entirely-different-32-byte-secret-pls")
    val token       = otherIssuer.issue(claims)
    val res         = PrincipalResolver.jwt(verifier).resolve(Some(s"Bearer $token"), None)
    assert(res.left.toOption.exists(_.message.contains("signature")))
  }
