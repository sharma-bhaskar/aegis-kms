package dev.aegiskms.iam

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import dev.aegiskms.core.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import scala.concurrent.duration.*

/** Tests for `AgentTokenIssuer` — the domain-level "human issues an agent" service backing `POST
  * /v1/agents/issue` (#18).
  *
  * The properties exercised here pin the spec's authz invariants:
  *
  *   1. Only Humans can issue agents (Service and Agent callers refused). 2. The agent JWT round-trips
  *      through the verifier with the expected claims (parent, scopes, TTL). 3. TTL is capped at 24 h; scopes
  *      must parse as Operation names; label must be non-empty. 4. `parent` in the body, when present, must
  *      match the caller's subject (no cross-principal issuance in v0.2.0).
  */
final class AgentTokenIssuerSpec extends AnyFunSuite with Matchers:

  // 32+ bytes for HS256
  private val secret   = "test-secret-test-secret-test-secret-12345"
  private val signer   = JwtIssuer.hmac(secret)
  private val verifier = JwtVerifier.hmac(secret)

  // Fixed clock so we can assert on exact expiresAt.
  private val fixedNow = Instant.parse("2026-05-19T10:00:00Z")

  private def issuer(maxTtl: FiniteDuration = AgentTokenIssuer.DefaultMaxTtl): AgentTokenIssuer =
    new AgentTokenIssuer(
      signer,
      issuerName = Some("https://aegis.local"),
      maxTtl = maxTtl,
      now = IO.pure(fixedNow)
    )

  private val alice: Principal.Human = Principal.Human("alice@org", Set("admins"))

  // ── Happy path ────────────────────────────────────────────────────────────

  test("Human caller successfully issues an agent token with the expected claims") {
    val req = IssueAgentRequest(
      label = "claude-invoice-batch-q2",
      scopes = List("Sign", "Get"),
      ttl = 1.hour
    )
    val token = issuer().issue(alice, req).unsafeRunSync().toOption.get

    token.agentId should startWith("agent-")
    token.jti should not be empty
    token.expiresAt shouldBe fixedNow.plusSeconds(3600)

    // Verifier sees the right claims.
    val claims = verifier.verify(token.jwt).toOption.get.asInstanceOf[JwtClaims.Agent]
    claims.subject shouldBe token.agentId
    claims.parentSubject shouldBe "alice@org"
    claims.purpose shouldBe "claude-invoice-batch-q2"
    claims.allowedOps shouldBe Set("Sign", "Get")
    claims.jti shouldBe token.jti
    claims.issuer shouldBe Some("https://aegis.local")
  }

  test("label is trimmed before going into the purpose claim") {
    val req    = IssueAgentRequest("  invoice-signing  ", List("Get"), 1.hour)
    val token  = issuer().issue(alice, req).unsafeRunSync().toOption.get
    val claims = verifier.verify(token.jwt).toOption.get.asInstanceOf[JwtClaims.Agent]
    claims.purpose shouldBe "invoice-signing"
  }

  // ── Authz ────────────────────────────────────────────────────────────────

  test("Service callers are refused with PermissionDenied") {
    val sys = Principal.Service("aegis-system", TenantId("system"))
    val res = issuer().issue(sys, IssueAgentRequest("x", List("Get"), 1.hour)).unsafeRunSync()
    res.left.toOption.map(_.code) shouldBe Some(ErrorCode.PermissionDenied)
    res.left.toOption.get.message should include("service")
  }

  test("Agent callers are refused with PermissionDenied (agents cannot issue agents)") {
    val ag = Principal.Agent(
      subject = "agent-abc",
      operator = alice,
      purpose = "test",
      issuedAt = fixedNow,
      ttl = 1.hour,
      allowedOps = Set.empty,
      parent = None
    )
    val res = issuer().issue(ag, IssueAgentRequest("x", List("Get"), 1.hour)).unsafeRunSync()
    res.left.toOption.map(_.code) shouldBe Some(ErrorCode.PermissionDenied)
    res.left.toOption.get.message should include("agents cannot issue agents")
  }

  // ── Validation ────────────────────────────────────────────────────────────

  test("empty label is rejected with InvalidField") {
    val res = issuer().issue(alice, IssueAgentRequest("   ", List("Get"), 1.hour)).unsafeRunSync()
    res.left.toOption.map(_.code) shouldBe Some(ErrorCode.InvalidField)
    res.left.toOption.get.message should include("label")
  }

  test("empty scopes is rejected with InvalidField") {
    val res = issuer().issue(alice, IssueAgentRequest("x", Nil, 1.hour)).unsafeRunSync()
    res.left.toOption.map(_.code) shouldBe Some(ErrorCode.InvalidField)
    res.left.toOption.get.message should include("scopes")
  }

  test("zero TTL is rejected with InvalidField") {
    val res = issuer().issue(alice, IssueAgentRequest("x", List("Get"), 0.seconds)).unsafeRunSync()
    res.left.toOption.map(_.code) shouldBe Some(ErrorCode.InvalidField)
    res.left.toOption.get.message should include("ttl")
  }

  test("TTL above the configured maximum is rejected with InvalidField") {
    val res = issuer(maxTtl = 1.hour)
      .issue(alice, IssueAgentRequest("x", List("Get"), 2.hours))
      .unsafeRunSync()
    res.left.toOption.map(_.code) shouldBe Some(ErrorCode.InvalidField)
    res.left.toOption.get.message should include("exceeds maximum")
  }

  test("an unknown operation name in scopes is rejected with InvalidField") {
    val res = issuer()
      .issue(alice, IssueAgentRequest("x", List("Sign", "NotARealOp"), 1.hour))
      .unsafeRunSync()
    res.left.toOption.map(_.code) shouldBe Some(ErrorCode.InvalidField)
    res.left.toOption.get.message should include("NotARealOp")
  }

  test("parent in the body matching the caller is accepted") {
    val req = IssueAgentRequest(
      "x",
      List("Get"),
      1.hour,
      parent = Some("alice@org"),
      callerSubject = Some("alice@org")
    )
    val res = issuer().issue(alice, req).unsafeRunSync()
    res.isRight shouldBe true
  }

  test("parent in the body not matching the caller is rejected") {
    val req =
      IssueAgentRequest("x", List("Get"), 1.hour, parent = Some("bob@org"), callerSubject = Some("alice@org"))
    val res = issuer().issue(alice, req).unsafeRunSync()
    res.left.toOption.map(_.code) shouldBe Some(ErrorCode.InvalidField)
    res.left.toOption.get.message should include("cross-principal")
  }

  test("agentId is fresh on every issuance (UUID, not constant)") {
    val req = IssueAgentRequest("x", List("Get"), 1.hour)
    val t1  = issuer().issue(alice, req).unsafeRunSync().toOption.get
    val t2  = issuer().issue(alice, req).unsafeRunSync().toOption.get
    t1.agentId should not equal t2.agentId
    t1.jti should not equal t2.jti
  }
