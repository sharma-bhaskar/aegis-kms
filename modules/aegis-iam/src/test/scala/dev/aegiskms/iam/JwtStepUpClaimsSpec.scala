package dev.aegiskms.iam

import dev.aegiskms.core.Principal
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/** Round-trip tests for the step-up claims (#102): issuer → wire → verifier → `Principal`.
  *
  * The policy itself is covered by `StepUpPolicySpec`. What is pinned here is that `amr` and `auth_time`
  * actually survive the JWT round-trip and reach the `Principal` the policy inspects — if they were dropped
  * anywhere along that path, every caller would silently fail step-up and the kill-switch would be
  * unreachable rather than protected.
  */
final class JwtStepUpClaimsSpec extends AnyFunSuite with Matchers:

  private val secret   = "test-secret-test-secret-test-secret-12345"
  private val issuer   = JwtIssuer.hmac(secret)
  private val verifier = JwtVerifier.hmac(secret)
  private val now      = Instant.now().truncatedTo(ChronoUnit.SECONDS)

  private def humanClaims(
      amr: Set[String] = Set("mfa"),
      authTime: Option[Instant] = Some(Instant.now().truncatedTo(ChronoUnit.SECONDS))
  ) = JwtClaims.Human(
    subject = "alice@org",
    issuer = None,
    issuedAt = now,
    expiresAt = now.plus(1, ChronoUnit.HOURS),
    groups = Set("operators"),
    jti = UUID.randomUUID().toString,
    amr = amr,
    authTime = authTime
  )

  private def roundTrip(c: JwtClaims.Human): JwtClaims.Human =
    verifier.verify(issuer.issue(c)).toOption.get.asInstanceOf[JwtClaims.Human]

  test("amr survives the round-trip") {
    roundTrip(humanClaims(amr = Set("mfa", "pwd"))).amr shouldBe Set("mfa", "pwd")
  }

  test("auth_time survives the round-trip at second precision") {
    val t = Instant.parse("2026-08-05T11:59:00Z")
    roundTrip(humanClaims(authTime = Some(t))).authTime shouldBe Some(t)
  }

  test("an omitted amr comes back empty, not null") {
    roundTrip(humanClaims(amr = Set.empty)).amr shouldBe empty
  }

  test("an omitted auth_time comes back as None") {
    roundTrip(humanClaims(authTime = None)).authTime shouldBe None
  }

  test("a token minted before step-up existed still verifies, carrying neither claim") {
    // Exactly what an older Aegis build emitted: no amr, no auth_time.
    val legacy = JwtClaims.Human(
      subject = "alice@org",
      issuer = None,
      issuedAt = now,
      expiresAt = now.plus(1, ChronoUnit.HOURS),
      groups = Set.empty,
      jti = UUID.randomUUID().toString
    )
    val back = roundTrip(legacy)

    back.subject shouldBe "alice@org"
    back.amr shouldBe empty
    back.authTime shouldBe None
    // …and it must therefore fail step-up rather than pass it.
    StepUpPolicy().check(Principal.Human(back.subject, back.groups, back.amr, back.authTime), now)
      .isLeft shouldBe true
  }

  test("the resolver carries amr and auth_time onto the Principal the policy inspects") {
    val authTime = Instant.parse("2026-08-05T11:58:00Z")
    val token    = issuer.issue(humanClaims(amr = Set("hwk"), authTime = Some(authTime)))

    val principal = PrincipalResolver.jwt(verifier).resolve(Some(s"Bearer $token"), None).toOption.get

    principal shouldBe a[Principal.Human]
    val h = principal.asInstanceOf[Principal.Human]
    h.amr shouldBe Set("hwk")
    h.authTime shouldBe Some(authTime)
  }

  test("agent tokens are unaffected by the human-only step-up claims") {
    val agent = JwtClaims.Agent(
      subject = "agent-7a3",
      issuer = None,
      issuedAt = now,
      expiresAt = now.plus(1, ChronoUnit.HOURS),
      parentSubject = "alice@org",
      purpose = "test",
      allowedOps = Set("Sign"),
      jti = UUID.randomUUID().toString
    )

    verifier.verify(issuer.issue(agent)).toOption.get shouldBe a[JwtClaims.Agent]
  }
