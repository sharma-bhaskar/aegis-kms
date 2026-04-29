package dev.aegiskms.iam

import org.scalatest.funsuite.AnyFunSuite

import java.time.Instant
import java.time.temporal.ChronoUnit

/** Round-trips JwtIssuer → JwtVerifier for both Human and Agent claim shapes, and verifies the negative paths
  * the verifier promises (expired, malformed, bad signature, wrong kind).
  *
  * The HMAC path is the only one shipped in v0.1.0, so the suite covers HS256 only. RSA / ES256 land in
  * v0.2.0 along with OIDC / JWKS.
  */
final class JwtRoundTripSpec extends AnyFunSuite:

  // 32+ bytes — required by jjwt for HS256
  private val secret   = "test-secret-test-secret-test-secret-12345"
  private val issuer   = JwtIssuer.hmac(secret)
  private val verifier = JwtVerifier.hmac(secret)

  // Use real wall-clock time — jjwt's parser evaluates `exp` against `Instant.now()` and there's no clock
  // injection seam on the verifier surface yet. Tests pass `now` in to keep timestamps consistent within
  // a single test, but the absolute value must be close to wall-clock so issued tokens haven't already
  // expired by the time the parser checks them.
  private val now = Instant.now()

  test("Human claim survives issue → verify with subject, groups, issuer, exp/iat") {
    val claims = JwtClaims.Human(
      subject = "alice@org",
      issuer = Some("https://aegis.local"),
      issuedAt = now,
      expiresAt = now.plus(1, ChronoUnit.HOURS),
      groups = Set("admins", "sre")
    )
    val token = issuer.issue(claims)
    val back  = verifier.verify(token).toOption.get.asInstanceOf[JwtClaims.Human]
    assert(back.subject == "alice@org")
    assert(back.groups == Set("admins", "sre"))
    assert(back.issuer.contains("https://aegis.local"))
    // JWT exp/iat are encoded as seconds-since-epoch — round-trip truncates sub-second precision.
    assert(back.issuedAt.getEpochSecond == now.getEpochSecond)
  }

  test("Agent claim carries parent, purpose, allowedOps") {
    val claims = JwtClaims.Agent(
      subject = "claude-session-7a3",
      issuer = Some("https://aegis.local"),
      issuedAt = now,
      expiresAt = now.plus(1, ChronoUnit.HOURS),
      parentSubject = "alice@org",
      purpose = "claude-invoice-batch-q2",
      allowedOps = Set("Get", "Activate")
    )
    val token = issuer.issue(claims)
    val back  = verifier.verify(token).toOption.get.asInstanceOf[JwtClaims.Agent]
    assert(back.parentSubject == "alice@org")
    assert(back.purpose == "claude-invoice-batch-q2")
    assert(back.allowedOps == Set("Get", "Activate"))
  }

  test("expired token is rejected with JwtError.Expired") {
    val claims = JwtClaims.Human(
      subject = "alice@org",
      issuer = None,
      issuedAt = now.minus(2, ChronoUnit.HOURS),
      expiresAt = now.minus(1, ChronoUnit.HOURS),
      groups = Set.empty
    )
    val token  = issuer.issue(claims)
    val result = verifier.verify(token)
    assert(result == Left(JwtError.Expired))
  }

  test("token signed with a different secret fails with SignatureInvalid") {
    val claims = JwtClaims.Human("alice@org", None, now, now.plusSeconds(60), Set.empty)
    val token  = issuer.issue(claims)
    val other  = JwtVerifier.hmac("a-totally-different-secret-also-32+bytes")
    assert(other.verify(token) == Left(JwtError.SignatureInvalid))
  }

  test("garbage string fails with JwtError.Malformed") {
    val result = verifier.verify("not.a.jwt")
    assert(result.isLeft)
    assert(result.left.toOption.exists(_.isInstanceOf[JwtError.Malformed]))
  }

  test("hmac() rejects secrets shorter than 32 bytes at construction time") {
    val ex = intercept[IllegalArgumentException](JwtVerifier.hmac("too-short"))
    assert(ex.getMessage.contains("≥32 bytes"))
  }
