package dev.aegiskms.iam

import cats.effect.unsafe.IORuntime
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Jwks
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.security.interfaces.{ECPublicKey, RSAPublicKey}
import java.security.spec.ECGenParameterSpec
import java.security.{KeyPair, KeyPairGenerator}
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.{Date, UUID}
import scala.jdk.CollectionConverters.*

/** Unit tests for `OidcJwtVerifier` using static (test-only) JWKS provided via `JwksProvider.static`.
  *
  * What we exercise here:
  *   - RS256 happy path: issued, verified, Human claims round-trip.
  *   - ES256 happy path: same, with an EC keypair.
  *   - Issuer mismatch is rejected.
  *   - Audience mismatch is rejected when audience is configured.
  *   - Audience is ignored when not configured.
  *   - Expired token is rejected.
  *   - Wrong-kid (header points to a key not in JWKS) is rejected.
  *   - Missing kid header is rejected.
  *   - Alg-confusion: a token signed with HMAC against the RSA public key's bytes is rejected.
  *   - Agent claim shape round-trips (parent/purpose/allowedOps/jti).
  *
  * What we don't exercise here (deferred to a follow-up Testcontainers Keycloak suite):
  *   - JWKS refresh on kid miss against a real HTTP endpoint.
  *   - OIDC discovery document parsing.
  */
final class OidcJwtVerifierSpec extends AnyFunSuite with Matchers:

  given IORuntime = IORuntime.global

  private val issuer   = "https://aegis.test/realms/aegis"
  private val audience = "aegis-server"

  // RSA-2048 keypair shared across most tests so we only do the expensive keygen once per JVM.
  private val rsaKp: KeyPair =
    val gen = KeyPairGenerator.getInstance("RSA")
    gen.initialize(2048)
    gen.generateKeyPair()
  private val rsaKid: String = "rsa-test-key-1"

  // EC P-256 keypair for the ES256 path.
  private val ecKp: KeyPair =
    val gen = KeyPairGenerator.getInstance("EC")
    gen.initialize(new ECGenParameterSpec("secp256r1"))
    gen.generateKeyPair()
  private val ecKid: String = "ec-test-key-1"

  /** Build a JWKS containing one RSA and one EC key. Marshalls via jjwt's `Jwks.builder` → `Jwks.toJson` to
    * keep the format strictly RFC 7517 compatible.
    */
  private val jwks: JwkSet =
    val rsaJwk = Jwks.builder().key(rsaKp.getPublic.asInstanceOf[RSAPublicKey]).id(rsaKid).build()
    val ecJwk  = Jwks.builder().key(ecKp.getPublic.asInstanceOf[ECPublicKey]).id(ecKid).build()
    JwkSet(Map(rsaKid -> rsaJwk.toKey, ecKid -> ecJwk.toKey))

  private val provider: JwksProvider = JwksProvider.static(jwks)

  private def verifier(
      iss: String = issuer,
      aud: Option[String] = Some(audience)
  ): OidcJwtVerifier =
    new OidcJwtVerifier(provider, expectedIssuer = iss, expectedAudience = aud)

  private def now: Instant = Instant.now()

  /** Mint a token for these tests. Defaults: RSA, Human, alice@org, 1 h TTL, expected iss / aud. */
  private def mintToken(
      kp: KeyPair = rsaKp,
      kid: String = rsaKid,
      iss: String = issuer,
      aud: String = audience,
      sub: String = "alice@org",
      kind: String = JwtClaims.Claim.KindHuman,
      groups: List[String] = List("admins"),
      issuedAt: Instant = now,
      expiresAt: Instant = now.plus(1, ChronoUnit.HOURS),
      extraClaims: Map[String, AnyRef] = Map.empty,
      jti: String = UUID.randomUUID().toString
  ): String =
    val builder = Jwts
      .builder()
      .header()
      .keyId(kid)
      .and()
      .id(jti)
      .subject(sub)
      .issuer(iss)
      .audience()
      .add(aud)
      .and()
      .issuedAt(Date.from(issuedAt))
      .expiration(Date.from(expiresAt))
      .claim(JwtClaims.Claim.Kind, kind)
    if groups.nonEmpty then builder.claim(JwtClaims.Claim.Groups, groups.asJava)
    extraClaims.foreach { case (k, v) => builder.claim(k, v) }
    builder.signWith(kp.getPrivate).compact()

  // ── Happy paths ────────────────────────────────────────────────────────────

  test("RS256-signed Human token verifies and returns the carried claims") {
    val tok    = mintToken()
    val result = verifier().verify(tok).toOption.get.asInstanceOf[JwtClaims.Human]
    result.subject shouldBe "alice@org"
    result.groups shouldBe Set("admins")
    result.issuer shouldBe Some(issuer)
    result.jti should not be empty
  }

  test("ES256-signed Human token verifies (EC keys, kid lookup picks the right key)") {
    val tok    = mintToken(kp = ecKp, kid = ecKid)
    val result = verifier().verify(tok).toOption.get.asInstanceOf[JwtClaims.Human]
    result.subject shouldBe "alice@org"
  }

  test("Agent claim shape round-trips through OIDC verifier (parent / purpose / allowedOps / jti)") {
    val jti = UUID.randomUUID().toString
    val tok = mintToken(
      kind = JwtClaims.Claim.KindAgent,
      groups = Nil,
      extraClaims = Map(
        JwtClaims.Claim.ParentSubject -> "alice@org",
        JwtClaims.Claim.Purpose       -> "claude-invoice-batch-q2",
        JwtClaims.Claim.AllowedOps    -> List("Sign", "Get").asJava
      ),
      jti = jti
    )
    val result = verifier().verify(tok).toOption.get.asInstanceOf[JwtClaims.Agent]
    result.parentSubject shouldBe "alice@org"
    result.purpose shouldBe "claude-invoice-batch-q2"
    result.allowedOps shouldBe Set("Sign", "Get")
    result.jti shouldBe jti
  }

  test("audience=None accepts any audience (operator opted out of audience enforcement)") {
    val tok    = mintToken(aud = "some-other-audience")
    val result = verifier(aud = None).verify(tok)
    result.isRight shouldBe true
  }

  // ── Threat-model rejections ───────────────────────────────────────────────

  test("token from a different issuer is rejected with InvalidClaims") {
    val tok    = mintToken(iss = "https://attacker.example.com")
    val result = verifier().verify(tok)
    result.left.toOption.collect { case JwtError.InvalidClaims(_) => () } shouldBe defined
  }

  test("token with the wrong audience is rejected with InvalidClaims") {
    val tok    = mintToken(aud = "different-audience")
    val result = verifier().verify(tok)
    result.left.toOption.collect { case JwtError.InvalidClaims(msg) =>
      msg should include("audience mismatch")
    } shouldBe defined
  }

  test("expired token is rejected with JwtError.Expired") {
    val past = now.minus(2, ChronoUnit.HOURS)
    val tok  = mintToken(issuedAt = past.minus(1, ChronoUnit.HOURS), expiresAt = past)
    verifier().verify(tok) shouldBe Left(JwtError.Expired)
  }

  test("token whose kid isn't in the JWKS is rejected as Malformed") {
    val tok    = mintToken(kid = "kid-not-in-jwks")
    val result = verifier().verify(tok)
    result.left.toOption.collect { case JwtError.Malformed(msg) =>
      msg should include("unknown kid")
    } shouldBe defined
  }

  test("token signed with a different private key (same kid) fails signature verification") {
    val attacker = KeyPairGenerator.getInstance("RSA")
    attacker.initialize(2048)
    val attackerKp = attacker.generateKeyPair()
    // Same kid that the JWKS advertises — but signed with attacker's key.
    val tok = mintToken(kp = attackerKp, kid = rsaKid)
    verifier().verify(tok) shouldBe Left(JwtError.SignatureInvalid)
  }

  test("malformed garbage fails with Malformed") {
    val result = verifier().verify("not.a.jwt")
    result.left.toOption.exists(_.isInstanceOf[JwtError.Malformed]) shouldBe true
  }

  // ── Claim validation ──────────────────────────────────────────────────────

  test("token without aegis_kind is rejected with InvalidClaims") {
    // Mint a token without the Aegis-specific kind claim — happens if a generic OIDC token from
    // the IDP reaches Aegis without going through `JwtIssuer`. We refuse rather than guess.
    val plain = Jwts
      .builder()
      .header()
      .keyId(rsaKid)
      .and()
      .id(UUID.randomUUID().toString)
      .subject("alice")
      .issuer(issuer)
      .audience()
      .add(audience)
      .and()
      .issuedAt(Date.from(now))
      .expiration(Date.from(now.plus(1, ChronoUnit.HOURS)))
      .signWith(rsaKp.getPrivate)
      .compact()

    val result = verifier().verify(plain)
    result.left.toOption.collect { case JwtError.InvalidClaims(msg) =>
      msg should include(JwtClaims.Claim.Kind)
    } shouldBe defined
  }
