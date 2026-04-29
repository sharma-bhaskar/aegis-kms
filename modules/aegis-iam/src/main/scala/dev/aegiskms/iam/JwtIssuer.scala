package dev.aegiskms.iam

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys

import java.nio.charset.StandardCharsets
import java.util.Date
import javax.crypto.SecretKey
import scala.jdk.CollectionConverters.*

/** Mints a JWS for the supplied [[JwtClaims]].
  *
  * v0.1.0 ships an HMAC-SHA256 (HS256) issuer. RSA / ECDSA issuers and an HTTP `POST /v1/agents/issue`
  * endpoint that consumes this trait are scoped for v0.2.0 (PR A1). The trait exists in v0.1.0 so:
  *   - Tests can mint real tokens to feed [[JwtVerifier]].
  *   - Embedders that want to issue tokens out-of-band (e.g. via SDK rather than HTTP) can do so today.
  */
trait JwtIssuer:
  def issue(claims: JwtClaims): String

object JwtIssuer:

  /** HMAC-SHA256 issuer paired with [[JwtVerifier.hmac]]. Symmetric key — use only inside a single trust
    * boundary (this is fine for self-issued agent tokens, not fine for cross-org federation).
    */
  def hmac(secret: String): JwtIssuer =
    val bytes = secret.getBytes(StandardCharsets.UTF_8)
    require(bytes.length >= 32, s"HMAC secret must be ≥32 bytes, was ${bytes.length}")
    new HmacJwtIssuer(Keys.hmacShaKeyFor(bytes))

  // ── Impl ─────────────────────────────────────────────────────────────────────

  final private class HmacJwtIssuer(key: SecretKey) extends JwtIssuer:
    def issue(claims: JwtClaims): String =
      val builder = Jwts
        .builder()
        .subject(claims.subject)
        .issuedAt(Date.from(claims.issuedAt))
        .expiration(Date.from(claims.expiresAt))

      claims.issuer.foreach(builder.issuer)

      claims match
        case h: JwtClaims.Human =>
          builder.claim(JwtClaims.Claim.Kind, JwtClaims.Claim.KindHuman)
          if h.groups.nonEmpty then
            builder.claim(JwtClaims.Claim.Groups, h.groups.toList.asJava)
        case a: JwtClaims.Agent =>
          builder.claim(JwtClaims.Claim.Kind, JwtClaims.Claim.KindAgent)
          builder.claim(JwtClaims.Claim.ParentSubject, a.parentSubject)
          builder.claim(JwtClaims.Claim.Purpose, a.purpose)
          if a.allowedOps.nonEmpty then
            builder.claim(JwtClaims.Claim.AllowedOps, a.allowedOps.toList.asJava)

      builder.signWith(key).compact()
