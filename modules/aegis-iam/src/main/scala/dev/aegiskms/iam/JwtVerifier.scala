package dev.aegiskms.iam

import io.jsonwebtoken.security.{Keys, SignatureException}
import io.jsonwebtoken.{Claims, ExpiredJwtException, JwtException, Jwts, MalformedJwtException}

import java.nio.charset.StandardCharsets
import java.time.Instant
import javax.crypto.SecretKey
import scala.jdk.CollectionConverters.*
import scala.util.{Failure, Success, Try}

/** Verifies a JWS bearer token and returns the strongly-typed [[JwtClaims]].
  *
  * v0.1.0 ships a single implementation: HMAC-SHA256 (`HS256`). RSA / ECDSA verification (RS256, ES256) and
  * full OIDC discovery / JWKS rotation are deferred to v0.2.0; the trait shape is the integration seam.
  *
  * Embedders constructing their own verifier should observe these invariants:
  *   - Always validate `exp` (the default jjwt parser does this; don't disable it).
  *   - Always validate the signature against a key the operator trusts (don't accept `alg=none`).
  *   - Translate jjwt exceptions to the typed [[JwtError]] ADT — the rest of the system expects an
  *     `Either[JwtError, JwtClaims]`, not raised exceptions.
  */
trait JwtVerifier:
  def verify(token: String): Either[JwtError, JwtClaims]

enum JwtError:
  case Malformed(message: String)
  case SignatureInvalid
  case Expired
  case InvalidClaims(message: String)

object JwtVerifier:

  /** Build a verifier that accepts `HS256` JWTs signed with the supplied shared secret.
    *
    * The secret must be at least 32 bytes (256 bits) — jjwt rejects shorter keys for HS256 by spec. The
    * caller is responsible for keeping the secret out of source control (env var, secret manager, etc.).
    */
  def hmac(secret: String): JwtVerifier =
    val bytes = secret.getBytes(StandardCharsets.UTF_8)
    require(bytes.length >= 32, s"HMAC secret must be ≥32 bytes, was ${bytes.length}")
    new HmacJwtVerifier(Keys.hmacShaKeyFor(bytes))

  // ── Impl ─────────────────────────────────────────────────────────────────────

  final private class HmacJwtVerifier(key: SecretKey) extends JwtVerifier:
    def verify(token: String): Either[JwtError, JwtClaims] =
      Try(Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload) match
        case Success(claims)                   => extract(claims)
        case Failure(_: ExpiredJwtException)   => Left(JwtError.Expired)
        case Failure(_: MalformedJwtException) => Left(JwtError.Malformed("malformed JWT"))
        case Failure(_: SignatureException)    => Left(JwtError.SignatureInvalid)
        case Failure(e: JwtException)          => Left(JwtError.Malformed(e.getMessage))
        case Failure(e)                        => Left(JwtError.Malformed(e.getMessage))

  // ── Claims extraction ────────────────────────────────────────────────────────

  private def extract(claims: Claims): Either[JwtError, JwtClaims] =
    val subject  = Option(claims.getSubject).getOrElse("")
    val issuer   = Option(claims.getIssuer)
    val issuedAt = Option(claims.getIssuedAt).map(_.toInstant).getOrElse(Instant.EPOCH)
    val expires  = Option(claims.getExpiration).map(_.toInstant).getOrElse(Instant.EPOCH)

    if subject.isEmpty then Left(JwtError.InvalidClaims("missing required claim: sub"))
    else
      Option(claims.get(JwtClaims.Claim.Kind, classOf[String])) match
        case Some(JwtClaims.Claim.KindHuman) =>
          val groups = stringList(claims, JwtClaims.Claim.Groups).toSet
          Right(JwtClaims.Human(subject, issuer, issuedAt, expires, groups))
        case Some(JwtClaims.Claim.KindAgent) =>
          for
            parent  <- requiredString(claims, JwtClaims.Claim.ParentSubject)
            purpose <- requiredString(claims, JwtClaims.Claim.Purpose)
          yield JwtClaims.Agent(
            subject = subject,
            issuer = issuer,
            issuedAt = issuedAt,
            expiresAt = expires,
            parentSubject = parent,
            purpose = purpose,
            allowedOps = stringList(claims, JwtClaims.Claim.AllowedOps).toSet
          )
        case Some(other) =>
          Left(JwtError.InvalidClaims(s"unknown ${JwtClaims.Claim.Kind}=$other"))
        case None =>
          Left(JwtError.InvalidClaims(s"missing required claim: ${JwtClaims.Claim.Kind}"))

  private def requiredString(claims: Claims, name: String): Either[JwtError, String] =
    Option(claims.get(name, classOf[String])) match
      case Some(s) if s.nonEmpty => Right(s)
      case _                     => Left(JwtError.InvalidClaims(s"missing required claim: $name"))

  /** Read a JSON-array claim as a `List[String]`. jjwt deserializes JSON arrays to `java.util.List`; cast and
    * filter to strings, ignoring any non-string entries rather than failing the whole token (a corrupt single
    * entry shouldn't deny an otherwise valid token).
    */
  private def stringList(claims: Claims, name: String): List[String] =
    Option(claims.get(name, classOf[java.util.List[?]])) match
      case Some(jl) =>
        jl.asScala.iterator.collect { case s: String => s }.toList
      case None => Nil
