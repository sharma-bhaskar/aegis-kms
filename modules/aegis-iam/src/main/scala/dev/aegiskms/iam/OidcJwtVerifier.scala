package dev.aegiskms.iam

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import io.jsonwebtoken.security.SignatureException
import io.jsonwebtoken.{
  Claims,
  ExpiredJwtException,
  Header,
  Jwts,
  Locator,
  MalformedJwtException,
  UnsupportedJwtException
}

import java.security.Key
import java.time.Instant
import scala.jdk.CollectionConverters.*
import scala.util.{Failure, Success, Try}

/** OIDC / JWKS-backed `JwtVerifier` — accepts tokens signed with RS256 / RS384 / RS512 / ES256 / ES384 /
  * ES512 issued by any provider that publishes a JWKS endpoint.
  *
  * Verification flow:
  *   1. Parse the token's protected header to read `kid` and `alg`. 2. Ask the `JwksProvider` for the cached
  *      `JwkSet`; look up the key by `kid`. 3. If the `kid` isn't in the cached set, force a JWKS refresh
  *      (handles the race where the provider just rotated) and look again. If still absent, fail with
  *      `JwtError.Malformed`. 4. Hand the resolved `PublicKey` to jjwt's parser, which verifies the signature
  *      with the key's natural algorithm. 5. Validate `iss` against the configured `expectedIssuer` (defends
  *      against token substitution from a different OIDC provider that happens to share a JWKS key set with
  *      us, e.g. shared cloud-provider IDPs). 6. Validate `aud` against the optional `expectedAudience` (when
  *      set). RFC 7519 lets `aud` be either a string or an array; we accept either, matching either form
  *      against the expected audience string. 7. Extract claims into the existing `JwtClaims.Human` /
  *      `JwtClaims.Agent` shape via the same logic the HMAC verifier uses (the `aegis_kind` / `aegis_groups`
  *      / `aegis_*` extensions survive whether the token was signed with HMAC or asymmetric keys).
  *
  * **Algorithm confusion attack defence.** jjwt's `verifyWith(Key)` API is type-safe: passing a `PublicKey`
  * (RSA / EC) means jjwt will refuse `HS256` tokens forged against the public key as an HMAC secret. We
  * deliberately do NOT use the `unsignedKey()` / `none` path. The "alg=none" attack is impossible because
  * `parseSignedClaims` requires a signature.
  *
  * **Why `IORuntime` here.** The `JwtVerifier` trait is synchronous — `verify(token): Either[…]` — which is
  * the right shape for the HTTP layer that consumes it. JWKS fetch + cache lookup are `IO`-shaped (Resource /
  * Ref / blocking HTTP call), so we bridge `IO → Sync` via `unsafeRunSync()` here. The `JwksProvider` cache
  * means this is a Ref read in the hot path, not a network call.
  */
final class OidcJwtVerifier(
    jwks: JwksProvider,
    expectedIssuer: String,
    expectedAudience: Option[String] = None
)(using runtime: IORuntime)
    extends JwtVerifier:

  def verify(token: String): Either[JwtError, JwtClaims] =
    locateAndVerify(token)

  private def locateAndVerify(token: String): Either[JwtError, JwtClaims] =
    Try {
      val parser = Jwts.parser()
        .keyLocator(KidLocator)
        .requireIssuer(expectedIssuer)
        .build()
      parser.parseSignedClaims(token).getPayload
    } match
      case Success(claims)                          => extract(claims)
      case Failure(_: ExpiredJwtException)          => Left(JwtError.Expired)
      case Failure(_: MalformedJwtException)        => Left(JwtError.Malformed("malformed JWT"))
      case Failure(_: SignatureException)           => Left(JwtError.SignatureInvalid)
      case Failure(_: UnsupportedJwtException)      => Left(JwtError.Malformed("unsupported JWT algorithm"))
      case Failure(e: KidNotFound)                  => Left(JwtError.Malformed(s"unknown kid '${e.kid}'"))
      case Failure(e: io.jsonwebtoken.JwtException) =>
        // jjwt throws `IncorrectClaimException` for issuer mismatch — pin that to InvalidClaims so
        // the operator-facing log explains WHY the token was rejected.
        if e.getMessage != null && e.getMessage.toLowerCase.contains("iss")
        then Left(JwtError.InvalidClaims(s"issuer mismatch: ${e.getMessage}"))
        else Left(JwtError.Malformed(e.getMessage))
      case Failure(e) => Left(JwtError.Malformed(e.getMessage))

  /** jjwt locator: look up the key for the `kid` in the protected header. On miss, force a JWKS refresh (one
    * chance) — handles the race where the provider rotated keys between our last cache fetch and this token's
    * issuance. After the refresh, a still-missing kid throws `KidNotFound` which the outer match translates
    * into `JwtError.Malformed`.
    */
  private object KidLocator extends Locator[Key]:
    def locate(header: Header): Key =
      val kid = Option(header.get("kid").asInstanceOf[String]).getOrElse("")
      if kid.isEmpty then throw KidNotFound("")
      val resolved = (
        for
          set <- jwks.get
          k <- set.get(kid) match
            case Some(key) => IO.pure(Option(key))
            case None      => jwks.refresh.map(_.get(kid))
        yield k
      ).unsafeRunSync()
      resolved match
        case Some(k) => k
        case None    => throw KidNotFound(kid)

  /** Same claim-extraction logic as `HmacJwtVerifier.extract` (with audience validation tacked on). Kept
    * inline rather than factored out into a shared helper because the two verifiers may diverge on audience
    * handling, claim mapping, or `nbf` validation in v0.3+.
    */
  private def extract(claims: Claims): Either[JwtError, JwtClaims] =
    val subject  = Option(claims.getSubject).getOrElse("")
    val issuer   = Option(claims.getIssuer)
    val issuedAt = Option(claims.getIssuedAt).map(_.toInstant).getOrElse(Instant.EPOCH)
    val expires  = Option(claims.getExpiration).map(_.toInstant).getOrElse(Instant.EPOCH)
    val jti      = Option(claims.getId).getOrElse("")

    if subject.isEmpty then Left(JwtError.InvalidClaims("missing required claim: sub"))
    else if !audienceMatches(claims) then
      Left(JwtError.InvalidClaims(
        s"audience mismatch: expected '${expectedAudience.getOrElse("")}', got '${Option(claims.getAudience).map(_.asScala.mkString(",")).getOrElse("")}'"
      ))
    else
      Option(claims.get(JwtClaims.Claim.Kind, classOf[String])) match
        case Some(JwtClaims.Claim.KindHuman) =>
          val groups = stringList(claims, JwtClaims.Claim.Groups).toSet
          Right(JwtClaims.Human(subject, issuer, issuedAt, expires, groups, jti))
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
            allowedOps = stringList(claims, JwtClaims.Claim.AllowedOps).toSet,
            jti = jti
          )
        case Some(other) =>
          Left(JwtError.InvalidClaims(s"unknown ${JwtClaims.Claim.Kind}=$other"))
        case None =>
          Left(JwtError.InvalidClaims(s"missing required claim: ${JwtClaims.Claim.Kind}"))

  private def audienceMatches(claims: Claims): Boolean =
    expectedAudience match
      case None => true // operator chose not to enforce
      case Some(expected) =>
        val auds = Option(claims.getAudience).map(_.asScala.toSet).getOrElse(Set.empty)
        auds.contains(expected)

  private def requiredString(claims: Claims, name: String): Either[JwtError, String] =
    Option(claims.get(name, classOf[String])) match
      case Some(s) if s.nonEmpty => Right(s)
      case _                     => Left(JwtError.InvalidClaims(s"missing required claim: $name"))

  private def stringList(claims: Claims, name: String): List[String] =
    Option(claims.get(name, classOf[java.util.List[?]])) match
      case Some(jl) =>
        jl.asScala.iterator.collect { case s: String => s }.toList
      case None => Nil

/** Internal exception used by `KidLocator` to bubble "no key found for this kid" out through jjwt's parse
  * pipeline into our typed `JwtError.Malformed`. `KidNotFound` is package-private because no caller outside
  * this file should be catching it.
  */
final private[iam] case class KidNotFound(kid: String)
    extends RuntimeException(s"no key in JWKS for kid='$kid'")

object OidcJwtVerifier:

  /** Convenience factory: build the verifier from an OIDC issuer URI by fetching the discovery document
    * (`/.well-known/openid-configuration`) and extracting `jwks_uri`. This is the one-step "wire OIDC" entry
    * point used by `Server.boot`.
    *
    * If you already know the JWKS URI directly (e.g. an internal IDP that doesn't publish full discovery),
    * use the primary constructor with `JwksProvider.http(jwksUri, ttl)` instead.
    */
  def fromIssuer(
      issuerUri: String,
      audience: Option[String],
      jwksCacheTtl: scala.concurrent.duration.FiniteDuration
  )(using IORuntime): IO[OidcJwtVerifier] =
    for
      jwksUri  <- discoverJwksUri(issuerUri)
      provider <- JwksProvider.http(jwksUri, jwksCacheTtl)
    yield new OidcJwtVerifier(provider, expectedIssuer = issuerUri, expectedAudience = audience)

  /** Fetch the OIDC discovery document and pull `jwks_uri`. We deliberately don't pull anything else from the
    * document (token endpoint, supported algs, etc.) — Aegis is a verifier, not a client, and those fields
    * belong on the issuer side.
    */
  def discoverJwksUri(issuerUri: String): IO[java.net.URI] =
    IO.blocking {
      val client = java.net.http.HttpClient.newHttpClient()
      val req = java.net.http.HttpRequest
        .newBuilder(java.net.URI.create(s"$issuerUri/.well-known/openid-configuration"))
        .timeout(java.time.Duration.ofSeconds(10))
        .header("Accept", "application/json")
        .GET()
        .build()
      val resp = client.send(req, java.net.http.HttpResponse.BodyHandlers.ofString())
      if resp.statusCode() / 100 != 2 then
        throw new RuntimeException(s"OIDC discovery failed: ${resp.statusCode()} from $issuerUri")
      val json = io.circe.parser.parse(resp.body()) match
        case Right(j)  => j
        case Left(err) => throw new RuntimeException(s"OIDC discovery JSON invalid: ${err.message}")
      val jwksUri = json.hcursor.downField("jwks_uri").as[String] match
        case Right(s) => s
        case Left(_)  => throw new RuntimeException("OIDC discovery document missing 'jwks_uri'")
      java.net.URI.create(jwksUri)
    }
