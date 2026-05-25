package dev.aegiskms.iam

import cats.effect.IO
import cats.effect.unsafe.IORuntime

/** Decorator that consults a [[RevocationList]] after the inner `JwtVerifier` has accepted the token. Keeps
  * the verifier composition order natural — signature + claims validation first (cheap, no network),
  * revocation check second (Redis round-trip on cache miss).
  *
  * **Why decorate rather than thread the list into every impl.** Every `JwtVerifier` impl (HMAC, OIDC, future
  * RS256-direct-key) would otherwise need a constructor arg for the list. Composition at the boot site keeps
  * the impls focused on what they uniquely do (signature verification) and lets the revocation policy be
  * swapped (noop / in-memory / Redis) without touching the verifier code.
  *
  * **What happens on revocation store outage.** `RevocationList.isRevoked` is allowed to return `false` on a
  * transient store failure (fail-open) — see the trait docstring for the rationale. That means a Redis outage
  * doesn't lock everyone out; the security gap is bounded by the token's TTL.
  *
  * **Why `IORuntime`.** The `JwtVerifier` trait is synchronous (`Either[JwtError, JwtClaims]`) to match the
  * HTTP layer's expectations. The revocation lookup is `IO`-shaped; we bridge via `unsafeRunSync`. For an
  * in-memory list this is a Ref read; for Redis it's an async call that still completes well under a
  * millisecond on a local cluster.
  *
  * **Tokens without `jti`.** Older externally-minted tokens may not carry a `jti` claim (the verifier
  * extracts it as the empty string in that case — see `JwtVerifier.extract`). A tokenless `jti` is treated as
  * "not revokable" and passes through. The HMAC issuer and OIDC IDPs Aegis-KMS issues for both set `jti`;
  * only legacy / non-Aegis tokens hit this path.
  */
final class RevocationAwareJwtVerifier(
    inner: JwtVerifier,
    revocation: RevocationList[IO]
)(using runtime: IORuntime)
    extends JwtVerifier:

  def verify(token: String): Either[JwtError, JwtClaims] =
    inner.verify(token) match
      case Right(claims) if claims.jti.nonEmpty =>
        if revocation.isRevoked(claims.jti).unsafeRunSync() then
          Left(JwtError.Revoked(claims.jti))
        else Right(claims)
      case other => other
