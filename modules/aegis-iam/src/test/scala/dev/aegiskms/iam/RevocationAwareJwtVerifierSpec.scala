package dev.aegiskms.iam

import cats.effect.unsafe.IORuntime
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/** Tests for the `RevocationAwareJwtVerifier` decorator. Verified properties:
  *
  *   1. Token whose `jti` isn't on the list passes through with the inner verifier's result. 2. Revoked `jti`
  *      produces `JwtError.Revoked(jti)`. 3. Token without a `jti` (legacy) is not subjected to revocation
  *      lookup — passes through. 4. If the inner verifier rejects (e.g. expired / bad sig), the revocation
  *      list is NOT consulted — saves a Redis call on rejected tokens. 5. Decoration is composable: an
  *      already-decorated verifier doesn't break when wrapped again.
  */
final class RevocationAwareJwtVerifierSpec extends AnyFunSuite with Matchers:

  // The decorator's verify uses `unsafeRunSync` internally; we don't need a separate runtime here.
  private given IORuntime = IORuntime.global

  // Stub verifier that returns whatever `Either` is supplied. Lets us drive the decorator without
  // setting up real keys / signatures.
  final private class StubVerifier(result: Either[JwtError, JwtClaims]) extends JwtVerifier:
    @volatile var verifyCalls: Int = 0
    def verify(token: String): Either[JwtError, JwtClaims] =
      verifyCalls += 1
      result

  private val now = Instant.now()

  private def humanClaims(jti: String = UUID.randomUUID().toString): JwtClaims.Human =
    JwtClaims.Human(
      subject = "alice@org",
      issuer = None,
      issuedAt = now,
      expiresAt = now.plus(1, ChronoUnit.HOURS),
      groups = Set("admins"),
      jti = jti
    )

  // ── Happy path ────────────────────────────────────────────────────────────

  test("token not on the revocation list passes through unchanged") {
    val claims = humanClaims()
    val inner  = StubVerifier(Right(claims))
    val program =
      for
        list <- RevocationList.inMemory
        v = new RevocationAwareJwtVerifier(inner, list)
      yield v.verify("any-token")
    val result = program.unsafeRunSync()
    result shouldBe Right(claims)
    inner.verifyCalls shouldBe 1
  }

  test("revoked jti is rejected with JwtError.Revoked(jti)") {
    val jti    = "jti-to-revoke"
    val claims = humanClaims(jti)
    val inner  = StubVerifier(Right(claims))
    val program =
      for
        list <- RevocationList.inMemory
        _    <- list.revoke(jti, claims.expiresAt)
        v = new RevocationAwareJwtVerifier(inner, list)
      yield v.verify("any-token")
    program.unsafeRunSync() shouldBe Left(JwtError.Revoked(jti))
  }

  test("token without jti (empty string) is not subjected to revocation lookup") {
    val claims = humanClaims(jti = "")
    val inner  = StubVerifier(Right(claims))
    val program =
      for
        list <- RevocationList.inMemory
        // Even if we revoke an empty string, the decorator shouldn't check it.
        _ <- list.revoke("", claims.expiresAt)
        v = new RevocationAwareJwtVerifier(inner, list)
      yield v.verify("any-token")
    program.unsafeRunSync() shouldBe Right(claims)
  }

  // ── Inner-rejection short-circuit ─────────────────────────────────────────

  test("inner rejection (Expired) bypasses the revocation lookup") {
    val inner = StubVerifier(Left(JwtError.Expired))
    val program =
      for
        list <- RevocationList.inMemory
        v = new RevocationAwareJwtVerifier(inner, list)
      yield v.verify("any-token")
    program.unsafeRunSync() shouldBe Left(JwtError.Expired)
  }

  test("inner rejection (SignatureInvalid) bypasses the revocation lookup") {
    val inner = StubVerifier(Left(JwtError.SignatureInvalid))
    val program =
      for
        list <- RevocationList.inMemory
        v = new RevocationAwareJwtVerifier(inner, list)
      yield v.verify("any-token")
    program.unsafeRunSync() shouldBe Left(JwtError.SignatureInvalid)
  }

  // ── Composition ──────────────────────────────────────────────────────────

  test("double-wrapping is idempotent (same behavior as single-wrap)") {
    val claims = humanClaims()
    val inner  = StubVerifier(Right(claims))
    val program =
      for
        list <- RevocationList.inMemory
        once  = new RevocationAwareJwtVerifier(inner, list)
        twice = new RevocationAwareJwtVerifier(once, list)
      yield twice.verify("any-token")
    program.unsafeRunSync() shouldBe Right(claims)
  }
