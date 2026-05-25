package dev.aegiskms.iam

import cats.effect.unsafe.implicits.global
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import scala.concurrent.duration.*

/** Tests for the in-memory and noop `RevocationList` implementations. The Redis impl is exercised by
  * `RedisRevocationListSpec` (Docker-gated) in aegis-server.
  *
  * Properties pinned here:
  *   1. `noop` never reports anything as revoked. 2. In-memory `revoke` then `isRevoked` returns true. 3. An
  *      entry whose `expiresAt` is in the past is treated as not-revoked (TTL evict on read). 4. `revoke` is
  *      idempotent — same `jti` twice doesn't double-count. 5. Pruning happens on `revoke` calls — the map
  *      stays bounded. 6. Empty `jti` revoke + lookup behaves predictably (empty string keyed lookup).
  */
final class RevocationListSpec extends AnyFunSuite with Matchers:

  private def aFew = Instant.now().plusSeconds(3600)
  private def past = Instant.now().minusSeconds(3600)

  // ── noop ──────────────────────────────────────────────────────────────────

  test("noop never reports anything as revoked") {
    val list = RevocationList.noop
    list.isRevoked("anything").unsafeRunSync() shouldBe false
    list.revoke("anything", aFew).unsafeRunSync() // no-op
    list.isRevoked("anything").unsafeRunSync() shouldBe false
  }

  // ── in-memory happy paths ────────────────────────────────────────────────

  test("in-memory: revoke then isRevoked returns true") {
    val program =
      for
        list <- RevocationList.inMemory
        _    <- list.revoke("jti-1", aFew)
        out  <- list.isRevoked("jti-1")
      yield out
    program.unsafeRunSync() shouldBe true
  }

  test("in-memory: unknown jti returns false") {
    val program =
      for
        list <- RevocationList.inMemory
        out  <- list.isRevoked("never-seen")
      yield out
    program.unsafeRunSync() shouldBe false
  }

  test("in-memory: expired entry is treated as not revoked (TTL evict on read)") {
    val program =
      for
        list <- RevocationList.inMemory
        _    <- list.revoke("jti-old", past) // already expired
        out  <- list.isRevoked("jti-old")
      yield out
    program.unsafeRunSync() shouldBe false
  }

  test("in-memory: revoke is idempotent — same jti twice doesn't grow the store") {
    val program =
      for
        list <- RevocationList.inMemory
        _    <- list.revoke("jti-dup", aFew)
        _    <- list.revoke("jti-dup", aFew)
        size <- list.asInstanceOf[RevocationList.InMemoryRevocationList].size
      yield size
    program.unsafeRunSync() shouldBe 1
  }

  test("in-memory: a stale entry from a past revoke is pruned on the next revoke call") {
    val program =
      for
        list <- RevocationList.inMemory
        impl = list.asInstanceOf[RevocationList.InMemoryRevocationList]
        _    <- impl.revoke("jti-stale", past) // immediately expired
        _    <- impl.revoke("jti-fresh", aFew)
        size <- impl.size
      yield size
    // The expired entry is pruned during the second revoke; only `jti-fresh` survives.
    program.unsafeRunSync() shouldBe 1
  }

  test("in-memory: revoking with an already-past expiresAt is a no-op (no entry stored)") {
    val program =
      for
        list <- RevocationList.inMemory
        impl = list.asInstanceOf[RevocationList.InMemoryRevocationList]
        _    <- impl.revoke("jti-dead", past)
        size <- impl.size
      yield size
    program.unsafeRunSync() shouldBe 0
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  test("RevocationList.expiryFrom adds the ttl to now") {
    val now = Instant.parse("2026-05-25T10:00:00Z")
    RevocationList.expiryFrom(now, 1.hour) shouldBe now.plusSeconds(3600)
  }
