package dev.aegiskms.iam

import cats.effect.{IO, Ref}

import java.time.Instant
import scala.concurrent.duration.FiniteDuration

/** SPI for a JWT revocation list keyed by `jti` claim.
  *
  * The auto-responder ([[dev.aegiskms.agent.AutoResponder]]) and the future agent-revoke admin endpoint use
  * this to invalidate a still-unexpired bearer token before its natural `exp`. Every `JwtVerifier` consults
  * the list on each verify — see `RevocationAwareJwtVerifier`.
  *
  * **TTL semantics.** `revoke(jti, expiresAt)` records the jti with an expiry equal to the token's `exp`
  * claim. Once the token would have expired naturally, the entry is purged (Redis via `PEXPIREAT`; in-memory
  * via lazy check). This keeps the list bounded — a year of revocation activity on 1-hour tokens stays at
  * most ~1h × 24 × 365 jtis if every token were revoked, which is in the low millions for the worst case and
  * still fits in a few MB of memory.
  *
  * **Idempotency.** Revoking the same `jti` twice is a no-op (the second TTL update is benign).
  *
  * **Failure model.** `isRevoked` on a transient Redis outage returns `false` (fail-open) so a partial-outage
  * on the revocation store doesn't lock every user out. Operators who want fail-closed semantics can wrap the
  * implementation in a decorator that re-raises. Defaults matter: getting a revocation check wrong by
  * treating "Redis unreachable" as "all tokens revoked" would create an outage; treating it as "no tokens
  * revoked" creates a security gap limited to the token TTL. The latter is the lesser evil for a v0.2.0
  * default.
  */
trait RevocationList[F[_]]:
  /** True iff the given `jti` is currently revoked. Implementations should return `false` on transient store
    * failures (fail-open).
    */
  def isRevoked(jti: String): F[Boolean]

  /** Record `jti` as revoked until `expiresAt`. After that instant the entry is automatically purged from the
    * store (no caller-side cleanup needed).
    */
  def revoke(jti: String, expiresAt: Instant): F[Unit]

object RevocationList:

  /** A no-op list: nothing is ever revoked. Used when revocation is disabled
    * (`aegis.iam.revocation.kind=none`) or in the dev resolver path where there are no JWTs at all. Returning
    * a singleton means the decorator's check is a single Boolean read per verify.
    */
  val noop: RevocationList[IO] = new RevocationList[IO]:
    def isRevoked(jti: String): IO[Boolean]               = IO.pure(false)
    def revoke(jti: String, expiresAt: Instant): IO[Unit] = IO.unit

  /** Build an in-memory revocation list. Entries are checked against wall-clock on every read; expired
    * entries are filtered out lazily (no background cleanup thread). Fine for single-node dev / testing —
    * production deployments should use the Redis impl in `aegis-server`.
    */
  def inMemory: IO[RevocationList[IO]] =
    Ref.of[IO, Map[String, Instant]](Map.empty).map(new InMemoryRevocationList(_))

  /** In-memory `RevocationList` using a `Ref[IO, Map[jti, expiresAt]]`. Read path: filter expired entries on
    * the fly so the store stays self-cleaning under load. Concurrent revoke + isRevoked are atomic via Ref's
    * CAS update.
    */
  final class InMemoryRevocationList(state: Ref[IO, Map[String, Instant]])
      extends RevocationList[IO]:

    def isRevoked(jti: String): IO[Boolean] =
      for
        now <- IO.realTimeInstant
        map <- state.get
      yield map.get(jti).exists(_.isAfter(now))

    def revoke(jti: String, expiresAt: Instant): IO[Unit] =
      // We also use the revoke call as a chance to prune obviously-expired entries — keeps the
      // map bounded over time even without a sweeper. O(N) on the map size, but N stays small in
      // practice (a few thousand at most under normal revocation activity).
      for
        now <- IO.realTimeInstant
        _ <- state.update { m =>
          val pruned = m.filter { case (_, exp) => exp.isAfter(now) }
          if expiresAt.isAfter(now) then pruned + (jti -> expiresAt) else pruned
        }
      yield ()

    /** Test helper: current size of the revocation store. */
    def size: IO[Int] = state.get.map(_.size)

  /** Convenience: derive `expiresAt` from a `now + ttl` pair. The Redis impl uses `PEXPIREAT` directly, so
    * this is only needed when the caller doesn't have an explicit instant.
    */
  def expiryFrom(now: Instant, ttl: FiniteDuration): Instant =
    now.plusSeconds(ttl.toSeconds)
