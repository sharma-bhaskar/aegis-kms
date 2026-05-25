package dev.aegiskms.app

import cats.effect.{IO, Resource}
import dev.aegiskms.iam.RevocationList
import io.lettuce.core.RedisClient
import io.lettuce.core.api.StatefulRedisConnection
import org.slf4j.LoggerFactory

import java.time.Instant

/** Lettuce-backed `RevocationList`. Stores each revoked `jti` as a single Redis key with `PEXPIREAT` set to
  * the token's natural `exp`, so the entry auto-evicts when the token would have expired anyway.
  *
  * **Why Lettuce (not redis4cats).** Lettuce is a single-jar Java client; the smaller transitive dep tree
  * keeps the aegis-server Docker image lean. We use the synchronous `RedisCommands` surface wrapped in
  * `IO.blocking` — for the call profile (one `EXISTS` per token verify, one `SETEX` per revoke) the
  * async/reactive APIs would just add complexity.
  *
  * **Why a key per jti (rather than a Sorted Set keyed by expiry).** A SET-per-jti gives us TTL eviction for
  * free — Redis handles the cleanup. The alternative (one SortedSet, sweeper job) needs a background process
  * and an extra commit point. Per-key TTL is the boring choice.
  *
  * **Fail-open on transient failures.** Lookup errors are swallowed and reported as "not revoked" — see
  * `RevocationList` trait docstring for why. Operators get the failure in the logs; users keep getting
  * served.
  */
final class RedisRevocationList private (
    connection: StatefulRedisConnection[String, String],
    keyPrefix: String
) extends RevocationList[IO]:

  private val logger = LoggerFactory.getLogger(classOf[RedisRevocationList])

  def isRevoked(jti: String): IO[Boolean] =
    IO.blocking {
      val cmd    = connection.sync()
      val exists = cmd.exists(redisKey(jti))
      exists != null && exists.longValue() > 0
    }.handleErrorWith { t =>
      // Fail-open: a Redis outage shouldn't lock every user out. Bounded security gap = token TTL.
      IO(logger.warn(s"revocation lookup failed (fail-open) for jti=$jti: ${t.getMessage}", t))
        .as(false)
    }

  def revoke(jti: String, expiresAt: Instant): IO[Unit] =
    IO.blocking {
      val cmd = connection.sync()
      val key = redisKey(jti)
      // PEXPIREAT semantics: the key is auto-purged at the given Unix-millis. If `expiresAt` is
      // already in the past (e.g. an unusual race during issue), Redis treats it as immediate
      // delete — fine, the jti was never useful to revoke.
      cmd.set(key, "1")
      cmd.pexpireat(key, expiresAt.toEpochMilli)
      ()
    }.handleErrorWith { t =>
      // Best-effort. A failed revoke is logged loudly so operators can retry; surfacing the
      // failure to the caller would create a worse story (the auto-responder's `Revoke` action
      // would refuse the audit row).
      IO(logger.error(s"revocation write failed for jti=$jti exp=$expiresAt: ${t.getMessage}", t))
    }

  /** Test seam: count how many revocation keys live under the configured prefix. Linear in the number of
    * revocations — fine for tests, not for prod (no one calls it in prod).
    */
  def size: IO[Long] =
    IO.blocking {
      val cmd = connection.sync()
      cmd.keys(s"$keyPrefix*").size().toLong
    }.handleErrorWith(_ => IO.pure(0L))

  private def redisKey(jti: String): String = s"$keyPrefix$jti"

object RedisRevocationList:

  /** Default Redis key prefix. Namespaced so a shared Redis (e.g. with a session store) doesn't collide.
    */
  val DefaultKeyPrefix: String = "aegis:revoked-jti:"

  /** Resource-managed builder. Owns the Lettuce `RedisClient` + connection; both are `AutoCloseable` and
    * released on SIGTERM.
    */
  def make(redisUri: String, keyPrefix: String = DefaultKeyPrefix): Resource[IO, RedisRevocationList] =
    for
      client <- Resource.fromAutoCloseable(IO {
        RedisClient.create(redisUri)
      })
      connection <- Resource.fromAutoCloseable(IO {
        client.connect()
      })
    yield new RedisRevocationList(connection, keyPrefix)

  /** Test seam: build a list against an already-open connection. Caller manages the connection lifecycle.
    */
  def withConnection(
      connection: StatefulRedisConnection[String, String],
      keyPrefix: String = DefaultKeyPrefix
  ): RedisRevocationList =
    new RedisRevocationList(connection, keyPrefix)
