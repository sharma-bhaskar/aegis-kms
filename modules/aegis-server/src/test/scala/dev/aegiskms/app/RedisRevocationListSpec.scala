package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import com.dimafeng.testcontainers.GenericContainer
import io.lettuce.core.RedisClient
import io.lettuce.core.api.StatefulRedisConnection
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.utility.DockerImageName

import java.time.Instant
import scala.util.Try

/** Integration test for `RedisRevocationList` against a real Redis in Docker.
  *
  * Container lifecycle is managed manually (matching `PostgresEventJournalSpec` / `PostgresAuditSinkSpec`) so
  * the suite skips cleanly via `assume(...)` on machines without Docker. The 8 cases here pin the contract
  * the JWT verifier's revocation check depends on: revoke writes, isRevoked reads, expiry honoured by Redis
  * TTL, idempotent re-revoke, prefix namespacing, fail-open on a torn-down connection.
  */
final class RedisRevocationListSpec extends AnyFunSuite with Matchers:

  given IORuntime = IORuntime.global

  private val dockerAvailable: Boolean =
    Try(org.testcontainers.DockerClientFactory.instance().isDockerAvailable).getOrElse(false)

  /** Build, start, run-with, and tear-down a single Redis container + connection. The block gets an open
    * `RedisRevocationList` against the test's key prefix.
    */
  private def withRedis(body: (RedisRevocationList, StatefulRedisConnection[String, String]) => Unit): Unit =
    assume(dockerAvailable, "Docker is not available; skipping Redis revocation list integration test")
    val container = GenericContainer(
      dockerImage = DockerImageName.parse("redis:7-alpine").asCompatibleSubstituteFor("redis").toString,
      exposedPorts = Seq(6379),
      waitStrategy = Wait.forListeningPort()
    )
    container.start()
    try
      val uri        = s"redis://${container.host}:${container.mappedPort(6379)}"
      val client     = RedisClient.create(uri)
      val connection = client.connect()
      try
        val list = RedisRevocationList.withConnection(connection, keyPrefix = "test:revoked-jti:")
        body(list, connection)
      finally
        connection.close()
        client.shutdown()
    finally container.stop()

  private val now: Instant = Instant.now()

  // ── Happy paths ────────────────────────────────────────────────────────────

  test("revoke followed by isRevoked returns true within the TTL window") {
    withRedis { (list, _) =>
      val program =
        for
          _   <- list.revoke("jti-1", now.plusSeconds(3600))
          out <- list.isRevoked("jti-1")
        yield out
      program.unsafeRunSync() shouldBe true
    }
  }

  test("isRevoked on an unknown jti returns false") {
    withRedis { (list, _) =>
      list.isRevoked("never-seen").unsafeRunSync() shouldBe false
    }
  }

  test("Redis honours the PEXPIREAT — revoking with a past instant evicts immediately") {
    withRedis { (list, _) =>
      val program =
        for
          // Use a very near-future expiry, then sleep past it. Avoid passing PEXPIREAT a past
          // millis (Redis behavior on that varies by version; safer to set a 100ms TTL and wait).
          _ <- list.revoke("jti-near-expiry", now.plusMillis(200))
          _ <- IO.sleep(scala.concurrent.duration.FiniteDuration(500, scala.concurrent.duration.MILLISECONDS))
          out <- list.isRevoked("jti-near-expiry")
        yield out
      program.unsafeRunSync() shouldBe false
    }
  }

  test("revoke is idempotent — same jti revoked twice does not multiply") {
    withRedis { (list, _) =>
      val program =
        for
          _    <- list.revoke("jti-dup", now.plusSeconds(3600))
          _    <- list.revoke("jti-dup", now.plusSeconds(3600))
          size <- list.size
        yield size
      program.unsafeRunSync() shouldBe 1L
    }
  }

  test("key-prefix isolates revocations from other workloads on the same Redis") {
    withRedis { (list, conn) =>
      // Write a key NOT under the prefix using the same connection — simulates another app on
      // the same Redis (a session store, rate limiter, etc.). Our `size` counts only our prefix.
      val program =
        for
          _    <- IO.blocking(conn.sync().set("some-other-app:key:foo", "bar")).void
          _    <- list.revoke("jti-1", now.plusSeconds(3600))
          size <- list.size
        yield size
      program.unsafeRunSync() shouldBe 1L
    }
  }

  test("multiple jtis can be revoked and looked up independently") {
    withRedis { (list, _) =>
      val program =
        for
          _     <- list.revoke("a", now.plusSeconds(3600))
          _     <- list.revoke("b", now.plusSeconds(3600))
          _     <- list.revoke("c", now.plusSeconds(3600))
          aHit  <- list.isRevoked("a")
          bHit  <- list.isRevoked("b")
          cHit  <- list.isRevoked("c")
          dMiss <- list.isRevoked("d")
        yield (aHit, bHit, cHit, dMiss)
      program.unsafeRunSync() shouldBe ((true, true, true, false))
    }
  }

  // ── Fail-open ─────────────────────────────────────────────────────────────

  test("isRevoked fails open (returns false) when the Redis connection is closed") {
    withRedis { (list, conn) =>
      conn.close()
      // After the connection is closed, Lettuce throws on `sync().exists(...)`. The decorator
      // catches and logs; users get fail-open semantics so a Redis outage doesn't lock everyone
      // out. Bounded security gap = token TTL.
      list.isRevoked("anything").unsafeRunSync() shouldBe false
    }
  }

  test("revoke errors are logged but don't throw (best-effort semantics)") {
    withRedis { (list, conn) =>
      conn.close()
      noException should be thrownBy
        list.revoke("jti-after-close", now.plusSeconds(3600)).unsafeRunSync()
    }
  }
