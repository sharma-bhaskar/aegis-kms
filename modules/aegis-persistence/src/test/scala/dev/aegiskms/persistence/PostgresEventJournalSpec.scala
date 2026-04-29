package dev.aegiskms.persistence

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import com.dimafeng.testcontainers.PostgreSQLContainer
import dev.aegiskms.core.{Algorithm, KeyEvent, KeyId, KeyObjectType, KeySpec}
import doobie.Transactor
import org.scalatest.funsuite.AnyFunSuite
import org.testcontainers.utility.DockerImageName

import java.time.Instant
import scala.util.Try

/** Integration test for [[PostgresEventJournal]] against a real Postgres in Docker.
  *
  * Container lifecycle is managed manually rather than via `TestContainerForAll` so the suite skips cleanly
  * on machines without Docker — `TestContainerForAll`'s `beforeAll` would throw before the per-test `assume`
  * fired. CI runners (GitHub Actions ubuntu-latest) ship with Docker, so the suite runs there.
  */
final class PostgresEventJournalSpec extends AnyFunSuite:

  given IORuntime = IORuntime.global

  private val dockerAvailable: Boolean =
    Try(org.testcontainers.DockerClientFactory.instance().isDockerAvailable).getOrElse(false)

  private def withPostgres(body: Transactor[IO] => Unit): Unit =
    assume(dockerAvailable, "Docker is not available; skipping Postgres journal integration test")
    val container = PostgreSQLContainer(
      dockerImageNameOverride = DockerImageName.parse("postgres:16-alpine"),
      databaseName = "aegis_test",
      username = "aegis",
      password = "aegis"
    )
    container.start()
    try
      val xa = Transactor.fromDriverManager[IO](
        driver = "org.postgresql.Driver",
        url = container.jdbcUrl,
        user = container.username,
        password = container.password,
        logHandler = None
      )
      body(xa)
    finally container.stop()

  private val keyId = KeyId.fromString("k-9f2c").toOption.get
  private val now   = Instant.parse("2026-04-29T12:00:00Z")
  private val spec  = KeySpec("invoice-2026", Algorithm.AES, 256, KeyObjectType.SymmetricKey)

  test("append + replay returns events in insertion order") {
    withPostgres { xa =>
      val program =
        for
          journal <- PostgresEventJournal.bootstrappedFor(xa)
          e1 = KeyEvent.Created("e1", now, keyId, spec, "alice", "alice")
          e2 = KeyEvent.Activated("e2", now.plusSeconds(1), keyId, "alice")
          e3 = KeyEvent.Destroyed("e3", now.plusSeconds(2), keyId, "alice")
          _      <- journal.append(e1)
          _      <- journal.append(e2)
          _      <- journal.append(e3)
          events <- journal.replay()
        yield events

      val events = program.unsafeRunSync()
      assert(events.map(_.eventId) == List("e1", "e2", "e3"))
      assert(events.collect { case e: KeyEvent.Created => e.spec.name } == List("invoice-2026"))
    }
  }

  test("bootstrap is idempotent — running twice on the same DB does not throw") {
    withPostgres { xa =>
      val once  = PostgresEventJournal.bootstrappedFor(xa).unsafeRunSync()
      val twice = PostgresEventJournal.bootstrappedFor(xa).unsafeRunSync()
      val event = KeyEvent.Created("e1", now, keyId, spec, "alice", "alice")
      once.append(event).unsafeRunSync()
      val events = twice.replay().unsafeRunSync()
      assert(events.map(_.eventId).contains("e1"))
    }
  }

  test("append rejects duplicate eventId via UNIQUE constraint") {
    withPostgres { xa =>
      val program =
        for
          journal <- PostgresEventJournal.bootstrappedFor(xa)
          event = KeyEvent.Created("dup", now, keyId, spec, "alice", "alice")
          _      <- journal.append(event)
          result <- journal.append(event).attempt
        yield result

      val result = program.unsafeRunSync()
      assert(result.isLeft, "second append with the same eventId should have failed")
    }
  }
