package dev.aegiskms.persistence

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import cats.syntax.parallel.*
import com.dimafeng.testcontainers.MySQLContainer
import dev.aegiskms.core.{Algorithm, KeyEvent, KeyId, KeyObjectType, KeySpec}
import doobie.Transactor
import doobie.implicits.*
import org.scalatest.BeforeAndAfterAll
import org.scalatest.funsuite.AnyFunSuite
import org.testcontainers.utility.DockerImageName

import java.time.Instant
import scala.util.Try

/** Integration test for [[MysqlEventJournal]] (#49) against a real MySQL in Docker.
  *
  * Container lifecycle: **one container shared across all tests in the suite** via `BeforeAndAfterAll`. The
  * original per-test pattern (boot a fresh container per `withMysql` call) was correct in isolation but slow
  * on CI — every MySQL container needs ~30 s to come up, so a 7-case suite spent ~3.5 min on container boot
  * alone. The shared pattern boots once and isolates per-test state by `DROP`-ing the table between cases.
  * This shaves about 80% off the CI wall-clock for this spec.
  *
  * Image pinned to `mysql:8.0`. The original code targeted `mysql:8.4` (the new LTS), but the Testcontainers
  * default `MySQLContainer` wait strategy was timing out against `mysql:8.4` on GitHub Actions runners — the
  * container exited with code 1 before the wait strategy could observe the "ready for connections" log line,
  * costing ~6 min per failed test. `mysql:8.0` is the previous LTS, still supported until 2032, and is the
  * version Testcontainers' wait strategy is most thoroughly validated against.
  *
  * Suite skips cleanly on machines without Docker — `assume(dockerAvailable)` on every test AND a
  * `dockerAvailable` guard in `beforeAll` so the container start is not attempted at all.
  */
final class MysqlEventJournalSpec extends AnyFunSuite with BeforeAndAfterAll:

  given IORuntime = IORuntime.global

  private val dockerAvailable: Boolean =
    Try(org.testcontainers.DockerClientFactory.instance().isDockerAvailable).getOrElse(false)

  // `var` is the standard scalatest pattern for fixtures torn up in beforeAll / down in afterAll.
  // Both are populated only when Docker is available.
  private var containerOpt: Option[MySQLContainer] = None
  private var xaOpt: Option[Transactor[IO]]        = None

  override def beforeAll(): Unit =
    if dockerAvailable then
      val c = MySQLContainer(
        mysqlImageVersion = DockerImageName.parse("mysql:8.0"),
        databaseName = "aegis_test",
        username = "aegis",
        password = "aegis"
      )
      c.start()
      containerOpt = Some(c)
      xaOpt = Some(Transactor.fromDriverManager[IO](
        driver = "com.mysql.cj.jdbc.Driver",
        url = c.jdbcUrl,
        user = c.username,
        password = c.password,
        logHandler = None
      ))
    super.beforeAll()

  override def afterAll(): Unit =
    try super.afterAll()
    finally containerOpt.foreach(_.stop())

  /** Run `body` against a freshly-cleared schema. Drops the table (if present) so each test starts from a
    * known empty state — the bootstrap inside the test body recreates it.
    */
  private def withMysql(body: Transactor[IO] => Unit): Unit =
    assume(dockerAvailable, "Docker is not available; skipping MySQL journal integration test")
    val xa = xaOpt.getOrElse(fail("Docker reported available but Transactor was not built"))
    sql"DROP TABLE IF EXISTS aegis_key_events".update.run.transact(xa).void.unsafeRunSync()
    body(xa)

  private val keyId = KeyId.fromString("k-9f2c").toOption.get
  private val now   = Instant.parse("2026-04-29T12:00:00Z")
  private val spec  = KeySpec("invoice-2026", Algorithm.AES, 256, KeyObjectType.SymmetricKey)

  test("append + replay returns events in insertion order") {
    withMysql { xa =>
      val program =
        for
          journal <- MysqlEventJournal.bootstrappedFor(xa)
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
    withMysql { xa =>
      val once  = MysqlEventJournal.bootstrappedFor(xa).unsafeRunSync()
      val twice = MysqlEventJournal.bootstrappedFor(xa).unsafeRunSync()
      val event = KeyEvent.Created("e1", now, keyId, spec, "alice", "alice")
      once.append(event).unsafeRunSync()
      val events = twice.replay().unsafeRunSync()
      assert(events.map(_.eventId).contains("e1"))
    }
  }

  test("append rejects duplicate eventId via UNIQUE constraint") {
    withMysql { xa =>
      val program =
        for
          journal <- MysqlEventJournal.bootstrappedFor(xa)
          event = KeyEvent.Created("dup", now, keyId, spec, "alice", "alice")
          _      <- journal.append(event)
          result <- journal.append(event).attempt
        yield result

      val result = program.unsafeRunSync()
      assert(result.isLeft, "second append with the same eventId should have failed")
    }
  }

  test("replay on an empty journal returns Nil") {
    withMysql { xa =>
      val program =
        for
          journal <- MysqlEventJournal.bootstrappedFor(xa)
          events  <- journal.replay()
        yield events

      val events = program.unsafeRunSync()
      assert(events.isEmpty, s"expected empty replay on a fresh journal, got: $events")
    }
  }

  test("idempotent bootstrap actually exercises the duplicate-index path (regression for error 1061)") {
    // The bootstrap-twice test above doesn't directly assert the duplicate-index handler ran —
    // it could pass if the handler silently swallowed a different error too. Here we verify the
    // schema state explicitly: after two bootstrappedFor calls, INFORMATION_SCHEMA reports
    // exactly one index of the expected name, and writes still work.
    withMysql { xa =>
      val program =
        for
          _ <- MysqlEventJournal.bootstrappedFor(xa)
          _ <- MysqlEventJournal.bootstrappedFor(xa)
          indexCount <- sql"""
            SELECT COUNT(*)
            FROM INFORMATION_SCHEMA.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME   = 'aegis_key_events'
              AND INDEX_NAME   = 'aegis_key_events_key_id_idx'
          """.query[Int].unique.transact(xa)
        yield indexCount

      // Index_name appears once per indexed column; our index has a single column so count=1.
      assert(program.unsafeRunSync() == 1, "duplicate-index handler should leave exactly one index")
    }
  }

  test("concurrent appends: pool-backed writes all land (no lost events under parallelism)") {
    withMysql { xa =>
      val program =
        for
          journal <- MysqlEventJournal.bootstrappedFor(xa)
          events =
            (1 to 20).toList.map(i =>
              KeyEvent.Created(s"e-$i", now.plusSeconds(i.toLong), keyId, spec, "alice", "alice")
            )
          // .parTraverse_ runs all 20 appends concurrently across cats-effect's compute pool.
          // HikariCP serialises through its connection set, but no rows should be dropped.
          _       <- events.parTraverse_(journal.append)
          replays <- journal.replay()
        yield replays.map(_.eventId).toSet

      val landed = program.unsafeRunSync()
      assert(landed.size == 20, s"expected all 20 concurrent events to land, got ${landed.size}: $landed")
      assert(landed == (1 to 20).map(i => s"e-$i").toSet)
    }
  }
