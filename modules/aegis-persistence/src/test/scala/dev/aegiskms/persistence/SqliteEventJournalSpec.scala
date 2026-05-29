package dev.aegiskms.persistence

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import cats.syntax.parallel.*
import dev.aegiskms.core.{Algorithm, KeyEvent, KeyId, KeyObjectType, KeySpec}
import doobie.Transactor
import org.scalatest.funsuite.AnyFunSuite

import java.nio.file.Files
import java.time.Instant

/** Unit tests for [[SqliteEventJournal]] (#50). Unlike the Postgres/MySQL specs, no Docker is required —
  * SQLite runs in-process via a temp file per test.
  *
  * We use a temp file rather than `jdbc:sqlite::memory:` because `Transactor.fromDriverManager` opens a fresh
  * connection per query, and SQLite `:memory:` databases are connection-scoped — the bootstrap migration's
  * schema would vanish before the first append even with `cache=shared` (which behaves correctly only with at
  * least one connection held open at all times). Temp files also exercise the file-system path that
  * production embedders actually use.
  */
final class SqliteEventJournalSpec extends AnyFunSuite:

  given IORuntime = IORuntime.global

  private def withSqlite(body: Transactor[IO] => Unit): Unit =
    val tmpFile = Files.createTempFile("aegis-sqlite-journal-", ".db")
    Files.delete(tmpFile) // delete; the SQLite driver recreates on first connect
    val url = s"jdbc:sqlite:${tmpFile.toAbsolutePath}"
    val xa = Transactor.fromDriverManager[IO](
      driver = "org.sqlite.JDBC",
      url = url,
      user = "",
      password = "",
      logHandler = None
    )
    try body(xa)
    finally Files.deleteIfExists(tmpFile)

  private val keyId = KeyId.fromString("k-9f2c").toOption.get
  private val now   = Instant.parse("2026-04-29T12:00:00Z")
  private val spec  = KeySpec("invoice-2026", Algorithm.AES, 256, KeyObjectType.SymmetricKey)

  test("append + replay returns events in insertion order") {
    withSqlite { xa =>
      val program =
        for
          journal <- SqliteEventJournal.bootstrappedFor(xa)
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
    withSqlite { xa =>
      val once  = SqliteEventJournal.bootstrappedFor(xa).unsafeRunSync()
      val twice = SqliteEventJournal.bootstrappedFor(xa).unsafeRunSync()
      val event = KeyEvent.Created("e1", now, keyId, spec, "alice", "alice")
      once.append(event).unsafeRunSync()
      val events = twice.replay().unsafeRunSync()
      assert(events.map(_.eventId).contains("e1"))
    }
  }

  test("append rejects duplicate eventId via UNIQUE constraint") {
    withSqlite { xa =>
      val program =
        for
          journal <- SqliteEventJournal.bootstrappedFor(xa)
          event = KeyEvent.Created("dup", now, keyId, spec, "alice", "alice")
          _      <- journal.append(event)
          result <- journal.append(event).attempt
        yield result

      val result = program.unsafeRunSync()
      assert(result.isLeft, "second append with the same eventId should have failed")
    }
  }

  test("replay on an empty journal returns Nil") {
    withSqlite { xa =>
      val program =
        for
          journal <- SqliteEventJournal.bootstrappedFor(xa)
          events  <- journal.replay()
        yield events

      val events = program.unsafeRunSync()
      assert(events.isEmpty, s"expected empty replay on a fresh journal, got: $events")
    }
  }

  test("concurrent appends serialise correctly under the single-writer model") {
    // SQLite serialises writes through one lock; with a real Transactor.fromDriverManager (single
    // shared connection) the appends queue up and all 20 land. This is the property that makes
    // SQlite usable as an embedded journal — but only when poolSize stays at 1, which the
    // production builder enforces. The test asserts the durability promise under parallelism.
    withSqlite { xa =>
      val program =
        for
          journal <- SqliteEventJournal.bootstrappedFor(xa)
          events =
            (1 to 20).toList.map(i =>
              KeyEvent.Created(s"e-$i", now.plusSeconds(i.toLong), keyId, spec, "alice", "alice")
            )
          _       <- events.parTraverse_(journal.append)
          replays <- journal.replay()
        yield replays.map(_.eventId).toSet

      val landed = program.unsafeRunSync()
      assert(landed.size == 20, s"expected all 20 concurrent events to land, got ${landed.size}: $landed")
      assert(landed == (1 to 20).map(i => s"e-$i").toSet)
    }
  }

  test("file-backed journal survives connection churn — the embedded-demo use case") {
    // Distinct from in-memory: write events, close + reopen, replay still returns them. This is
    // the property that makes SQLite usable for embedded deployments where the process restarts.
    val tmpFile = Files.createTempFile("aegis-sqlite-journal-", ".db")
    Files.delete(tmpFile) // delete; the driver recreates
    val url = s"jdbc:sqlite:${tmpFile.toAbsolutePath}"
    try
      def freshXa(): Transactor[IO] =
        Transactor.fromDriverManager[IO](
          driver = "org.sqlite.JDBC",
          url = url,
          user = "",
          password = "",
          logHandler = None
        )

      // First "session" — write three events.
      val writeProgram =
        for
          journal <- SqliteEventJournal.bootstrappedFor(freshXa())
          _       <- journal.append(KeyEvent.Created("e1", now, keyId, spec, "alice", "alice"))
          _       <- journal.append(KeyEvent.Activated("e2", now.plusSeconds(1), keyId, "alice"))
          _       <- journal.append(KeyEvent.Destroyed("e3", now.plusSeconds(2), keyId, "alice"))
        yield ()
      writeProgram.unsafeRunSync()

      // Second "session" — fresh transactor, replay sees all three.
      val replayProgram =
        for
          journal <- SqliteEventJournal.bootstrappedFor(freshXa())
          events  <- journal.replay()
        yield events
      val events = replayProgram.unsafeRunSync()
      assert(events.map(_.eventId) == List("e1", "e2", "e3"))
    finally Files.deleteIfExists(tmpFile)
  }
