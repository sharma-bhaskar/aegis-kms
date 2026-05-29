package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import com.typesafe.config.{Config, ConfigFactory}
import dev.aegiskms.core.{Algorithm, KeyEvent, KeyId, KeyObjectType, KeySpec}
import dev.aegiskms.persistence.EventJournal
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.nio.file.Files
import java.time.Instant

/** Unit tests for `Server.journalResource` (#49 + #50). Mirrors `RootOfTrustResourceSpec` and
  * `PolicyEngineResourceSpec`: reflectively invoke the private builder, exercise each branch of the
  * config-driven selection, and assert the fail-fast paths a misconfigured production deployment would hit at
  * boot.
  *
  * The Postgres and MySQL branches are NOT exercised here — both call `HikariTransactor.make` which eagerly
  * opens a JDBC connection at acquisition time. Without a live DB, the test would block or time out. Those
  * branches are covered by `PostgresEventJournalSpec` and `MysqlEventJournalSpec` against real
  * Testcontainers. This spec covers in-memory, SQLite (which works locally with a temp file), and the
  * fail-fast paths — the boot logic that's not tied to a specific backend's connection lifecycle.
  */
final class JournalResourceSpec extends AnyFunSuite with Matchers:

  given IORuntime = IORuntime.global

  private val builder = Server.getClass.getDeclaredMethod(
    "journalResource",
    classOf[Config]
  )
  builder.setAccessible(true)
  private def invoke(c: Config) =
    builder.invoke(Server, c).asInstanceOf[cats.effect.Resource[IO, EventJournal[IO]]]

  private def cfg(hocon: String): Config =
    ConfigFactory.parseString(hocon).withFallback(ConfigFactory.load())

  private val keyId = KeyId.fromString("k-test").toOption.get
  private val now   = Instant.parse("2026-05-29T00:00:00Z")
  private val spec  = KeySpec("invoice", Algorithm.AES, 256, KeyObjectType.SymmetricKey)

  test("kind=in-memory yields a working journal (append+replay end-to-end)") {
    val program = invoke(cfg("""aegis.persistence.journal.kind = "in-memory" """)).use { j =>
      val e1 = KeyEvent.Created("e1", now, keyId, spec, "alice", "alice")
      j.append(e1) *> j.replay()
    }
    val events = program.unsafeRunSync()
    events.map(_.eventId) shouldBe List("e1")
  }

  test("kind defaults to in-memory when no override is set (application.conf default)") {
    val program = invoke(cfg("")).use { j =>
      val e1 = KeyEvent.Created("default", now, keyId, spec, "alice", "alice")
      j.append(e1) *> j.replay()
    }
    program.unsafeRunSync().map(_.eventId) shouldBe List("default")
  }

  test("kind=sqlite with a file URL yields a working journal (no Docker needed)") {
    val tmpFile = Files.createTempFile("aegis-journal-resource-", ".db")
    Files.delete(tmpFile)
    try
      val hocon = s"""
        aegis.persistence.journal {
          kind   = "sqlite"
          sqlite { jdbc-url = "jdbc:sqlite:${tmpFile.toAbsolutePath}" }
        }
      """
      val program = invoke(cfg(hocon)).use { j =>
        val e1 = KeyEvent.Created("sql1", now, keyId, spec, "alice", "alice")
        j.append(e1) *> j.replay()
      }
      program.unsafeRunSync().map(_.eventId) shouldBe List("sql1")
    finally Files.deleteIfExists(tmpFile)
  }

  test("unknown kind fails fast at boot with a clear error listing the valid set") {
    val ex = intercept[IllegalArgumentException] {
      invoke(cfg("""aegis.persistence.journal.kind = "cassandra" """))
        .use(_ => IO.unit)
        .unsafeRunSync()
    }
    ex.getMessage should include("Unknown aegis.persistence.journal.kind=cassandra")
    ex.getMessage should include("'in-memory'")
    ex.getMessage should include("'postgres'")
    ex.getMessage should include("'mysql'")
    ex.getMessage should include("'sqlite'")
  }
