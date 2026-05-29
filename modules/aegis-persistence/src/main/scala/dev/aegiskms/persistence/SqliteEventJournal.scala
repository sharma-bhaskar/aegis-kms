package dev.aegiskms.persistence

import cats.effect.{IO, Resource}
import cats.syntax.all.*
import dev.aegiskms.core.KeyEvent
import dev.aegiskms.core.codecs.KeyEventCodec.given
import doobie.*
import doobie.hikari.HikariTransactor
import doobie.implicits.*
import io.circe.parser.parse as parseJson
import io.circe.syntax.*

import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** Doobie-backed SQLite implementation of [[EventJournal]] (#50).
  *
  * The "no Postgres, please" embedded option — single-file durable journal for laptops, CI pipelines, and
  * edge / single-node deployments. NOT a substitute for Postgres at any meaningful write concurrency: SQLite
  * serialises all writes through a single lock, which is fine for an Aegis instance handling tens of
  * operations per second but a bottleneck above that.
  *
  * Schema differences vs. Postgres / MySQL — SQLite is dynamically typed and accepts almost any column type,
  * but we declare types matching SQLite's affinity rules so the schema reads cleanly:
  *   - `BIGSERIAL` → `INTEGER PRIMARY KEY AUTOINCREMENT` (the unique magic incantation SQLite recognises for
  *     a monotonically-increasing rowid alias)
  *   - `VARCHAR(n)` → `TEXT` (SQLite ignores the length; TEXT is clearer)
  *   - `JSONB` → `TEXT` (no native JSON type pre-3.45; we keep TEXT for maximum portability)
  *   - `TIMESTAMPTZ` → `TEXT` storing ISO-8601 UTC strings (same approach as the MySQL adapter)
  *   - `NOT NULL DEFAULT now()` → `DEFAULT CURRENT_TIMESTAMP`
  *
  * The pool size is forced to 1 even if the config says otherwise — see [[SqliteJournalConfig]] for why. A
  * larger pool would just produce SQLITE_BUSY errors under any write concurrency.
  */
object SqliteEventJournal:

  /** Resource-managed SQLite-backed journal. Acquires a single-connection HikariCP `Transactor`, runs the
    * bootstrap migration (idempotent), and yields the journal. Releasing the resource closes the connection.
    */
  def make(config: SqliteJournalConfig): Resource[IO, EventJournal[IO]] =
    for
      ec <- ExecutionContexts.fixedThreadPool[IO](1)
      xa <- HikariTransactor.newHikariTransactor[IO](
        driverClassName = "org.sqlite.JDBC",
        url = config.jdbcUrl,
        user = "",
        pass = "",
        connectEC = ec
      )
      _ <- Resource.eval(bootstrap(xa))
    yield Impl(xa)

  /** Test/embedding seam: take an existing `Transactor`, run the bootstrap migration, yield a journal. The
    * caller owns the transactor's lifecycle.
    */
  def bootstrappedFor(xa: Transactor[IO]): IO[EventJournal[IO]] =
    bootstrap(xa).as(Impl(xa))

  // ── Migration ────────────────────────────────────────────────────────────────

  private val createTable: doobie.ConnectionIO[Int] =
    sql"""
      CREATE TABLE IF NOT EXISTS aegis_key_events (
        seq           INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id      TEXT    NOT NULL UNIQUE,
        key_id        TEXT    NOT NULL,
        event_type    TEXT    NOT NULL,
        occurred_at   TEXT    NOT NULL,
        actor_subject TEXT    NOT NULL,
        payload       TEXT    NOT NULL,
        inserted_at   TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    """.update.run

  private val createIndex: doobie.ConnectionIO[Int] =
    sql"""
      CREATE INDEX IF NOT EXISTS aegis_key_events_key_id_idx
      ON aegis_key_events(key_id)
    """.update.run

  private def bootstrap(xa: Transactor[IO]): IO[Unit] =
    (createTable *> createIndex).transact(xa).void

  // ── Impl ─────────────────────────────────────────────────────────────────────

  private val isoFormatter: DateTimeFormatter =
    DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC)

  final private class Impl(xa: Transactor[IO]) extends EventJournal[IO]:

    def append(event: KeyEvent): IO[Unit] =
      val payloadJson = event.asJson.noSpaces
      val kind = event match
        case _: KeyEvent.Created     => "Created"
        case _: KeyEvent.Activated   => "Activated"
        case _: KeyEvent.Deactivated => "Deactivated"
        case _: KeyEvent.Destroyed   => "Destroyed"
        case _: KeyEvent.Compromised => "Compromised"
        case _: KeyEvent.Rotated     => "Rotated"
      val occurredAt = isoFormatter.format(event.at)
      sql"""
        INSERT INTO aegis_key_events
          (event_id, key_id, event_type, occurred_at, actor_subject, payload)
        VALUES
          (${event.eventId}, ${event.keyId.value}, $kind, $occurredAt,
           ${event.actorSubject}, $payloadJson)
      """.update.run.transact(xa).void

    def replay(): IO[List[KeyEvent]] =
      sql"""
        SELECT payload
        FROM aegis_key_events
        ORDER BY seq ASC
      """
        .query[String]
        .to[List]
        .transact(xa)
        .flatMap { rows =>
          rows.traverse { raw =>
            parseJson(raw).flatMap(_.as[KeyEvent]) match
              case Right(ev) => IO.pure(ev)
              case Left(err) =>
                IO.raiseError(new RuntimeException(
                  s"Failed to decode KeyEvent from SQLite journal payload: ${err.getMessage}"
                ))
          }
        }
