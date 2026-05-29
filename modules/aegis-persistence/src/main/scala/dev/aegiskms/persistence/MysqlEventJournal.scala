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

/** Doobie-backed MySQL implementation of [[EventJournal]] (#49).
  *
  * Schema differences vs. `PostgresEventJournal`:
  *   - `BIGSERIAL` → `BIGINT AUTO_INCREMENT` (MySQL's auto-increment column type)
  *   - `JSONB` → `JSON` (MySQL's native JSON type — TEXT with validation; supports `JSON_EXTRACT` etc. for
  *     ad-hoc operator queries even though replay() only reads the whole column)
  *   - `TIMESTAMPTZ` → we store ISO-8601 strings in a `VARCHAR(40)` column instead of a `DATETIME(6)`.
  *     MySQL's `DATETIME` has no timezone (it's stored as the local server's TZ unless you go to `TIMESTAMP`,
  *     which has a 2038 problem and only spans 1970–2038), so the cleanest portable approach is to store UTC
  *     ISO-8601 strings and convert in app code. The denormalised `occurred_at` column is never read for
  *     replay (we ORDER BY `seq`), so the string format is fine for the indexed-by-app-code path. Operators
  *     inspecting the table see human-readable timestamps.
  *
  * The JSON payload is stored as a `String` (not via `doobie-postgres-circe`'s `JSONB` Meta, which is
  * Postgres-only). The round-trip is identical: `KeyEvent.asJson.noSpaces` on write, `parseJson` on read. The
  * same `KeyEventCodec` is used.
  *
  * Why one bootstrap migration via `CREATE TABLE IF NOT EXISTS`: matches the Postgres adapter, keeps v0.2.0
  * deployment dependency-free. Flyway swap-in is a v0.3.0+ concern.
  */
object MysqlEventJournal:

  /** Resource-managed MySQL-backed journal. Acquires a HikariCP `Transactor`, runs the bootstrap migration
    * (idempotent), and yields the journal. Releasing the resource closes the pool.
    */
  def make(config: MysqlJournalConfig): Resource[IO, EventJournal[IO]] =
    for
      ec <- ExecutionContexts.fixedThreadPool[IO](config.poolSize)
      xa <- HikariTransactor.newHikariTransactor[IO](
        driverClassName = "com.mysql.cj.jdbc.Driver",
        url = config.jdbcUrl,
        user = config.username,
        pass = config.password,
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
        seq           BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
        event_id      VARCHAR(64)  NOT NULL UNIQUE,
        key_id        VARCHAR(256) NOT NULL,
        event_type    VARCHAR(32)  NOT NULL,
        occurred_at   VARCHAR(40)  NOT NULL,
        actor_subject VARCHAR(256) NOT NULL,
        payload       JSON         NOT NULL,
        inserted_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
      )
    """.update.run

  private val createIndex: doobie.ConnectionIO[Int] =
    sql"""
      CREATE INDEX aegis_key_events_key_id_idx
      ON aegis_key_events(key_id)
    """.update.run

  /** Idempotent bootstrap. MySQL has no `CREATE INDEX IF NOT EXISTS`, so we catch the duplicate-key error on
    * the index step. The table step is naturally idempotent via `CREATE TABLE IF NOT EXISTS`.
    */
  private def bootstrap(xa: Transactor[IO]): IO[Unit] =
    val program =
      for
        _ <- createTable
        _ <- createIndex.attemptSql.map {
          case Left(e) if isDuplicateKeyError(e) => 0
          case Left(e)                           => throw e
          case Right(n)                          => n
        }
      yield ()
    program.transact(xa).void

  /** MySQL returns SQLSTATE `42000` (Syntax error / access rule violation) with `ERROR 1061 (42000):
    * Duplicate key name` when an index of the same name already exists. We match on the vendor error code
    * (`1061`) for reliability across SQLSTATE conventions.
    */
  private def isDuplicateKeyError(e: java.sql.SQLException): Boolean =
    e.getErrorCode == 1061

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
                  s"Failed to decode KeyEvent from MySQL journal payload: ${err.getMessage}"
                ))
          }
        }
