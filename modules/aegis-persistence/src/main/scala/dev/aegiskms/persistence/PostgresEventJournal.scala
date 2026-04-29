package dev.aegiskms.persistence

import cats.effect.{IO, Resource}
import cats.syntax.all.*
import dev.aegiskms.core.KeyEvent
import dev.aegiskms.core.codecs.KeyEventCodec.given
import doobie.*
import doobie.hikari.HikariTransactor
import doobie.implicits.*
import doobie.postgres.circe.jsonb.implicits.*
import doobie.postgres.implicits.*
import io.circe.Json
import io.circe.syntax.*

/** Doobie-backed Postgres implementation of [[EventJournal]].
  *
  * Schema:
  * {{{
  *   aegis_key_events (
  *     seq           BIGSERIAL    PRIMARY KEY,    -- monotonic insertion order; replay() ORDER BYs this
  *     event_id      VARCHAR(64)  NOT NULL UNIQUE,-- KeyEvent.eventId, idempotency key
  *     key_id        VARCHAR(256) NOT NULL,       -- denormalised for per-key indexes
  *     event_type    VARCHAR(32)  NOT NULL,       -- denormalised discriminator
  *     occurred_at   TIMESTAMPTZ  NOT NULL,       -- decision time inside KeyOpsActor (NOT insert time)
  *     actor_subject VARCHAR(256) NOT NULL,
  *     payload       JSONB        NOT NULL,       -- full circe-encoded KeyEvent
  *     inserted_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
  *   )
  * }}}
  *
  * Why JSONB rather than fully-normalised columns: `KeyEvent` is going to grow more variants (Rotated,
  * Imported, Wrapped). Storing the full payload in JSONB lets the trait grow without DDL changes, and the
  * denormalised columns above cover everything the operational queries need (per-key history, time range,
  * actor scope). The codec round-trip in `KeyEventCodecSpec` is the gate that keeps the JSONB readable.
  *
  * Why one bootstrap migration via `CREATE TABLE IF NOT EXISTS`: keeps the v0.1.0 deployment dependency-free.
  * When the schema needs to evolve in v0.2.0, swap in Flyway under `bootstrap()` without changing the SPI.
  */
object PostgresEventJournal:

  /** Resource-managed Postgres-backed journal. Acquires a HikariCP-backed `Transactor`, runs the bootstrap
    * migration (idempotent), and yields the journal. Releasing the resource shuts the pool down cleanly.
    *
    * Use this from `aegis-server`'s `Server.scala` boot path.
    */
  def make(config: PostgresJournalConfig): Resource[IO, EventJournal[IO]] =
    for
      ec <- ExecutionContexts.fixedThreadPool[IO](config.poolSize)
      xa <- HikariTransactor.newHikariTransactor[IO](
        driverClassName = "org.postgresql.Driver",
        url = config.jdbcUrl,
        user = config.username,
        pass = config.password,
        connectEC = ec
      )
      _ <- Resource.eval(bootstrap(xa))
    yield Impl(xa)

  /** Test/embedding seam: take an existing `Transactor` (e.g. from a Testcontainers Postgres or an in-memory
    * H2 wired by the embedder), run the bootstrap migration, and yield a journal. The caller owns the
    * transactor's lifecycle.
    */
  def bootstrappedFor(xa: Transactor[IO]): IO[EventJournal[IO]] =
    bootstrap(xa).as(Impl(xa))

  // ── Migration ────────────────────────────────────────────────────────────────

  private val createTable: doobie.ConnectionIO[Int] =
    sql"""
      CREATE TABLE IF NOT EXISTS aegis_key_events (
        seq           BIGSERIAL    PRIMARY KEY,
        event_id      VARCHAR(64)  NOT NULL UNIQUE,
        key_id        VARCHAR(256) NOT NULL,
        event_type    VARCHAR(32)  NOT NULL,
        occurred_at   TIMESTAMPTZ  NOT NULL,
        actor_subject VARCHAR(256) NOT NULL,
        payload       JSONB        NOT NULL,
        inserted_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
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

  final private class Impl(xa: Transactor[IO]) extends EventJournal[IO]:

    def append(event: KeyEvent): IO[Unit] =
      val payload = event.asJson
      val kind = event match
        case _: KeyEvent.Created     => "Created"
        case _: KeyEvent.Activated   => "Activated"
        case _: KeyEvent.Deactivated => "Deactivated"
        case _: KeyEvent.Destroyed   => "Destroyed"
      sql"""
        INSERT INTO aegis_key_events
          (event_id, key_id, event_type, occurred_at, actor_subject, payload)
        VALUES
          (${event.eventId}, ${event.keyId.value}, $kind, ${event.at},
           ${event.actorSubject}, $payload)
      """.update.run.transact(xa).void

    def replay(): IO[List[KeyEvent]] =
      sql"""
        SELECT payload
        FROM aegis_key_events
        ORDER BY seq ASC
      """
        .query[Json]
        .to[List]
        .transact(xa)
        .flatMap { rows =>
          rows.traverse { json =>
            json
              .as[KeyEvent]
              .fold(
                err =>
                  IO.raiseError(
                    new RuntimeException(
                      s"Failed to decode KeyEvent from journal payload: ${err.getMessage}"
                    )
                  ),
                IO.pure
              )
          }
        }
