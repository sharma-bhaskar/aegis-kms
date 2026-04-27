package dev.aegiskms.persistence

import cats.effect.{IO, Ref}
import cats.syntax.all.*
import dev.aegiskms.core.KeyEvent

/** Append-only journal of `KeyEvent`s. The lifecycle actor in `aegis-server` writes one event per state
  * transition and replays the full journal on boot, so the journal is the single source of truth for managed
  * keys.
  *
  * The contract is intentionally tiny:
  *   - `append` MUST be durable before it returns. If the durable store is unreachable, append fails and the
  *     caller is responsible for surfacing that failure to the originating client.
  *   - `replay` returns events in the same order they were appended. An implementation MAY internally store
  *     events out-of-order (e.g. Kafka with multiple partitions) but MUST surface a consistent total order
  *     per `keyId`.
  *
  * Bundled implementations:
  *   - `InMemoryEventJournal` (this file) — tests and the developer mode in `aegis-server`.
  *   - Doobie/Postgres — to land in PR F1.b alongside the schema migration.
  *
  * Community backends expected: Kafka, S3 object store, OpenTelemetry logs.
  */
trait EventJournal[F[_]]:

  /** Append a single event. Must be durable before this completes. */
  def append(event: KeyEvent): F[Unit]

  /** Stream the full event log in append order. Used for actor recovery on boot. */
  def replay(): F[List[KeyEvent]]

object EventJournal:

  /** Build an in-memory journal backed by a `Ref`. Not durable — for tests and dev. */
  def inMemory: IO[EventJournal[IO]] =
    Ref.of[IO, Vector[KeyEvent]](Vector.empty).map { ref =>
      new EventJournal[IO]:
        def append(event: KeyEvent): IO[Unit] = ref.update(_ :+ event)
        def replay(): IO[List[KeyEvent]]      = ref.get.map(_.toList)
    }
