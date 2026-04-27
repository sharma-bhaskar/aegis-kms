package dev.aegiskms.audit

import cats.effect.{IO, Ref}

/** Test/dev `AuditSink` that retains every record in a `Ref`-backed buffer.
  *
  * Useful for unit tests that assert audit-trail properties without a database, and for the dev-mode server
  * where operators tail records via the CLI.
  */
final class InMemoryAuditSink private (ref: Ref[IO, Vector[AuditRecord]]) extends AuditSink[IO]:
  def write(record: AuditRecord): IO[Unit] = ref.update(_ :+ record)

  /** All records currently retained, in insertion order. */
  def all: IO[List[AuditRecord]] = ref.get.map(_.toList)

  /** Drop all retained records — for tests that want a fresh slate without rebuilding the sink. */
  def clear: IO[Unit] = ref.set(Vector.empty)

object InMemoryAuditSink:
  def make: IO[InMemoryAuditSink] =
    Ref.of[IO, Vector[AuditRecord]](Vector.empty).map(new InMemoryAuditSink(_))
