package dev.aegiskms.audit

import cats.effect.{IO, Ref}

import java.time.Instant

/** Test/dev `AuditSink` that retains every record in a `Ref`-backed buffer.
  *
  * Useful for unit tests that assert audit-trail properties without a database, and for the dev-mode server
  * where operators tail records via the CLI.
  *
  * Also implements [[AuditQuery]] with the same filter semantics as `PostgresAuditSink`, so consumers of the
  * read side (the audit-read endpoint, the advisor, the agent registry) can be unit-tested against a real
  * implementation rather than a hand-rolled stub that only approximates the contract. It is deliberately
  * *not* selectable via `aegis.audit.kind` — a key-management service whose audit trail evaporates on restart
  * is not something an operator should be able to configure by accident.
  */
final class InMemoryAuditSink private (ref: Ref[IO, Vector[AuditRecord]])
    extends AuditSink[IO]
    with AuditQuery[IO]:
  def write(record: AuditRecord): IO[Unit] = ref.update(_ :+ record)

  /** All records currently retained, in insertion order. */
  def all: IO[List[AuditRecord]] = ref.get.map(_.toList)

  /** Drop all retained records — for tests that want a fresh slate without rebuilding the sink. */
  def clear: IO[Unit] = ref.set(Vector.empty)

  /** Mirrors the Postgres implementation: filters AND together, newest first, `limit + 1` probe to derive
    * `hasMore` without a second pass.
    */
  def query(filter: AuditQuery.Filter): IO[AuditQuery.Page] =
    val safeLimit  = math.max(1, math.min(filter.limit, AuditQuery.MaxLimit))
    val safeOffset = math.max(0, filter.offset)
    ref.get.map { all =>
      val matched = all.filter(matches(filter, _))
        // `occurred_at DESC, seq DESC` in SQL. Insertion order stands in for `seq`, so reversing the
        // buffer before a stable sort reproduces the tie-break for records sharing a timestamp.
        .reverse
        .sortWith((a, b) => a.at.isAfter(b.at))
      val window  = matched.drop(safeOffset)
      val hasMore = window.size > safeLimit
      AuditQuery.Page(window.take(safeLimit).toList, safeLimit, safeOffset, hasMore)
    }

  def lastActivityBy(actors: Set[String], since: Instant): IO[Map[String, Instant]] =
    if actors.isEmpty then IO.pure(Map.empty)
    else
      ref.get.map { all =>
        all
          .filter(r => actors.contains(r.principal.subject) && !r.at.isBefore(since))
          .groupMapReduce(_.principal.subject)(_.at)((a, b) => if a.isAfter(b) then a else b)
      }

  private def matches(filter: AuditQuery.Filter, r: AuditRecord): Boolean =
    filter.since.forall(s => !r.at.isBefore(s)) &&
      filter.until.forall(u => r.at.isBefore(u)) &&
      filter.actor.forall(_ == r.principal.subject) &&
      filter.resource.forall(_ == r.resource) &&
      filter.resourcePrefix.forall(r.resource.startsWith) &&
      filter.operation.forall(_ == r.operation)

object InMemoryAuditSink:
  def make: IO[InMemoryAuditSink] =
    Ref.of[IO, Vector[AuditRecord]](Vector.empty).map(new InMemoryAuditSink(_))
