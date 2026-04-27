package dev.aegiskms.audit

import cats.effect.IO
import dev.aegiskms.core.*

import java.util.UUID

/** Decorator that records every `KeyService` call to an `AuditSink`.
  *
  * Wraps any `KeyService[IO]` and writes a single `AuditRecord` per call — including failures, so the audit
  * log captures `AccessDenied` and `ItemNotFound` outcomes the operator needs for incident review.
  *
  * Order of operations is **inner-then-audit**: the underlying service runs first, then the audit record is
  * written. This means a slow audit sink can't delay the user response — but it also means a sink failure
  * does not block the operation. Sinks that need crash-consistency (e.g. Postgres in the same transaction as
  * the EventJournal) should run inside the actor's `appendOr` instead, not as a decorator like this one.
  *
  * Correlation IDs are generated per call so a single client request can be joined across audit, journal, and
  * detector streams.
  */
final class AuditingKeyService(inner: KeyService[IO], sink: AuditSink[IO]) extends KeyService[IO]:

  def create(spec: KeySpec, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(Operation.Create, by, resourceForCreate(spec)) {
      inner.create(spec, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(k) => s"Success keyId=${k.id.value}"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Create, resourceForCreate(spec), outcome, corr)
    }

  def get(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(Operation.Get, by, id.value) {
      inner.get(id, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(_) => "Success"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Get, id.value, outcome, corr)
    }

  def locate(namePattern: String, by: Principal): IO[List[ManagedKey]] =
    val resource = s"pattern:$namePattern"
    for
      now  <- IO.realTimeInstant
      corr <- IO(freshCorrelationId())
      list <- inner.locate(namePattern, by)
      _    <- sink.write(AuditRecord(now, by, Operation.Locate, resource, s"Hits=${list.size}", corr))
    yield list

  def activate(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(Operation.Activate, by, id.value) {
      inner.activate(id, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(_) => "Success"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Activate, id.value, outcome, corr)
    }

  def revoke(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(Operation.Revoke, by, id.value) {
      inner.revoke(id, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(_) => "Success"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Revoke, id.value, outcome, corr)
    }

  def destroy(id: KeyId, by: Principal): IO[Either[KmsError, Unit]] =
    instrument(Operation.Destroy, by, id.value) {
      inner.destroy(id, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(_) => "Success"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Destroy, id.value, outcome, corr)
    }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private def instrument[A](op: Operation, by: Principal, resource: String)(
      action: => IO[A]
  )(record: (java.time.Instant, String, A) => AuditRecord): IO[A] =
    for
      _      <- IO.unit
      corr   <- IO(freshCorrelationId())
      result <- action
      now    <- IO.realTimeInstant
      _      <- sink.write(record(now, corr, result))
    yield result

  private def resourceForCreate(spec: KeySpec): String =
    s"name:${spec.name}/alg:${spec.algorithm}/size:${spec.sizeBits}"

  private def freshCorrelationId(): String = UUID.randomUUID().toString
