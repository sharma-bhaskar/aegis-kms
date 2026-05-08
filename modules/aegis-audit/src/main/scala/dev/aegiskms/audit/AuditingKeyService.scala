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
    instrument {
      inner.create(spec, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(k) => s"Success keyId=${k.id.value}"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Create, resourceForCreate(spec), outcome, corr)
    }

  def get(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument {
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
    instrument {
      inner.activate(id, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(_) => "Success"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Activate, id.value, outcome, corr)
    }

  def revoke(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument {
      inner.revoke(id, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(_) => "Success"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Revoke, id.value, outcome, corr)
    }

  def destroy(id: KeyId, by: Principal): IO[Either[KmsError, Unit]] =
    instrument {
      inner.destroy(id, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(_) => "Success"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Destroy, id.value, outcome, corr)
    }

  def sign(
      id: KeyId,
      message: Array[Byte],
      alg: SigAlgorithm,
      by: Principal
  ): IO[Either[KmsError, Signature]] =
    instrument {
      inner.sign(id, message, alg, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(_) => s"Success alg=$alg msgLen=${message.length}"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Sign, id.value, outcome, corr)
    }

  def verify(
      id: KeyId,
      message: Array[Byte],
      signature: Signature,
      by: Principal
  ): IO[Either[KmsError, Boolean]] =
    instrument {
      inner.verify(id, message, signature, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(true)  => s"Success valid=true alg=${signature.algorithm}"
        case Right(false) => s"Success valid=false alg=${signature.algorithm}"
        case Left(e)      => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Verify, id.value, outcome, corr)
    }

  def encrypt(
      id: KeyId,
      plaintext: Array[Byte],
      context: Map[String, String],
      by: Principal
  ): IO[Either[KmsError, Ciphertext]] =
    instrument {
      inner.encrypt(id, plaintext, context, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(_) =>
          s"Success ctxKeys=${context.keys.toSeq.sorted.mkString(",")} ptLen=${plaintext.length}"
        case Left(e) => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Encrypt, id.value, outcome, corr)
    }

  def decrypt(
      id: KeyId,
      ciphertext: Ciphertext,
      context: Map[String, String],
      by: Principal
  ): IO[Either[KmsError, Array[Byte]]] =
    instrument {
      inner.decrypt(id, ciphertext, context, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(pt) => s"Success ctxKeys=${context.keys.toSeq.sorted.mkString(",")} ptLen=${pt.length}"
        case Left(e)   => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Decrypt, id.value, outcome, corr)
    }

  def wrap(id: KeyId, dek: Array[Byte], by: Principal): IO[Either[KmsError, WrappedDek]] =
    instrument {
      inner.wrap(id, dek, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(_) => s"Success dekLen=${dek.length}"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Wrap, id.value, outcome, corr)
    }

  def unwrap(
      id: KeyId,
      wrapped: WrappedDek,
      by: Principal
  ): IO[Either[KmsError, Array[Byte]]] =
    instrument {
      inner.unwrap(id, wrapped, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(dek) => s"Success dekLen=${dek.length}"
        case Left(e)    => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Unwrap, id.value, outcome, corr)
    }

  def compromise(id: KeyId, reason: String, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument {
      inner.compromise(id, reason, by)
    } { (now, corr, result) =>
      // Compromise is the highest-severity event in the system. Mark the audit row with the
      // `severity=Critical` prefix so SIEM ingestion can route on it without re-deriving from
      // the operation type alone.
      val outcome = result match
        case Right(_) => s"severity=Critical Success reason=$reason"
        case Left(e)  => s"severity=Critical Failed code=${e.code} reason=$reason"
      AuditRecord(now, by, Operation.Compromise, id.value, outcome, corr)
    }

  def rotate(id: KeyId, policy: RotationPolicy, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument {
      inner.rotate(id, policy, by)
    } { (now, corr, result) =>
      val outcome = result match
        case Right(k) => s"Success newVersion=${k.currentVersion} policy=${policy.render}"
        case Left(e)  => s"Failed code=${e.code} policy=${policy.render}"
      AuditRecord(now, by, Operation.Rotate, id.value, outcome, corr)
    }

  // ── Helpers ────────────────────────────────────────────────────────────────

  /** Threads a fresh correlation id and a wall-clock timestamp through the action and writes the resulting
    * `AuditRecord`. The caller closes over `op`, `by`, and `resource` directly when building the record —
    * this helper deliberately doesn't take them, since duplicating that parameter list (helper + closure) was
    * dead weight (and the compiler's `-Wunused` agreed).
    */
  private def instrument[A](action: => IO[A])(
      record: (java.time.Instant, String, A) => AuditRecord
  ): IO[A] =
    for
      corr   <- IO(freshCorrelationId())
      result <- action
      now    <- IO.realTimeInstant
      _      <- sink.write(record(now, corr, result))
    yield result

  private def resourceForCreate(spec: KeySpec): String =
    s"name:${spec.name}/alg:${spec.algorithm}/size:${spec.sizeBits}"

  private def freshCorrelationId(): String = UUID.randomUUID().toString
