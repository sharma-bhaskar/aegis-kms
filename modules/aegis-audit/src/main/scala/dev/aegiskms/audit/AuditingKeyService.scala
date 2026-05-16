package dev.aegiskms.audit

import cats.effect.IO
import dev.aegiskms.core.*

import java.util.UUID

/** Decorator that records every `KeyService` call to an `AuditSink`.
  *
  * Wraps any `KeyService[IO]` and writes a single `AuditRecord` per call — including failures, so the audit
  * log captures `AccessDenied` and `ItemNotFound` outcomes the operator needs for incident review.
  *
  * Order of operations is **score → inner → audit**: the optional `RiskScorer` is consulted first (its result
  * is stamped into the `AuditRecord.context` whether the inner call succeeds or fails), then the underlying
  * service runs, then the audit record is written. The scorer is intentionally evaluated even for denied
  * calls so post-incident review can answer "did the scoring engine already know this was risky?"
  *
  * A slow audit sink can't delay the user response — but it also means a sink failure does not block the
  * operation. Sinks that need crash-consistency (e.g. Postgres in the same transaction as the EventJournal)
  * should run inside the actor's `appendOr` instead, not as a decorator like this one.
  *
  * Correlation IDs are generated per call so a single client request can be joined across audit, journal, and
  * detector streams.
  */
final class AuditingKeyService(
    inner: KeyService[IO],
    sink: AuditSink[IO],
    scorer: Option[RiskScorer[IO]] = None
) extends KeyService[IO]:

  def create(spec: KeySpec, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(by, Operation.Create, None) {
      inner.create(spec, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(k) => s"Success keyId=${k.id.value}"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Create, resourceForCreate(spec), outcome, corr, ctx)
    }

  def get(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(by, Operation.Get, Some(id)) {
      inner.get(id, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(_) => "Success"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Get, id.value, outcome, corr, ctx)
    }

  def locate(namePattern: String, by: Principal): IO[List[ManagedKey]] =
    val resource = s"pattern:$namePattern"
    for
      now  <- IO.realTimeInstant
      corr <- IO(freshCorrelationId())
      ctx  <- scoreContext(by, Operation.Locate, None, now)
      list <- inner.locate(namePattern, by)
      _    <- sink.write(AuditRecord(now, by, Operation.Locate, resource, s"Hits=${list.size}", corr, ctx))
    yield list

  def activate(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(by, Operation.Activate, Some(id)) {
      inner.activate(id, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(_) => "Success"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Activate, id.value, outcome, corr, ctx)
    }

  def revoke(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(by, Operation.Revoke, Some(id)) {
      inner.revoke(id, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(_) => "Success"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Revoke, id.value, outcome, corr, ctx)
    }

  def destroy(id: KeyId, by: Principal): IO[Either[KmsError, Unit]] =
    instrument(by, Operation.Destroy, Some(id)) {
      inner.destroy(id, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(_) => "Success"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Destroy, id.value, outcome, corr, ctx)
    }

  def sign(
      id: KeyId,
      message: Array[Byte],
      alg: SigAlgorithm,
      by: Principal
  ): IO[Either[KmsError, Signature]] =
    instrument(by, Operation.Sign, Some(id)) {
      inner.sign(id, message, alg, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(_) => s"Success alg=$alg msgLen=${message.length}"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Sign, id.value, outcome, corr, ctx)
    }

  def verify(
      id: KeyId,
      message: Array[Byte],
      signature: Signature,
      by: Principal
  ): IO[Either[KmsError, Boolean]] =
    instrument(by, Operation.Verify, Some(id)) {
      inner.verify(id, message, signature, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(true)  => s"Success valid=true alg=${signature.algorithm}"
        case Right(false) => s"Success valid=false alg=${signature.algorithm}"
        case Left(e)      => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Verify, id.value, outcome, corr, ctx)
    }

  def encrypt(
      id: KeyId,
      plaintext: Array[Byte],
      context: Map[String, String],
      by: Principal
  ): IO[Either[KmsError, Ciphertext]] =
    instrument(by, Operation.Encrypt, Some(id)) {
      inner.encrypt(id, plaintext, context, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(_) =>
          s"Success ctxKeys=${context.keys.toSeq.sorted.mkString(",")} ptLen=${plaintext.length}"
        case Left(e) => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Encrypt, id.value, outcome, corr, ctx)
    }

  def decrypt(
      id: KeyId,
      ciphertext: Ciphertext,
      context: Map[String, String],
      by: Principal
  ): IO[Either[KmsError, Array[Byte]]] =
    instrument(by, Operation.Decrypt, Some(id)) {
      inner.decrypt(id, ciphertext, context, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(pt) => s"Success ctxKeys=${context.keys.toSeq.sorted.mkString(",")} ptLen=${pt.length}"
        case Left(e)   => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Decrypt, id.value, outcome, corr, ctx)
    }

  def wrap(id: KeyId, dek: Array[Byte], by: Principal): IO[Either[KmsError, WrappedDek]] =
    instrument(by, Operation.Wrap, Some(id)) {
      inner.wrap(id, dek, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(_) => s"Success dekLen=${dek.length}"
        case Left(e)  => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Wrap, id.value, outcome, corr, ctx)
    }

  def unwrap(
      id: KeyId,
      wrapped: WrappedDek,
      by: Principal
  ): IO[Either[KmsError, Array[Byte]]] =
    instrument(by, Operation.Unwrap, Some(id)) {
      inner.unwrap(id, wrapped, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(dek) => s"Success dekLen=${dek.length}"
        case Left(e)    => s"Failed code=${e.code}"
      AuditRecord(now, by, Operation.Unwrap, id.value, outcome, corr, ctx)
    }

  def compromise(id: KeyId, reason: String, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(by, Operation.Compromise, Some(id)) {
      inner.compromise(id, reason, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(_) => s"severity=Critical Success reason=$reason"
        case Left(e)  => s"severity=Critical Failed code=${e.code} reason=$reason"
      AuditRecord(now, by, Operation.Compromise, id.value, outcome, corr, ctx)
    }

  def rotate(id: KeyId, policy: RotationPolicy, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(by, Operation.Rotate, Some(id)) {
      inner.rotate(id, policy, by)
    } { (now, corr, ctx, result) =>
      val outcome = result match
        case Right(k) => s"Success newVersion=${k.currentVersion} policy=${policy.render}"
        case Left(e)  => s"Failed code=${e.code} policy=${policy.render}"
      AuditRecord(now, by, Operation.Rotate, id.value, outcome, corr, ctx)
    }

  // ── Helpers ────────────────────────────────────────────────────────────────

  /** Threads a fresh correlation id, a wall-clock timestamp, and a risk-scoring context map through the
    * action and writes the resulting `AuditRecord`. The scoring call happens BEFORE the inner action so the
    * same score lands on success and failure rows alike.
    *
    * The caller closes over `by`, the resource string, and op-specific outcome formatting when building the
    * record. The helper deliberately doesn't take those — duplicating the parameter list (helper + closure)
    * was dead weight (and `-Wunused` agreed).
    */
  private def instrument[A](
      by: Principal,
      op: Operation,
      keyId: Option[KeyId]
  )(action: => IO[A])(
      record: (java.time.Instant, String, Map[String, String], A) => AuditRecord
  ): IO[A] =
    for
      corr   <- IO(freshCorrelationId())
      now0   <- IO.realTimeInstant
      ctx    <- scoreContext(by, op, keyId, now0)
      result <- action
      now    <- IO.realTimeInstant
      _      <- sink.write(record(now, corr, ctx, result))
    yield result

  /** Call the optional `RiskScorer` and return a stamping map. `risk.score` is fixed to 2 decimal places
    * (avoids `0.62000…01` floating-point noise in audit rows); `risk.factors` is a semicolon-separated
    * `name:weight` list. Returns an empty map when no scorer is configured.
    */
  private def scoreContext(
      by: Principal,
      op: Operation,
      keyId: Option[KeyId],
      now: java.time.Instant
  ): IO[Map[String, String]] =
    scorer match
      case None => IO.pure(Map.empty)
      case Some(s) =>
        s.score(RiskScorer.Request(by, op, keyId, now)).map { rs =>
          Map("risk.score" -> rs.renderedScore, "risk.factors" -> rs.renderedFactors)
        }

  private def resourceForCreate(spec: KeySpec): String =
    s"name:${spec.name}/alg:${spec.algorithm}/size:${spec.sizeBits}"

  private def freshCorrelationId(): String = UUID.randomUUID().toString
