package dev.aegiskms.app

import cats.effect.IO
import dev.aegiskms.core.*
import io.micrometer.core.instrument.{MeterRegistry, Timer}

import java.util.concurrent.TimeUnit

/** `KeyService[IO]` decorator that records a counter + latency timer per operation, plus an error counter
  * tagged by the failing `KmsError.code`. The output is the application-side half of issue #10's metric set —
  * request rate, latency histogram, error rate, all per-operation.
  *
  * Layered position: this sits **outside** `AuthorizingKeyService` and **inside** `AuditingKeyService`. The
  * audit row should always reflect the true outcome (including denies + errors), so audit must be the
  * outermost decorator. Metrics, on the other hand, want to count denies as failures with the
  * `code=PermissionDenied` tag — that requires sitting on the deny side of the auth gate, i.e. outside it.
  * Concretely the chain reads from the wire in:
  *
  * `AuditingKeyService → MeteredKeyService → AuthorizingKeyService → ActorBackedKeyService`
  *
  * Metric names follow Prometheus convention (snake_case with the `aegis_` prefix). Counters use `_total` as
  * the suffix; timers expose `_seconds` (Micrometer maps `Timer` to a histogram + `_count` + `_sum`).
  *
  * The timer publishes percentile histograms so dashboards can render p50/p95/p99 without re-deriving from
  * the count + sum fields.
  */
final class MeteredKeyService(inner: KeyService[IO], registry: MeterRegistry) extends KeyService[IO]:

  def create(spec: KeySpec, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(Operation.Create)(inner.create(spec, by))

  def get(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(Operation.Get)(inner.get(id, by))

  def locate(namePattern: String, by: Principal): IO[List[ManagedKey]] =
    val started = System.nanoTime()
    inner.locate(namePattern, by).flatTap { _ =>
      IO {
        opTimer(Operation.Locate, "success").record(System.nanoTime() - started, TimeUnit.NANOSECONDS)
        opCounter(Operation.Locate).increment()
      }
    }

  def activate(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(Operation.Activate)(inner.activate(id, by))

  def revoke(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(Operation.Revoke)(inner.revoke(id, by))

  def destroy(id: KeyId, by: Principal): IO[Either[KmsError, Unit]] =
    instrument(Operation.Destroy)(inner.destroy(id, by))

  def sign(
      id: KeyId,
      message: Array[Byte],
      alg: SigAlgorithm,
      by: Principal
  ): IO[Either[KmsError, Signature]] =
    instrument(Operation.Sign)(inner.sign(id, message, alg, by))

  def verify(
      id: KeyId,
      message: Array[Byte],
      signature: Signature,
      by: Principal
  ): IO[Either[KmsError, Boolean]] =
    instrument(Operation.Verify)(inner.verify(id, message, signature, by))

  def encrypt(
      id: KeyId,
      plaintext: Array[Byte],
      context: Map[String, String],
      by: Principal
  ): IO[Either[KmsError, Ciphertext]] =
    instrument(Operation.Encrypt)(inner.encrypt(id, plaintext, context, by))

  def decrypt(
      id: KeyId,
      ciphertext: Ciphertext,
      context: Map[String, String],
      by: Principal
  ): IO[Either[KmsError, Array[Byte]]] =
    instrument(Operation.Decrypt)(inner.decrypt(id, ciphertext, context, by))

  def wrap(id: KeyId, dek: Array[Byte], by: Principal): IO[Either[KmsError, WrappedDek]] =
    instrument(Operation.Wrap)(inner.wrap(id, dek, by))

  def unwrap(
      id: KeyId,
      wrapped: WrappedDek,
      by: Principal
  ): IO[Either[KmsError, Array[Byte]]] =
    instrument(Operation.Unwrap)(inner.unwrap(id, wrapped, by))

  def compromise(id: KeyId, reason: String, by: Principal): IO[Either[KmsError, ManagedKey]] =
    instrument(Operation.Compromise)(inner.compromise(id, reason, by))

  def rotate(
      id: KeyId,
      policy: RotationPolicy,
      by: Principal
  ): IO[Either[KmsError, ManagedKey]] =
    instrument(Operation.Rotate)(inner.rotate(id, policy, by))

  // ── Helpers ────────────────────────────────────────────────────────────────

  /** Run `action`, record the timer with the success/failure outcome tag, increment the per-op counter, and
    * on `Left` increment the error counter tagged by the `KmsError.code`. The timing is wall-clock
    * `System.nanoTime` — sufficient for p50/p95/p99 dashboarding; we don't try to compensate for thread-park
    * time across `IO.fromFuture`.
    */
  private def instrument[A](op: Operation)(
      action: IO[Either[KmsError, A]]
  ): IO[Either[KmsError, A]] =
    IO(System.nanoTime()).flatMap { started =>
      action.flatTap { result =>
        IO {
          val elapsedNs = System.nanoTime() - started
          val outcome   = if result.isRight then "success" else "failure"
          opTimer(op, outcome).record(elapsedNs, TimeUnit.NANOSECONDS)
          opCounter(op).increment()
          result.left.foreach(err => errorCounter(op, err.code).increment())
        }
      }
    }

  private def opCounter(op: Operation) =
    registry.counter("aegis_keys_op_total", "operation", op.toString)

  private def opTimer(op: Operation, outcome: String): Timer =
    Timer.builder("aegis_keys_op_duration_seconds")
      .tag("operation", op.toString)
      .tag("outcome", outcome)
      .publishPercentileHistogram()
      .register(registry)

  private def errorCounter(op: Operation, code: ErrorCode) =
    registry.counter("aegis_keys_op_errors_total", "operation", op.toString, "code", code.toString)
