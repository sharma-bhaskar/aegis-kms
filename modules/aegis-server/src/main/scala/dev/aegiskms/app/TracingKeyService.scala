package dev.aegiskms.app

import cats.effect.IO
import dev.aegiskms.core.*
import io.opentelemetry.api.common.{AttributeKey, Attributes}
import io.opentelemetry.api.trace.{Span, StatusCode, Tracer}

/** `KeyService[IO]` decorator that wraps each call in an OpenTelemetry span. The span name is
  * `kms.<operation>` (lowercase), and the span carries a small attribute set:
  *
  *   - `aegis.operation` — the `Operation` enum value (`Sign`, `Encrypt`, …).
  *   - `aegis.key.id` — the `KeyId.value` for ops that take one (omitted for `create` and `locate` since the
  *     id either doesn't exist yet or doesn't apply).
  *   - `aegis.principal.subject` — the calling principal's subject.
  *   - `aegis.principal.kind` — `human` or `agent`.
  *   - `aegis.outcome` — `success`, `failure`, or `error_<code>` on `Left`. Span status is set to `ERROR` on
  *     failure with the `KmsError` message as the description.
  *
  * Layered position: this sits **outside** `MeteredKeyService` and **inside** `AuditingKeyService`. The trace
  * span thus measures auth + actor + journal as one unit; metrics record their own (smaller) timer next to
  * it. Audit stays the outermost layer so the audit row reflects the post-trace outcome.
  *
  * Concretely the chain reads from the wire in:
  *
  * `AuditingKeyService → TracingKeyService → MeteredKeyService → AuthorizingKeyService →
  * ActorBackedKeyService`
  *
  * **Context propagation.** When the OpenTelemetry Java Agent is attached, an inbound HTTP request already
  * carries an active server span; this decorator's `spanBuilder` picks it up as the parent via the
  * thread-local `Context.current()`. Without the agent (e.g. local dev without OTel), spans are still created
  * but without parents — they show up as roots in whatever exporter is configured (or silently dropped if
  * `OTEL_TRACES_EXPORTER=none`).
  */
final class TracingKeyService(inner: KeyService[IO], tracer: Tracer) extends KeyService[IO]:

  import TracingKeyService.*

  def create(spec: KeySpec, by: Principal): IO[Either[KmsError, ManagedKey]] =
    traced(Operation.Create, keyId = None, by)(inner.create(spec, by))

  def get(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    traced(Operation.Get, Some(id), by)(inner.get(id, by))

  def locate(namePattern: String, by: Principal): IO[List[ManagedKey]] =
    // `locate` returns `List` rather than `Either`; we can't share the helper. Hand-roll the same
    // outcome handling without the `Either` branch.
    IO(startSpan(Operation.Locate, keyId = None, by)).flatMap { span =>
      inner.locate(namePattern, by).attempt.flatMap {
        case Right(list) =>
          IO {
            span.setAttribute("aegis.outcome", "success")
            span.setAttribute("aegis.locate.hits", list.size.toLong)
            span.end()
          } *> IO.pure(list)
        case Left(t) =>
          IO {
            span.setStatus(StatusCode.ERROR, t.getMessage)
            span.recordException(t)
            span.end()
          } *> IO.raiseError(t)
      }
    }

  def activate(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    traced(Operation.Activate, Some(id), by)(inner.activate(id, by))

  def revoke(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    traced(Operation.Revoke, Some(id), by)(inner.revoke(id, by))

  def destroy(id: KeyId, by: Principal): IO[Either[KmsError, Unit]] =
    traced(Operation.Destroy, Some(id), by)(inner.destroy(id, by))

  def sign(
      id: KeyId,
      message: Array[Byte],
      alg: SigAlgorithm,
      by: Principal
  ): IO[Either[KmsError, Signature]] =
    traced(Operation.Sign, Some(id), by, detail = alg.toString)(inner.sign(id, message, alg, by))

  def verify(
      id: KeyId,
      message: Array[Byte],
      signature: Signature,
      by: Principal
  ): IO[Either[KmsError, Boolean]] =
    traced(Operation.Verify, Some(id), by, detail = signature.algorithm.toString)(
      inner.verify(id, message, signature, by)
    )

  def encrypt(
      id: KeyId,
      plaintext: Array[Byte],
      context: Map[String, String],
      by: Principal
  ): IO[Either[KmsError, Ciphertext]] =
    traced(Operation.Encrypt, Some(id), by)(inner.encrypt(id, plaintext, context, by))

  def decrypt(
      id: KeyId,
      ciphertext: Ciphertext,
      context: Map[String, String],
      by: Principal
  ): IO[Either[KmsError, Array[Byte]]] =
    traced(Operation.Decrypt, Some(id), by)(inner.decrypt(id, ciphertext, context, by))

  def wrap(id: KeyId, dek: Array[Byte], by: Principal): IO[Either[KmsError, WrappedDek]] =
    traced(Operation.Wrap, Some(id), by)(inner.wrap(id, dek, by))

  def unwrap(
      id: KeyId,
      wrapped: WrappedDek,
      by: Principal
  ): IO[Either[KmsError, Array[Byte]]] =
    traced(Operation.Unwrap, Some(id), by)(inner.unwrap(id, wrapped, by))

  def compromise(id: KeyId, reason: String, by: Principal): IO[Either[KmsError, ManagedKey]] =
    traced(Operation.Compromise, Some(id), by)(inner.compromise(id, reason, by))

  def rotate(
      id: KeyId,
      policy: RotationPolicy,
      by: Principal
  ): IO[Either[KmsError, ManagedKey]] =
    traced(Operation.Rotate, Some(id), by, detail = policy.render)(inner.rotate(id, policy, by))

  // ── Helpers ────────────────────────────────────────────────────────────────

  /** Open a span, run `action`, set outcome attributes + status from the resulting `Either`, always close the
    * span. `detail` is an optional extra attribute (algorithm string for sign/verify, policy for rotate) —
    * `""` skips setting it.
    */
  private def traced[A](
      op: Operation,
      keyId: Option[KeyId],
      by: Principal,
      detail: String = ""
  )(action: IO[Either[KmsError, A]]): IO[Either[KmsError, A]] =
    IO(startSpan(op, keyId, by)).flatMap { span =>
      if detail.nonEmpty then span.setAttribute("aegis.detail", detail): Unit
      action.flatTap { result =>
        IO {
          result match
            case Right(_) =>
              span.setAttribute("aegis.outcome", "success"): Unit
            case Left(err) =>
              span.setAttribute("aegis.outcome", s"error_${err.code}")
              span.setStatus(StatusCode.ERROR, err.message)
          span.end()
        }
      }.handleErrorWith { t =>
        IO {
          span.setStatus(StatusCode.ERROR, t.getMessage)
          span.recordException(t)
          span.end()
        } *> IO.raiseError(t)
      }
    }

  private def startSpan(op: Operation, keyId: Option[KeyId], by: Principal): Span =
    val builder = tracer.spanBuilder(s"kms.${op.toString.toLowerCase}")
    val attrs   = Attributes.builder()
    attrs.put(OperationAttr, op.toString)
    keyId.foreach(id => attrs.put(KeyIdAttr, id.value))
    attrs.put(PrincipalSubjectAttr, by.subject)
    attrs.put(PrincipalKindAttr, principalKind(by))
    builder.setAllAttributes(attrs.build()).startSpan()

  private def principalKind(p: Principal): String = p match
    case _: Principal.Agent => "agent"
    case _                  => "human"

object TracingKeyService:
  // Pre-build the AttributeKey instances; the SDK caches but the API charges an allocation per build()
  // otherwise.
  private val OperationAttr        = AttributeKey.stringKey("aegis.operation")
  private val KeyIdAttr            = AttributeKey.stringKey("aegis.key.id")
  private val PrincipalSubjectAttr = AttributeKey.stringKey("aegis.principal.subject")
  private val PrincipalKindAttr    = AttributeKey.stringKey("aegis.principal.kind")
