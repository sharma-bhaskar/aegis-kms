package dev.aegiskms.audit

import cats.effect.IO
import dev.aegiskms.core.*

import java.util.UUID

/** Decorator that records every `KeyService` call to an `AuditSink`, with optional risk-based gating.
  *
  * Wraps any `KeyService[IO]` and writes a single `AuditRecord` per call — including failures, so the audit
  * log captures `AccessDenied`, `StepUpRequired`, and `ItemNotFound` outcomes the operator needs for incident
  * review.
  *
  * Two optional dependencies thread risk-awareness through this decorator:
  *
  *   - `scorer` — a `RiskScorer[IO]` (typically `BaselineRiskScorer` from `aegis-agent-ai`). If present,
  *     every request is scored BEFORE the inner action runs, and the `risk.score` + `risk.factors` are
  *     stamped into the audit row's `context` regardless of outcome.
  *   - `engine` — a `DecisionEngine[IO]` (typically `ThresholdDecisionEngine`). If present, the score is
  *     translated into a `Decision`. `Decision.Deny` short-circuits with a synthetic
  *     `KmsError(PermissionDenied, "risk: …")`; `Decision.StepUp` short-circuits with a synthetic
  *     `KmsError(StepUpRequired, …)` that the HTTP layer maps to `401 + WWW-Authenticate: aegis-stepup`.
  *     `Decision.Allow` (or no engine configured) lets the request through to the inner service. The decision
  *     label and reason land in audit context as `outcome.decision` / `outcome.decision.reason`.
  *
  * The boolean policy gate (`AuthorizingKeyService`) remains the floor — a policy denial cannot be overridden
  * by `Decision.Allow`. The decision adapter is purely additive: it can further restrict an action policy
  * already permits; it cannot widen one policy forbids.
  *
  * Order of operations is **score → decide → (short-circuit | inner) → audit**: the scorer + engine are
  * consulted first (their outputs always land in the audit row), then either we short-circuit or run the
  * underlying service, then the audit record is written. A slow audit sink can't delay the user response, but
  * also can't block the operation — sinks needing crash-consistency belong inside the actor's `appendOr`
  * instead.
  *
  * Correlation IDs are generated per call so a single client request can be joined across audit, journal, and
  * detector streams.
  */
final class AuditingKeyService(
    inner: KeyService[IO],
    sink: AuditSink[IO],
    scorer: Option[RiskScorer[IO]] = None,
    engine: Option[DecisionEngine[IO]] = None,
    /** Per-request context bag (typically the HTTP layer's `source.ip`, MCP session id, etc.). Defaults to
      * [[RequestContext.empty]] so existing callers compile unchanged. When wired with
      * `RequestContext.fromIOLocal`, every audit record's `context` map merges in whatever the transport
      * layer stamped onto the IOLocal for this request.
      */
    requestContext: RequestContext = RequestContext.empty
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
    // Locate is read-only directory access; we score for visibility but never gate (the engine isn't
    // consulted). Returning a filtered/empty result on Deny would leak existence-or-not signal to the
    // caller and isn't useful as a security primitive — the policy gate handles authorization for
    // discovery separately.
    val resource = s"pattern:$namePattern"
    for
      corr   <- IO(freshCorrelationId())
      now    <- IO.realTimeInstant
      reqCtx <- requestContext.current
      score  <- scoreOpt(by, Operation.Locate, None, now)
      ctx = preflightContext(score, None, reqCtx)
      list <- inner.locate(namePattern, by)
      _ <- sink.write(
        AuditRecord(now, by, Operation.Locate, resource, s"Hits=${list.size}", corr, ctx)
      )
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

  /** Threads a fresh correlation id, a wall-clock timestamp, and the preflight (score + decision) context
    * through the action and writes the resulting `AuditRecord`. Specialized to `Either[KmsError, A]`-typed
    * actions so it can synthesize a `Left` when the decision engine short-circuits the request.
    */
  private def instrument[A](
      by: Principal,
      op: Operation,
      keyId: Option[KeyId]
  )(action: => IO[Either[KmsError, A]])(
      record: (java.time.Instant, String, Map[String, String], Either[KmsError, A]) => AuditRecord
  ): IO[Either[KmsError, A]] =
    for
      corr     <- IO(freshCorrelationId())
      now0     <- IO.realTimeInstant
      reqCtx   <- requestContext.current
      score    <- scoreOpt(by, op, keyId, now0)
      decision <- decideOpt(score, by, op)
      ctx = preflightContext(score, decision, reqCtx)
      result <- shortCircuitOr(decision, action)
      now    <- IO.realTimeInstant
      _      <- sink.write(record(now, corr, ctx, result))
    yield result

  /** Run the inner action unless the decision short-circuits the request. */
  private def shortCircuitOr[A](
      decision: Option[Decision],
      action: => IO[Either[KmsError, A]]
  ): IO[Either[KmsError, A]] =
    decision match
      case Some(Decision.Deny(reason)) =>
        IO.pure(Left(KmsError(ErrorCode.PermissionDenied, s"risk: $reason")))
      case Some(Decision.StepUpRequired(reason)) =>
        IO.pure(Left(KmsError(ErrorCode.StepUpRequired, reason)))
      case _ => action

  /** Call the optional `RiskScorer` and return its score (or `None` if no scorer is configured). */
  private def scoreOpt(
      by: Principal,
      op: Operation,
      keyId: Option[KeyId],
      now: java.time.Instant
  ): IO[Option[RiskScore]] =
    scorer match
      case None    => IO.pure(None)
      case Some(s) => s.score(RiskScorer.Request(by, op, keyId, now)).map(Some(_))

  /** Call the optional `DecisionEngine` against the score (skipped when either is missing). */
  private def decideOpt(
      score: Option[RiskScore],
      by: Principal,
      op: Operation
  ): IO[Option[Decision]] =
    (score, engine) match
      case (Some(s), Some(e)) => e.decide(s, by, op).map(Some(_))
      case _                  => IO.pure(None)

  /** Build the `AuditRecord.context` fragment from the score, decision, and the per-request context bag
    * stamped by the transport layer (typically `source.ip`). Stamps:
    *
    *   - `risk.score` — present iff scorer was configured
    *   - `risk.factors` — present iff scorer was configured
    *   - `outcome.decision` — present iff engine was configured ("Allow" / "StepUp" / "Deny")
    *   - `outcome.decision.reason` — present iff engine was configured AND decision != Allow
    *   - any keys present on the request context (e.g. `source.ip`) — merged last so an explicit
    *     transport-supplied value overrides a same-key value from score/decision (unlikely but defines an
    *     unambiguous precedence).
    */
  private def preflightContext(
      score: Option[RiskScore],
      decision: Option[Decision],
      requestCtx: Map[String, String]
  ): Map[String, String] =
    val builder = Map.newBuilder[String, String]
    score.foreach { rs =>
      builder += ("risk.score"   -> rs.renderedScore)
      builder += ("risk.factors" -> rs.renderedFactors)
    }
    decision.foreach { d =>
      import Decision.label
      import Decision.reasonOrEmpty
      builder += ("outcome.decision"                                -> d.label)
      val reason                                = d.reasonOrEmpty
      if reason.nonEmpty then builder += ("outcome.decision.reason" -> reason)
    }
    builder ++= requestCtx
    builder.result()

  private def resourceForCreate(spec: KeySpec): String =
    s"name:${spec.name}/alg:${spec.algorithm}/size:${spec.sizeBits}"

  private def freshCorrelationId(): String = UUID.randomUUID().toString
