package dev.aegiskms.agent

import cats.effect.IO
import dev.aegiskms.core.*

/** Simple two-threshold decision engine.
  *
  *   - `score >= denyAt` → `Decision.Deny`
  *   - `score >= stepUpAt` → `Decision.StepUpRequired`
  *   - else → `Decision.Allow`
  *
  * Plus destructive-op overrides: for `Compromise` / `Destroy` / `Rotate` / `Revoke` the thresholds are
  * lowered by `destructiveOpOffset` (default 0.15). This means a moderate-risk request to destroy a key gets
  * stepped up where the same risk on a `Get` would have passed — losing data is far less reversible than
  * reading it.
  *
  * Default thresholds are tuned for the demo target:
  *
  *   - `denyAt = 0.85` — only a composite alert (multiple factors) trips an outright deny
  *   - `stepUpAt = 0.60` — a single high-weight factor (new scope, new source IP) trips step-up
  *
  * The decision rationale is bundled into the `reason` string of `StepUp` / `Deny`, drawing on the
  * `RiskScore.renderedFactors` for evidence. Example reason: `"score=0.71 threshold=0.60
  * factors=ScopeBaseline:0.5;AgentPrincipal:0.2"`. This string lands in the audit row
  * (`outcome.decision.reason`) and in the HTTP error payload, so operators can answer "why was this blocked?"
  * without re-running the scorer.
  */
final class ThresholdDecisionEngine(thresholds: ThresholdDecisionEngine.Thresholds)
    extends DecisionEngine[IO]:

  import ThresholdDecisionEngine.*

  def decide(score: RiskScore, principal: Principal, operation: Operation): IO[Decision] =
    IO.pure(decideSync(score, operation))

  private def decideSync(score: RiskScore, operation: Operation): Decision =
    val (denyAt, stepUpAt) = effectiveThresholds(operation)
    if score.value >= denyAt then
      Decision.Deny(formatReason("score", score, denyAt))
    else if score.value >= stepUpAt then
      Decision.StepUpRequired(formatReason("score", score, stepUpAt))
    else Decision.Allow

  private def effectiveThresholds(op: Operation): (Double, Double) =
    if DestructiveOps.contains(op) then
      // Clamp to [0.0, 1.0] in case operator config sets odd values.
      val deny   = math.max(0.0, thresholds.denyAt - thresholds.destructiveOpOffset)
      val stepUp = math.max(0.0, thresholds.stepUpAt - thresholds.destructiveOpOffset)
      (deny, stepUp)
    else (thresholds.denyAt, thresholds.stepUpAt)

  private def formatReason(label: String, score: RiskScore, threshold: Double): String =
    val factors = if score.factors.isEmpty then "(none)" else score.renderedFactors
    f"$label=${score.value}%.2f threshold=$threshold%.2f factors=$factors"

object ThresholdDecisionEngine:

  /** Ops where the cost of a wrongful allow is irreversible — see `BaselineRiskScorer.DestructiveOps` for the
    * matching list used in scoring. The two lists are kept in sync deliberately: a destructive op is both
    * *scored* higher (the scorer's `DestructiveOp` contextual factor) and *gated* harder (this engine's lower
    * thresholds).
    */
  private val DestructiveOps: Set[Operation] =
    Set(Operation.Destroy, Operation.Compromise, Operation.Rotate, Operation.Revoke)

  /** Tunable thresholds. Defaults are calibrated against `BaselineRiskScorer.Weights.Default`:
    *
    *   - A single firing baseline factor (e.g. ScopeBaseline at 0.5) → Allow.
    *   - Two factors (e.g. ScopeBaseline + AgentPrincipal = 0.7) → StepUp.
    *   - Three+ factors (e.g. the demo composite at ~0.85+) → Deny.
    *
    * Operator-tuned thresholds will land via HOCON in a later PR.
    */
  final case class Thresholds(
      denyAt: Double = 0.85,
      stepUpAt: Double = 0.60,
      destructiveOpOffset: Double = 0.15
  ):
    require(denyAt >= stepUpAt, s"denyAt ($denyAt) must be >= stepUpAt ($stepUpAt)")
    require(destructiveOpOffset >= 0.0, s"destructiveOpOffset must be >= 0 (was $destructiveOpOffset)")

  object Thresholds:
    val Default: Thresholds = Thresholds()

  def make(thresholds: Thresholds = Thresholds.Default): ThresholdDecisionEngine =
    new ThresholdDecisionEngine(thresholds)
