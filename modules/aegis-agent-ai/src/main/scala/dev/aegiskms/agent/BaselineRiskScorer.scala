package dev.aegiskms.agent

import cats.effect.IO
import dev.aegiskms.core.*

import java.time.{Duration, ZoneOffset}
import scala.concurrent.duration.FiniteDuration

/** `RiskScorer` implementation that combines `BaselineDetector` signals with contextual signals from the
  * `Principal`. This is the AI-governance Pillar 2 surface — every request gets a number + reasoning before
  * the decision adapter (issue #16) consumes it.
  *
  * Two input sources:
  *
  *   1. **Baseline signals.** Read `BaselineDetector.snapshot()` to get the per-actor `ActorBaseline`, then
  *      check the current request against it for each of the five baselines the detector tracks (scope, rate,
  *      op-histogram, time-of-day, source-IP). A "fired" baseline contributes a factor with a fixed weight;
  *      the actual `BaselineDetector.observe` (which writes the new request *into* the baseline) happens
  *      separately when the audit row is built. 2. **Contextual signals.** Read the `Principal` shape: agents
  *      are riskier than humans; long-lived credentials are riskier than fresh ones; broad scopes are riskier
  *      than narrow ones; destructive operations are riskier than read-only ones.
  *
  * The weights in `Weights.Default` are tuned for the demo target — they produce risk scores between `0.0`
  * (cold-start human Get) and ~`0.95` (agent doing a rotate on a new key at 3 AM from a new IP). They're a
  * starting point, not a science: PR W4 will rebalance once we have real customer telemetry.
  */
final class BaselineRiskScorer(detector: BaselineDetector, weights: BaselineRiskScorer.Weights)
    extends RiskScorer[IO]:

  import BaselineRiskScorer.*

  def score(request: RiskScorer.Request): IO[RiskScore] =
    detector.snapshot.map { snap =>
      val baseline     = snap.getOrElse(request.principal.subject, BaselineDetector.ActorBaseline.empty)
      val baselineFs   = baselineFactors(request, baseline)
      val contextualFs = contextualFactors(request)
      RiskScore.fromFactors(baselineFs ++ contextualFs)
    }.handleError { t =>
      RiskScore(0.0, List(RiskFactor("ScorerError", 0.0, s"scorer error: ${t.getMessage}")))
    }

  // ── Baseline factors ──────────────────────────────────────────────────────

  private def baselineFactors(
      req: RiskScorer.Request,
      baseline: BaselineDetector.ActorBaseline
  ): List[RiskFactor] =
    val fs = List.newBuilder[RiskFactor]

    // Cold start: no baseline at all. Don't fire any baseline factors — contextual ones will still apply.
    if baseline.firstSeen.isEmpty then return fs.result()

    // ScopeBaseline: key not in the actor's seen set.
    val resource = req.keyId.fold("")(id => s"key:${id.value}")
    if resource.nonEmpty && baseline.keysSeen.nonEmpty && !baseline.keysSeen.contains(resource) then
      fs += RiskFactor(
        "ScopeBaseline",
        weights.scope,
        s"actor never touched $resource before (${baseline.keysSeen.size} prior keys)"
      )

    // OpHistogramBaseline: operation kind the actor has never performed.
    if baseline.opsSeen.nonEmpty && !baseline.opsSeen.contains(req.operation) then
      fs += RiskFactor(
        "OpHistogramBaseline",
        weights.opHistogram,
        s"actor never performed ${req.operation} before (${baseline.opsSeen.size} prior op kinds)"
      )

    // TimeOfDayBaseline: hour-of-day outside the seen set.
    val hour = req.at.atZone(ZoneOffset.UTC).getHour
    if baseline.hoursSeen.nonEmpty && !baseline.hoursSeen.contains(hour) then
      fs += RiskFactor(
        "TimeOfDayBaseline",
        weights.timeOfDay,
        s"UTC hour $hour outside the actor's pattern (${baseline.hoursSeen.toSeq.sorted.mkString(",")})"
      )

    // SourceIpBaseline: source IP not in the seen set. Reads the same context key the detector reads.
    req.context.get(BaselineDetector.SourceIpContextKey).foreach { ip =>
      if baseline.sourceIpsSeen.nonEmpty && !baseline.sourceIpsSeen.contains(ip) then
        fs += RiskFactor(
          "SourceIpBaseline",
          weights.sourceIp,
          s"new source IP $ip (${baseline.sourceIpsSeen.size} prior)"
        )
    }

    // RateSpike: scaled — the burst factor `recent / threshold` determines the weight (capped at the
    // configured max). A 3× burst gets the full weight; smaller bursts are proportional.
    val burstStart    = req.at.minus(Duration.ofSeconds(weights.rateBurstWindowSecs))
    val recentInBurst = baseline.recentRequests.count(t => !t.isBefore(burstStart))
    if recentInBurst >= weights.rateBurstThreshold then
      val factor       = recentInBurst.toDouble / weights.rateBurstThreshold
      val scaledWeight = math.min(weights.rateMax, weights.rateMax * (factor / 3.0))
      fs += RiskFactor(
        "RateSpike",
        scaledWeight,
        f"$recentInBurst requests in ${weights.rateBurstWindowSecs}s (factor=$factor%.2f)"
      )

    fs.result()

  // ── Contextual factors ────────────────────────────────────────────────────

  private def contextualFactors(req: RiskScorer.Request): List[RiskFactor] =
    val fs = List.newBuilder[RiskFactor]

    req.principal match
      case agent: Principal.Agent =>
        fs += RiskFactor(
          "AgentPrincipal",
          weights.agentKind,
          s"actor is an Agent on behalf of ${agent.operator.subject} (humans default lower)"
        )

        // Credential age — if the agent's JWT is past 80% of its TTL, weight up. Older credentials are
        // more likely to have leaked or been picked up by a compromised script.
        val ageSecs = math.max(0L, java.time.Duration.between(agent.issuedAt, req.at).getSeconds)
        val ttlSecs = agent.ttl match
          case fd: FiniteDuration => fd.toSeconds
          case _                  => 0L
        if ttlSecs > 0 && ageSecs.toDouble / ttlSecs.toDouble >= 0.8 then
          fs += RiskFactor(
            "CredentialAge",
            weights.credentialAge,
            f"credential is ${ageSecs}s of ${ttlSecs}s TTL (${ageSecs.toDouble / ttlSecs * 100}%.0f%%)"
          )

        // Broad scope — agents with allowedOps covering more than the threshold are flagged.
        if agent.allowedOps.size > weights.broadScopeOpThreshold then
          fs += RiskFactor(
            "BroadScope",
            weights.broadScope,
            s"agent has ${agent.allowedOps.size} allowed ops (threshold ${weights.broadScopeOpThreshold})"
          )

      case _ => () // Humans and Services: no agent-specific factors

    // Destructive operations carry an extra weight regardless of principal kind.
    if DestructiveOps.contains(req.operation) then
      fs += RiskFactor(
        "DestructiveOp",
        weights.destructiveOp,
        s"${req.operation} is destructive or irreversible"
      )

    fs.result()

object BaselineRiskScorer:

  /** Ops that move a key to a terminal or near-terminal state. A high score on these is the difference
    * between "alert" and "block" — see #16's decision adapter.
    */
  private val DestructiveOps: Set[Operation] =
    Set(Operation.Destroy, Operation.Compromise, Operation.Rotate, Operation.Revoke)

  /** Weights tuned for the demo target. All values are starting points; v0.2.1 / W4 rebalance them with real
    * telemetry. Documented per-factor so reviewers can see what's intentional vs accidental.
    */
  final case class Weights(
      // Baseline factor weights — match the BaselineDetector's severity model.
      scope: Double = 0.50,
      opHistogram: Double = 0.30,
      timeOfDay: Double = 0.20,
      sourceIp: Double = 0.30,
      rateMax: Double = 0.40,
      rateBurstThreshold: Int = 30,
      rateBurstWindowSecs: Long = 60L,

      // Contextual factor weights.
      agentKind: Double = 0.20,
      credentialAge: Double = 0.10,
      broadScope: Double = 0.10,
      broadScopeOpThreshold: Int = 5,
      destructiveOp: Double = 0.10
  )

  object Weights:
    val Default: Weights = Weights()

  def make(detector: BaselineDetector, weights: Weights = Weights.Default): BaselineRiskScorer =
    new BaselineRiskScorer(detector, weights)
