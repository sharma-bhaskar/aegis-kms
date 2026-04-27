package dev.aegiskms.agent

import cats.effect.{IO, Ref}
import dev.aegiskms.audit.AuditRecord
import dev.aegiskms.core.{Operation, Principal}

import java.time.{Duration, Instant}
import java.util.UUID

/** Sliding-window baseline detector — the W1 MVP that powers the "Claude goes rogue" demo in the README.
  *
  * Maintains, per actor subject, a small in-memory baseline:
  *   - the set of keys the actor has ever touched (within the retention window),
  *   - the histogram of ops the actor has ever performed,
  *   - the timestamps of the last N requests, used for rate-spike detection.
  *
  * Two detector heuristics:
  *   - `ScopeBaseline`: the actor touched a key not in its baseline. For agents this is severity High
  *     (suggested action `Revoke`); for humans it's severity Low (suggested action `Alert`).
  *   - `RateSpike`: the actor issued more than `rateBurstThreshold` requests in `rateBurstWindow`. Severity
  *     scales linearly with the multiplier above the burst threshold.
  *
  * The detector is intentionally tiny: this is the demo bar, not the production scorer. Risk-scored access
  * decisions and the LLM advisor are PRs W2 and W4.
  */
final class BaselineDetector private (
    state: Ref[IO, Map[String, BaselineDetector.ActorBaseline]],
    config: BaselineDetector.Config
):

  import BaselineDetector.*

  /** Observe a single audit record and return any recommendations it produced. */
  def observe(rec: AuditRecord): IO[List[AgentRecommendation]] =
    state.modify { current =>
      val existing = current.getOrElse(rec.principal.subject, ActorBaseline.empty)
      val resource = keyResource(rec)
      val recs     = mutable(rec, existing, config, resource)
      val updated  = existing.update(rec, resource, config.rateRetention)
      (current + (rec.principal.subject -> updated), recs)
    }

  /** Snapshot of all baselines — used by tests and by `aegis advisor explain`. */
  def snapshot: IO[Map[String, ActorBaseline]] = state.get

object BaselineDetector:

  final case class Config(
      rateRetention: Duration,
      rateBurstWindow: Duration,
      rateBurstThreshold: Int
  )

  object Config:
    val Demo: Config = Config(
      rateRetention = Duration.ofMinutes(5),
      rateBurstWindow = Duration.ofSeconds(60),
      rateBurstThreshold = 30
    )

  final case class ActorBaseline(
      keysSeen: Set[String],
      opsSeen: Map[Operation, Int],
      recentRequests: Vector[Instant],
      firstSeen: Option[Instant]
  ):
    def update(rec: AuditRecord, resource: String, retention: Duration): ActorBaseline =
      val cutoff = rec.at.minus(retention)
      val pruned = recentRequests.dropWhile(_.isBefore(cutoff))
      val newOps = opsSeen.updatedWith(rec.operation)(o => Some(o.getOrElse(0) + 1))
      ActorBaseline(
        keysSeen = keysSeen + resource,
        opsSeen = newOps,
        recentRequests = pruned :+ rec.at,
        firstSeen = firstSeen.orElse(Some(rec.at))
      )

  object ActorBaseline:
    val empty: ActorBaseline = ActorBaseline(Set.empty, Map.empty, Vector.empty, None)

  def make(config: Config = Config.Demo): IO[BaselineDetector] =
    Ref.of[IO, Map[String, ActorBaseline]](Map.empty).map(new BaselineDetector(_, config))

  // ── Detector logic ────────────────────────────────────────────────────────

  private def mutable(
      rec: AuditRecord,
      existing: ActorBaseline,
      config: Config,
      resource: String
  ): List[AgentRecommendation] =
    val recs = List.newBuilder[AgentRecommendation]

    // 1. ScopeBaseline — actor touched a key it has never touched before.
    if existing.keysSeen.nonEmpty && !existing.keysSeen.contains(resource) then
      val severity = rec.principal match
        case _: Principal.Agent => Severity.High
        case _                  => Severity.Low
      val action = rec.principal match
        case _: Principal.Agent => SuggestedAction.Revoke
        case _                  => SuggestedAction.Alert
      recs += AgentRecommendation(
        eventId = freshId(),
        at = rec.at,
        actor = rec.principal,
        detector = "ScopeBaseline",
        severity = severity,
        summary = s"Actor touched a key outside its established baseline (${resource})",
        details = Map(
          "resource"      -> resource,
          "keysSeenCount" -> existing.keysSeen.size.toString,
          "outcome"       -> rec.outcome,
          "correlationId" -> rec.correlationId
        ),
        suggestedAction = action
      )

    // 2. RateSpike — too many requests in the burst window.
    val burstStart    = rec.at.minus(config.rateBurstWindow)
    val recentInBurst = existing.recentRequests.count(t => !t.isBefore(burstStart))
    if recentInBurst >= config.rateBurstThreshold then
      val factor = recentInBurst.toDouble / config.rateBurstThreshold
      val severity =
        if factor >= 3.0 then Severity.High
        else if factor >= 2.0 then Severity.Medium
        else Severity.Low
      val action =
        if severity == Severity.High then SuggestedAction.Revoke
        else SuggestedAction.Alert
      recs += AgentRecommendation(
        eventId = freshId(),
        at = rec.at,
        actor = rec.principal,
        detector = "RateSpike",
        severity = severity,
        summary =
          s"$recentInBurst requests in ${config.rateBurstWindow.getSeconds}s (threshold=${config.rateBurstThreshold})",
        details = Map(
          "burstCount"      -> recentInBurst.toString,
          "burstWindowSecs" -> config.rateBurstWindow.getSeconds.toString,
          "factor"          -> f"$factor%.2f",
          "correlationId"   -> rec.correlationId
        ),
        suggestedAction = action
      )

    recs.result()

  private def keyResource(rec: AuditRecord): String =
    // Audit records carry resource as `key:<id>` for op-on-key, or `name:<n>/...` for create.
    // Normalize to the keyId where possible.
    if rec.resource.startsWith("name:") then rec.resource
    else rec.resource

  private def freshId(): String = UUID.randomUUID().toString
