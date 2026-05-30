package dev.aegiskms.agent

import cats.effect.{IO, Ref}
import dev.aegiskms.audit.AuditRecord
import dev.aegiskms.core.{KeyId, Operation, Principal}

import java.time.{Duration, Instant, ZoneOffset}
import java.util.UUID

/** Sliding-window baseline detector — the W1 MVP that powers the "Claude goes rogue" demo in the README.
  *
  * Maintains, per actor subject, a small in-memory baseline:
  *   - the set of keys the actor has ever touched (within the retention window),
  *   - the histogram of ops the actor has ever performed,
  *   - the set of UTC hours-of-day the actor has been active in,
  *   - the set of source IPs the actor has been seen from,
  *   - the timestamps of the last N requests, used for rate-spike detection.
  *
  * Five detector heuristics:
  *   - `ScopeBaseline`: the actor touched a key not in its baseline. For agents this is severity High
  *     (suggested action `Revoke`); for humans it's severity Low (suggested action `Alert`).
  *   - `RateSpike`: the actor issued more than `rateBurstThreshold` requests in `rateBurstWindow`. Severity
  *     scales linearly with the multiplier above the burst threshold.
  *   - `OpHistogramBaseline`: the actor performed an `Operation` it has never performed before.
  *   - `TimeOfDayBaseline`: the actor was active in a UTC hour-of-day they have never been active in.
  *   - `SourceIpBaseline`: the actor's request came from an IP not in their seen set. Reads
  *     `record.context("source.ip")`, which the HTTP layer populates via `RequestContext` (#78).
  *   - `HoneyKey` (#26): an **agent** touched a `KeyId` the operator marked as a canary via
  *     `aegis.security.honey-keys`. Fires unconditionally at `Severity.High` — no cold-start guard.
  *     AutoResponder.DefaultRules turn High → Revoke, killing both the key and the agent's JWT via the wired
  *     RevocationList.
  *
  * Cold-start: every detector requires the actor to have at least one prior observation in the relevant
  * dimension before it can fire. The first time `claude-session-7a3` shows up we record but don't alert; the
  * *second* observation is what produces a recommendation if it deviates.
  *
  * The detector is intentionally tiny: this is the demo bar, not the production scorer. Risk-scored access
  * decisions and the LLM advisor are PRs W2 and W4.
  */
final class BaselineDetector private (
    state: Ref[IO, Map[String, BaselineDetector.ActorBaseline]],
    config: BaselineDetector.Config,
    honeyKeys: HoneyKeyRegistry
):

  import BaselineDetector.*

  /** Observe a single audit record and return any recommendations it produced. */
  def observe(rec: AuditRecord): IO[List[AgentRecommendation]] =
    state.modify { current =>
      val existing = current.getOrElse(rec.principal.subject, ActorBaseline.empty)
      val resource = keyResource(rec)
      val recs     = mutable(rec, existing, config, resource, honeyKeys)
      val updated  = existing.update(rec, resource, config.rateRetention)
      (current + (rec.principal.subject -> updated), recs)
    }

  /** Snapshot of all baselines — used by tests and by `aegis advisor explain`. */
  def snapshot: IO[Map[String, ActorBaseline]] = state.get

object BaselineDetector:

  /** Well-known key the SourceIp detector reads from `AuditRecord.context`. The HTTP layer populates it via
    * `RequestContext.fromIOLocal` wired through `AuditingKeyService` (#78). Tests can also synthesize records
    * with this key directly.
    */
  val SourceIpContextKey: String = "source.ip"

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

  /** Per-actor baseline. `hoursSeen` are UTC hours-of-day (`0`–`23`); we deliberately don't try to be
    * timezone-aware in v0.1.1 — this is the *demo* detector. `sourceIpsSeen` is populated from
    * `AuditRecord.context("source.ip")`, which the HTTP layer fills in (#78).
    */
  final case class ActorBaseline(
      keysSeen: Set[String],
      opsSeen: Map[Operation, Int],
      hoursSeen: Set[Int],
      sourceIpsSeen: Set[String],
      recentRequests: Vector[Instant],
      firstSeen: Option[Instant]
  ):
    def update(rec: AuditRecord, resource: String, retention: Duration): ActorBaseline =
      val cutoff  = rec.at.minus(retention)
      val pruned  = recentRequests.dropWhile(_.isBefore(cutoff))
      val newOps  = opsSeen.updatedWith(rec.operation)(o => Some(o.getOrElse(0) + 1))
      val newHour = rec.at.atZone(ZoneOffset.UTC).getHour
      val maybeIp = rec.context.get(SourceIpContextKey)
      ActorBaseline(
        keysSeen = keysSeen + resource,
        opsSeen = newOps,
        hoursSeen = hoursSeen + newHour,
        sourceIpsSeen = maybeIp.fold(sourceIpsSeen)(sourceIpsSeen + _),
        recentRequests = pruned :+ rec.at,
        firstSeen = firstSeen.orElse(Some(rec.at))
      )

  object ActorBaseline:
    val empty: ActorBaseline =
      ActorBaseline(Set.empty, Map.empty, Set.empty, Set.empty, Vector.empty, None)

  def make(
      config: Config = Config.Demo,
      honeyKeys: HoneyKeyRegistry = HoneyKeyRegistry.empty
  ): IO[BaselineDetector] =
    Ref.of[IO, Map[String, ActorBaseline]](Map.empty)
      .map(new BaselineDetector(_, config, honeyKeys))

  // ── Detector logic ────────────────────────────────────────────────────────

  private def mutable(
      rec: AuditRecord,
      existing: ActorBaseline,
      config: Config,
      resource: String,
      honeyKeys: HoneyKeyRegistry
  ): List[AgentRecommendation] =
    val recs = List.newBuilder[AgentRecommendation]

    // 1. ScopeBaseline — actor touched a key it has never touched before.
    if existing.keysSeen.nonEmpty && !existing.keysSeen.contains(resource) then
      recs += AgentRecommendation(
        eventId = freshId(),
        at = rec.at,
        actor = rec.principal,
        detector = "ScopeBaseline",
        severity = severityForActor(rec.principal),
        summary = s"Actor touched a key outside its established baseline (${resource})",
        details = Map(
          "resource"      -> resource,
          "keysSeenCount" -> existing.keysSeen.size.toString,
          "outcome"       -> rec.outcome,
          "correlationId" -> rec.correlationId
        ),
        suggestedAction = actionForActor(rec.principal)
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

    // 3. OpHistogramBaseline — actor performed an Operation it has never used before.
    //    Cold-start guard: we need at least one prior op (`opsSeen.nonEmpty`) before the *novelty* of
    //    a new op is meaningful. Without this guard the detector would fire on every actor's first call.
    if existing.opsSeen.nonEmpty && !existing.opsSeen.contains(rec.operation) then
      recs += AgentRecommendation(
        eventId = freshId(),
        at = rec.at,
        actor = rec.principal,
        detector = "OpHistogramBaseline",
        severity = severityForActor(rec.principal),
        summary =
          s"Actor performed ${rec.operation} for the first time (prior ops: ${existing.opsSeen.keys.toSeq.sortBy(_.toString).mkString(", ")})",
        details = Map(
          "newOperation"  -> rec.operation.toString,
          "priorOpKinds"  -> existing.opsSeen.size.toString,
          "outcome"       -> rec.outcome,
          "correlationId" -> rec.correlationId
        ),
        suggestedAction = actionForActor(rec.principal)
      )

    // 4. TimeOfDayBaseline — actor active in a UTC hour-of-day they've never been active in.
    val hour = rec.at.atZone(ZoneOffset.UTC).getHour
    if existing.hoursSeen.nonEmpty && !existing.hoursSeen.contains(hour) then
      recs += AgentRecommendation(
        eventId = freshId(),
        at = rec.at,
        actor = rec.principal,
        detector = "TimeOfDayBaseline",
        // Off-hours is suspicious for any principal, but we keep agents at High because they should
        // never be the ones widening their schedule on their own.
        severity = severityForActor(rec.principal),
        summary =
          s"Actor active at UTC hour=$hour, outside the established baseline (${existing.hoursSeen.toSeq.sorted.mkString(",")})",
        details = Map(
          "newHourUtc"    -> hour.toString,
          "hoursSeen"     -> existing.hoursSeen.toSeq.sorted.mkString(","),
          "correlationId" -> rec.correlationId
        ),
        suggestedAction = actionForActor(rec.principal)
      )

    // 5. SourceIpBaseline — request from an IP not in the actor's seen set. Reads
    //    `record.context("source.ip")`, populated by the HTTP layer's `RequestContext` (#78). We only
    //    fire when the actor has at least one prior IP — so the cold-start case (no IP history at
    //    all) doesn't alert.
    rec.context.get(SourceIpContextKey).foreach { ip =>
      if existing.sourceIpsSeen.nonEmpty && !existing.sourceIpsSeen.contains(ip) then
        recs += AgentRecommendation(
          eventId = freshId(),
          at = rec.at,
          actor = rec.principal,
          detector = "SourceIpBaseline",
          severity = severityForActor(rec.principal),
          summary = s"Actor request from new source IP $ip (prior IPs: ${existing.sourceIpsSeen.size})",
          details = Map(
            "sourceIp"      -> ip,
            "priorIpCount"  -> existing.sourceIpsSeen.size.toString,
            "correlationId" -> rec.correlationId
          ),
          suggestedAction = actionForActor(rec.principal)
        )
    }

    // 6. HoneyKey (#26) — agent touched a key the operator has marked as a canary. Fires at
    //    Severity.High unconditionally regardless of the agent's prior baseline; the entire point
    //    of a honey key is to short-circuit the "give the actor benefit of the doubt" path. The
    //    AutoResponder.DefaultRules turn High → Revoke, which kills both the key and the agent's
    //    JWT via the wired RevocationList. NO cold-start guard (unlike the other detectors) — the
    //    first touch is the trip wire by design.
    //
    //    Humans touching a honey key intentionally is plausible (someone validating the canary is
    //    still active), so we restrict the detector to agent principals only. A human touching a
    //    honey key may still warrant an audit-log investigation, but we don't auto-revoke.
    rec.principal match
      case _: Principal.Agent =>
        keyIdFromResource(rec.resource).foreach { keyId =>
          if honeyKeys.isHoney(keyId) then
            recs += AgentRecommendation(
              eventId = freshId(),
              at = rec.at,
              actor = rec.principal,
              detector = "HoneyKey",
              severity = Severity.High,
              summary =
                s"Agent ${rec.principal.subject} touched honey key ${keyId.value} via ${rec.operation} — auto-revoke fired",
              details = Map(
                "honeyKeyId"    -> keyId.value,
                "operation"     -> rec.operation.toString,
                "outcome"       -> rec.outcome,
                "resource"      -> resource,
                "correlationId" -> rec.correlationId
              ),
              suggestedAction = SuggestedAction.Revoke
            )
        }
      case _ => ()

    recs.result()

  private def severityForActor(p: Principal): Severity = p match
    case _: Principal.Agent => Severity.High
    case _                  => Severity.Low

  private def actionForActor(p: Principal): SuggestedAction = p match
    case _: Principal.Agent => SuggestedAction.Revoke
    case _                  => SuggestedAction.Alert

  private def keyResource(rec: AuditRecord): String =
    // Audit records carry resource as `key:<id>` for op-on-key, or `name:<n>/...` for create.
    // Normalize to the keyId where possible.
    if rec.resource.startsWith("name:") then rec.resource
    else rec.resource

  /** Parse the `KeyId` out of an audit `resource` string. Audit records produced by
    * `AuditingKeyService.instrument(...)` set `resource = id.value` for ops on existing keys (Sign, Get,
    * Activate, Revoke, ...). The `Create` op uses `name:.../alg:.../size:...` shape (no `KeyId` yet) and
    * `Locate` uses `pattern:...`; both return `None` here, which means honey keys aren't tripped by Create /
    * Locate — by design, since you can't touch a honey key you haven't seen yet.
    */
  private def keyIdFromResource(resource: String): Option[KeyId] =
    if resource.startsWith("name:") || resource.startsWith("pattern:") then None
    else KeyId.fromString(resource).toOption

  private def freshId(): String = UUID.randomUUID().toString
