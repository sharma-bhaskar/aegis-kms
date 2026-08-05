package dev.aegiskms.agent

import cats.effect.{IO, Ref}
import dev.aegiskms.audit.{AuditRecord, AuditSink}
import dev.aegiskms.core.*
import org.slf4j.LoggerFactory

import java.time.Instant
import java.util.UUID
import scala.concurrent.duration.*

/** The W3 auto-responder: turns `AgentRecommendation` events into KMS actions.
  *
  * Slotted into the existing detector → recommendation pipeline as a decorating `RecommendationSink`: every
  * recommendation is first persisted to the inner sink (so operators still see the full alert history
  * regardless of what the responder does), then matched against the configured rule list, then (if a rule
  * fires and the cooldown allows) the action is executed.
  *
  * **Action execution path bypasses `AuditingKeyService` on purpose.** The responder calls a "below the audit
  * decorator" `KeyService` and writes its own action audit row directly. Routing through the audited service
  * would feed every auto-response back into the detector → recommendation pipeline, causing recursion (revoke
  * → audit row → detector fires → more revokes). Each action is recorded as a separate audit event with
  * `actor = Principal.Service("aegis-system", TenantId("system"))` and the outcome string
  * `"AnomalyAlert(detector=…, severity=…, rec=<id>, action=…)"` — matching the spec in issue #17. Operators
  * can filter on this actor to see the full auto-response timeline.
  *
  * **Cooldown.** Per-`(actor.subject, action)` cooldown (default 60 s) suppresses repeat fires. Without this,
  * a sustained rate-spike would issue dozens of revokes-per-second for the same key. The cooldown is
  * in-memory only — restart resets it, which is fine for v0.2.0 (the operator-visible behaviour is "we acted
  * once per minute per actor" — restart just means "the clock resets"). Persistent cooldown lands with the
  * SIEM webhook PR (#21) which needs durable de-duplication anyway.
  *
  * **Failure handling.** Action failures (revoke errors, missing target keys, malformed details) are logged +
  * audited but never propagated back to the caller — the responder's `publish` is total. The recommendation
  * has already been persisted by the inner sink, so the operator still sees the event; the audit row
  * documents WHY the action couldn't proceed.
  */
final class AutoResponder private (
    rules: List[AutoResponseRule],
    inner: RecommendationSink,
    keyService: KeyService[IO],
    auditSink: AuditSink[IO],
    cooldown: FiniteDuration,
    recentlyFired: Ref[IO, Map[(String, AutoResponseAction), Instant]],
    now: IO[Instant],
    /** Present only when the operator has explicitly enabled fleet-wide auto-revocation. `None` makes
      * `KillAgentFleet` an audited no-op — see [[AutoResponseAction.KillAgentFleet]].
      */
    killSwitch: Option[AgentKillSwitch]
) extends RecommendationSink:

  import AutoResponder.*

  private val logger = LoggerFactory.getLogger(classOf[AutoResponder])

  def publish(rec: AgentRecommendation): IO[Unit] =
    inner.publish(rec) *> maybeApplyRule(rec)

  private def maybeApplyRule(rec: AgentRecommendation): IO[Unit] =
    matchRule(rec) match
      case None => IO.unit // no rule for this detector + severity
      case Some(rule) =>
        cooldownGate(rec.actor.subject, rule.action).flatMap {
          case false => IO.unit
          case true  => executeRule(rule, rec)
        }

  private def matchRule(rec: AgentRecommendation): Option[AutoResponseRule] =
    rules.find(r => r.detector == rec.detector && r.severity == rec.severity)

  /** Returns `true` if this `(subject, action)` pair is OUTSIDE its cooldown window (i.e. we should fire). */
  private def cooldownGate(subject: String, action: AutoResponseAction): IO[Boolean] =
    now.flatMap { t =>
      recentlyFired.modify { map =>
        val key = (subject, action)
        map.get(key) match
          case Some(prev) if java.time.Duration.between(prev, t).toMillis < cooldown.toMillis =>
            (map, false)
          case _ => (map + (key -> t), true)
      }
    }

  private def executeRule(rule: AutoResponseRule, rec: AgentRecommendation): IO[Unit] =
    val attempt: IO[Either[String, String]] = rule.action match
      case AutoResponseAction.Alert          => IO.pure(Right("alert recorded"))
      case AutoResponseAction.Revoke         => doRevoke(rec)
      case AutoResponseAction.Deactivate     => doRevoke(rec) // mapped — see AutoResponseAction docs
      case AutoResponseAction.Freeze         => doFreeze(rec)
      case AutoResponseAction.KillAgentFleet => doKillFleet(rec)

    for
      outcome <- attempt
      _       <- writeActionAudit(rule, rec, outcome)
      _       <- IO(logResult(rule, rec, outcome))
    yield ()

  private def doRevoke(rec: AgentRecommendation): IO[Either[String, String]] =
    extractKeyId(rec) match
      case Left(why) => IO.pure(Left(why))
      case Right(kid) =>
        keyService.revoke(kid, SystemPrincipal).map {
          case Right(_) => Right(s"revoked key=${kid.value}")
          case Left(e)  => Left(s"revoke failed code=${e.code} msg=${e.message}")
        }

  /** Revoke every live agent under the offending agent's parent operator.
    *
    * Only meaningful for an `Agent` actor — that is the only principal kind with a parent to sweep. A
    * recommendation about a human or service has no fleet, and guessing one would be the worst kind of wrong:
    * revoking agents belonging to whoever happens to share a subject string.
    */
  private def doKillFleet(rec: AgentRecommendation): IO[Either[String, String]] =
    killSwitch match
      case None =>
        IO.pure(Left(
          "kill-fleet not enabled (set aegis.auto-response.kill-fleet.enabled=true and wire a kill-switch)"
        ))
      case Some(ks) =>
        rec.actor match
          case a: Principal.Agent =>
            ks.revokeAll(SystemPrincipal, KillSwitchRequest(parent = a.operator.subject)).map {
              case Right(r) =>
                Right(s"kill-switch swept parent=${r.parent} killed=${r.killed.size}")
              case Left(e) => Left(s"kill-switch failed code=${e.code} msg=${e.message}")
            }
          case other =>
            IO.pure(Left(
              s"kill-fleet only applies to agent actors; actor '${other.subject}' has no parent fleet"
            ))

  private def doFreeze(rec: AgentRecommendation): IO[Either[String, String]] =
    // v0.2.0: no enforcement. Real freeze requires the JTI blacklist (#24).
    IO.pure(
      Right(s"freeze noted for actor=${rec.actor.subject} (enforcement deferred to #24)")
    )

  private def extractKeyId(rec: AgentRecommendation): Either[String, KeyId] =
    rec.details.get("resource") match
      // Explicit `key:<id>` prefix (e.g. hand-built recommendations).
      case Some(r) if r.startsWith("key:") =>
        KeyId.fromString(r.stripPrefix("key:")).left.map(msg => s"invalid keyId in details: $msg")
      // Create / Locate resources are name- or pattern-shaped — there's no single key to revoke.
      case Some(r) if r.startsWith("name:") || r.startsWith("pattern:") =>
        Left(s"recommendation resource is not a key reference: '$r'")
      // Op-on-key audit records carry the bare KeyId as the resource — the common case for the
      // detector pipeline (Sign / Get / Encrypt / … against an existing key).
      case Some(r) =>
        KeyId.fromString(r).left.map(_ => s"recommendation resource is not a key reference: '$r'")
      case None =>
        Left("recommendation has no 'resource' detail to target")

  private def writeActionAudit(
      rule: AutoResponseRule,
      rec: AgentRecommendation,
      outcome: Either[String, String]
  ): IO[Unit] =
    now.flatMap { t =>
      val outcomeStr = outcome match
        case Right(msg) => s"Success $msg"
        case Left(msg)  => s"Failed $msg"
      val record = AuditRecord(
        at = t,
        principal = SystemPrincipal,
        operation = operationForAction(rule.action),
        resource = rec.details.getOrElse("resource", s"actor:${rec.actor.subject}"),
        outcome =
          s"AnomalyAlert(detector=${rec.detector}, severity=${rec.severity}, rec=${rec.eventId}, action=${rule.action}) $outcomeStr",
        correlationId = UUID.randomUUID().toString,
        context = Map(
          "auto.response.rule"        -> s"${rule.detector}:${rule.severity}:${rule.action}",
          "auto.response.actor"       -> rec.actor.subject,
          "auto.response.recId"       -> rec.eventId,
          "auto.response.detectorMsg" -> rec.summary
        )
      )
      auditSink.write(record)
    }

  private def operationForAction(a: AutoResponseAction): Operation = a match
    case AutoResponseAction.Alert      => Operation.AddAttribute // closest "informational" op; see note below
    case AutoResponseAction.Revoke     => Operation.Revoke
    case AutoResponseAction.Deactivate => Operation.Revoke       // mapped, see action docs
    case AutoResponseAction.Freeze     => Operation.Revoke
    case AutoResponseAction.KillAgentFleet => Operation.Revoke

  private def logResult(
      rule: AutoResponseRule,
      rec: AgentRecommendation,
      outcome: Either[String, String]
  ): Unit =
    outcome match
      case Right(msg) =>
        logger.warn(
          s"auto-response action=${rule.action} fired for ${rec.detector}/${rec.severity} actor=${rec.actor.subject}: $msg"
        )
      case Left(msg) =>
        logger.error(
          s"auto-response action=${rule.action} FAILED for ${rec.detector}/${rec.severity} actor=${rec.actor.subject}: $msg"
        )

object AutoResponder:

  /** The system actor under whose identity auto-response actions are taken. Identifying as a `Service` (not a
    * `Human`) lets the policy gate carve a single per-`subject` exception for it; identifying as
    * `"aegis-system"` (a deliberately namespaced name no operator would pick) keeps it greppable in audit log
    * searches.
    */
  val SystemPrincipal: Principal =
    Principal.Service(subject = "aegis-system", tenant = TenantId("system"))

  /** Sensible out-of-the-box defaults that ship the wedge demo:
    *
    *   - Any `High` severity from any detector → `Revoke`.
    *   - Any `Medium` severity → `Alert` (informational; lets operators see the trend without acting).
    *   - `Low` severity is intentionally absent — too much noise; operators opt in by adding their own rule.
    *
    * The list MUST include every detector name `BaselineDetector` can emit — including the `HoneyKey` trip
    * wire (#26), whose whole point is to fire High → Revoke on the first agent touch. Omitting it silently
    * no-ops the canary.
    *
    * Operator-tuned rules will land via HOCON in a later PR; for v0.2.0 these defaults are baked into
    * `Server.boot`.
    */
  val DefaultRules: List[AutoResponseRule] =
    val detectors =
      List(
        "ScopeBaseline",
        "RateSpike",
        "OpHistogramBaseline",
        "TimeOfDayBaseline",
        "SourceIpBaseline",
        "HoneyKey"
      )
    detectors.flatMap(d =>
      List(
        AutoResponseRule(d, Severity.High, AutoResponseAction.Revoke),
        AutoResponseRule(d, Severity.Medium, AutoResponseAction.Alert)
      )
    )

  def make(
      rules: List[AutoResponseRule],
      inner: RecommendationSink,
      keyService: KeyService[IO],
      auditSink: AuditSink[IO],
      cooldown: FiniteDuration = 60.seconds,
      now: IO[Instant] = IO.realTimeInstant,
      /** Defaults to `None`: fleet-wide auto-revocation must be switched on deliberately, never inherited by
        * upgrading. See [[AutoResponseAction.KillAgentFleet]].
        */
      killSwitch: Option[AgentKillSwitch] = None
  ): IO[AutoResponder] =
    Ref.of[IO, Map[(String, AutoResponseAction), Instant]](Map.empty).map { ref =>
      new AutoResponder(rules, inner, keyService, auditSink, cooldown, ref, now, killSwitch)
    }
