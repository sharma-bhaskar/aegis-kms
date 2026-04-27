package dev.aegiskms.agent

import dev.aegiskms.core.Principal

import java.time.Instant

/** Output of an anomaly detector: a structured "something is off" event that operators see in the CLI, the
  * UI, and webhooks.
  *
  * Distinct from `PolicyRecommendation`, which is the LLM-advisor's read-only suggestion based on the audit
  * log. `AgentRecommendation` is produced by streaming detectors in real time on the request path; it is the
  * vehicle that drives the auto-response actions in PR W3.
  *
  * One detector may emit multiple recommendations against the same actor over time. Each recommendation has
  * a stable `detector` name plus an event id so consumers can de-duplicate.
  */
final case class AgentRecommendation(
    eventId: String,
    at: Instant,
    actor: Principal,
    detector: String,
    severity: Severity,
    summary: String,
    details: Map[String, String],
    suggestedAction: SuggestedAction
)

/** Auto-response action a detector suggests. The actual execution is wired in PR W3 (`AutoResponder`). */
enum SuggestedAction:
  case None
  case Alert
  case StepUp
  case Revoke
  case Rotate
  case Freeze
