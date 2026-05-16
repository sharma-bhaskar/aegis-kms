package dev.aegiskms.agent

/** A single mapping from `(detector, severity)` to an `AutoResponseAction`.
  *
  * The auto-responder evaluates rules in order; the first match wins. Multiple rules per detector are fine —
  * finer-grained severities can pair with stronger actions (e.g. `Low → Alert`, `High → Revoke`).
  *
  * The `detector` field matches `AgentRecommendation.detector` exactly: `"ScopeBaseline"`, `"RateSpike"`,
  * `"OpHistogramBaseline"`, `"TimeOfDayBaseline"`, `"SourceIpBaseline"`. No wildcard matching in v0.2.0 — if
  * an operator wants "any detector at High severity → Revoke", they enumerate the five rules explicitly.
  * Wildcard rules are cheap to add later if real configurations show the need.
  */
final case class AutoResponseRule(
    detector: String,
    severity: Severity,
    action: AutoResponseAction
)

/** Concrete execution-level action the auto-responder can take. Deliberately a separate vocabulary from
  * `SuggestedAction` (the detector's *suggestion*): the responder owns what it actually *does*, while
  * detectors only opine.
  *
  *   - `Alert` — write an audit row noting the recommendation; no state change. The minimum auto- response —
  *     guarantees the event is captured in the audit timeline for operators.
  *   - `Revoke` — call `KeyService.revoke` on the target key extracted from
  *     `AgentRecommendation.details("resource")`. Moves Active → Deactivated. Reversible by re-activation if
  *     the operator deems the alert a false positive.
  *   - `Deactivate` — for v0.2.0 mapped to `Revoke` (KMIP's Deactivate→Revoke separation isn't wired into
  *     `KeyService` yet — see ROADMAP §v0.3.0).
  *   - `Freeze` — temporarily block the agent's credential from issuing further ops. Full enforcement
  *     requires #24 (Redis-backed JTI blacklist); for v0.2.0 the action records an audit row + log line
  *     documenting the freeze intent, so operators see the call.
  */
enum AutoResponseAction:
  case Alert
  case Revoke
  case Deactivate
  case Freeze
