package dev.aegiskms.core

/** Outcome of evaluating a request against a gating engine (policy floor and/or risk overlay).
  *
  * Three possible verdicts:
  *
  *   - `Allow` — request proceeds normally; the inner `KeyService` is invoked.
  *   - `StepUpRequired` — the caller's credential is insufficient for the risk level of THIS request; the
  *     HTTP layer translates this to `401 Unauthorized` so the client can re-present with a stronger
  *     credential (MFA-stepped, freshly-minted, etc.). The original request is NOT executed.
  *   - `Deny` — the request is refused outright. The inner `KeyService` is NOT invoked. HTTP returns `403`.
  *
  * The `reason` field on `StepUpRequired` / `Deny` is recorded in the audit row's `outcome.decision.reason`
  * context key and surfaced in the HTTP error payload, so operators can answer "why was this blocked?" from
  * the audit log alone.
  *
  * **Two producers, same type.** Both `PolicyEngine` (in `aegis-iam`, the boolean policy floor) and
  * `DecisionEngine` (in `aegis-core` SPI, the risk overlay implemented by `ThresholdDecisionEngine` in
  * `aegis-agent-ai`) emit `Decision`. The policy gate runs first as the floor; the risk gate is additive on
  * top — risk can further restrict an action policy permits, but cannot widen one policy forbids.
  */
enum Decision:
  case Allow
  case Deny(reason: String)
  case StepUpRequired(reason: String)

object Decision:
  /** Wire-stable label used in audit context (`outcome.decision`) and metrics. */
  extension (d: Decision)
    def label: String = d match
      case Allow             => "Allow"
      case StepUpRequired(_) => "StepUp"
      case Deny(_)           => "Deny"

    /** The `reason` string, or `""` for `Allow`. Convenience for context-map stamping. */
    def reasonOrEmpty: String = d match
      case Allow             => ""
      case StepUpRequired(r) => r
      case Deny(r)           => r
