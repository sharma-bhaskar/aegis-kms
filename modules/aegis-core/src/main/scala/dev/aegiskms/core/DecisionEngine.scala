package dev.aegiskms.core

/** SPI: translate a `(RiskScore, Principal, Operation)` triple into a `Decision`.
  *
  * Implementations live outside `aegis-core` because they need configuration (thresholds, per-op overrides)
  * or external state (a future remote policy backend, an OPA bridge). The trait stays here so the audit
  * decorator can take an `Option[DecisionEngine[IO]]` constructor arg without pulling Pekko or any specific
  * backend into the library-safe tier.
  *
  * Contract:
  *   - Pure with respect to the request: no I/O, no mutation. Threshold values come from constructor
  *     configuration; the engine itself is stateless across calls.
  *   - Total — never throws. Decision engines that need to call external systems should wrap failures into a
  *     conservative `Deny(reason="engine error: ...")` rather than propagating the exception.
  *   - Cheap. The engine is invoked on every state-changing request. Anything expensive belongs in the
  *     `RiskScorer`, not here.
  *
  * The boolean policy gate (`AuthorizingKeyService`) remains the floor — see `Decision` for the additive-only
  * relationship between policy and risk.
  */
trait DecisionEngine[F[_]]:
  def decide(score: RiskScore, principal: Principal, operation: Operation): F[Decision]
