package dev.aegiskms.iam

import dev.aegiskms.core.{Decision, Operation, Principal}

/** SPI for policy evaluation. The default implementation is an allowlist matcher over role bindings.
  * Alternate implementations could wrap OPA / Rego or a policy language hosted elsewhere.
  *
  * Returns the shared `dev.aegiskms.core.Decision` enum — the same type the risk decision engine
  * (`DecisionEngine` in `aegis-core`) emits. This is deliberate: both gating engines speak the same `Allow /
  * Deny / StepUpRequired` vocabulary so downstream consumers (`AuthorizingKeyService` here,
  * `AuditingKeyService` over in `aegis-audit`) don't need two separate code paths.
  */
trait PolicyEngine[F[_]]:
  def permit(principal: Principal, op: Operation, resource: String): F[Decision]
