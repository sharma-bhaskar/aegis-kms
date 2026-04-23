package dev.aegiskms.iam

import dev.aegiskms.core.{Operation, Principal}

/** SPI for policy evaluation. The default implementation is an allowlist matcher over role bindings.
  * Alternate implementations could wrap OPA / Rego or a policy language hosted elsewhere.
  */
trait PolicyEngine[F[_]]:
  def permit(principal: Principal, op: Operation, resource: String): F[Decision]

enum Decision:
  case Allow
  case Deny(reason: String)
  case StepUpRequired(reason: String)
