package dev.aegiskms.app

import cats.effect.IO
import dev.aegiskms.core.{Operation, Principal}
import dev.aegiskms.iam.{Decision, PolicyEngine}

/** A permissive `PolicyEngine` for dev-mode boots.
  *
  * The default `HttpRoutes` builds `Principal.Human(headerVal.getOrElse("anonymous"), Set.empty)` — empty
  * groups, arbitrary subject — which makes a role-based engine useless without an OIDC layer. This engine
  * grants every Human the full op set and runs the agent recursion identically to
  * [[dev.aegiskms.iam.RoleBasedPolicyEngine]]: an agent is allowed iff it asked for an op in its own
  * `allowedOps` AND its parent (recursively) is allowed.
  *
  * That last property is the load-bearing one: even with permissive humans, an agent whose own scope does not
  * include the op is still denied. So the README's "Claude goes rogue" demo still produces a
  * `PermissionDenied` when Claude tries to use an op outside its issued scope.
  *
  * NEVER use this in production. Production should use `RoleBasedPolicyEngine` with subject + role bindings
  * derived from the OIDC token claims.
  */
final class DevPolicyEngine extends PolicyEngine[IO]:

  def permit(principal: Principal, op: Operation, resource: String): IO[Decision] =
    IO.pure(decide(principal, op))

  private def decide(principal: Principal, op: Operation): Decision =
    principal match
      case Principal.Human(_, _)   => Decision.Allow
      case Principal.Service(_, _) => Decision.Allow
      case Principal.Agent(subject, parent, _, _, _, allowedOps, _) =>
        if !allowedOps.contains(op) then
          Decision.Deny(s"agent $subject scope does not include $op")
        else
          decide(parent, op) match
            case Decision.Allow               => Decision.Allow
            case Decision.Deny(reason)        => Decision.Deny(s"agent $subject blocked by parent: $reason")
            case Decision.StepUpRequired(why) => Decision.StepUpRequired(why)
