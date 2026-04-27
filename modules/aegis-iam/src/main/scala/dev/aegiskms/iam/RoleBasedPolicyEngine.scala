package dev.aegiskms.iam

import cats.effect.IO
import dev.aegiskms.core.{Operation, Principal}

/** A simple allowlist policy engine.
  *
  * Boolean policy is the floor of the four-pillar model — risk scoring (PR W2) and anomaly detection (PR W1)
  * layer on top, but a deny here is always honored without consulting them.
  *
  * Rules:
  *   - `Principal.Human(subject, groups)` is allowed if any of `groups` is bound to the requested op via
  *     `roleBindings`, OR the subject itself has an explicit binding via `subjectBindings`.
  *   - `Principal.Service(subject, _)` is allowed via `subjectBindings` only.
  *   - `Principal.Agent(subject, parent, _, _, _, allowedOps, _)` is allowed iff:
  *     - `op` is in the agent's own `allowedOps` allowlist, AND
  *     - the parent principal would be allowed for the same op (recursive check).
  *
  * The recursive parent check is the heart of the agent-identity model: an agent never escalates beyond what
  * the human who issued its credential could do. If Alice can sign with `key:invoice-2026` but not
  * `key:treasury-master`, no agent issued under Alice can sign with `key:treasury-master` even if its own
  * allowlist is broader.
  */
final class RoleBasedPolicyEngine(
    roleBindings: Map[String, Set[Operation]],
    subjectBindings: Map[String, Set[Operation]]
) extends PolicyEngine[IO]:

  def permit(principal: Principal, op: Operation, resource: String): IO[Decision] =
    IO.pure(decide(principal, op))

  private def decide(principal: Principal, op: Operation): Decision =
    principal match
      case Principal.Human(subject, groups) =>
        val bySubject = subjectBindings.getOrElse(subject, Set.empty).contains(op)
        val byRole    = groups.exists(g => roleBindings.getOrElse(g, Set.empty).contains(op))
        if bySubject || byRole then Decision.Allow
        else
          Decision.Deny(s"$subject is not bound to $op via any role or direct binding")

      case Principal.Service(subject, _) =>
        if subjectBindings.getOrElse(subject, Set.empty).contains(op) then Decision.Allow
        else Decision.Deny(s"service $subject has no direct binding for $op")

      case agent @ Principal.Agent(subject, operator, _, _, _, allowedOps, _) =>
        if !allowedOps.contains(op) then
          Decision.Deny(s"agent $subject scope does not include $op")
        else
          decide(operator, op) match
            case Decision.Allow               => Decision.Allow
            case Decision.Deny(reason)        => Decision.Deny(s"agent $subject blocked by parent: $reason")
            case Decision.StepUpRequired(why) => Decision.StepUpRequired(why)

object RoleBasedPolicyEngine:

  /** Construct an engine with no bindings — every call returns `Deny`. Useful as a deny-by-default base for
    * tests that add a single binding inline.
    */
  val denyAll: RoleBasedPolicyEngine = new RoleBasedPolicyEngine(Map.empty, Map.empty)

  /** Constructor for the common dev-mode case: a single role granting the full op set. */
  def adminsOnly(role: String): RoleBasedPolicyEngine =
    new RoleBasedPolicyEngine(
      roleBindings = Map(role -> Operation.values.toSet),
      subjectBindings = Map.empty
    )
