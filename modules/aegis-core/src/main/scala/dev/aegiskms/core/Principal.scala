package dev.aegiskms.core

import java.time.Instant
import scala.concurrent.duration.Duration

/** A principal is any identity that can act against Aegis-KMS.
  *
  * Modeled as a sealed ADT so every call site is forced to pattern-match all three kinds. In particular this
  * means no code path can ever silently conflate a short-lived `Agent` principal with a long-lived `Human`.
  */
sealed trait Principal:
  def subject: String

object Principal:

  /** A human operator, typically authenticated via OIDC.
    *
    * `amr` and `authTime` carry *how* and *when* this human proved their identity, mirroring the OIDC claims
    * of the same names. They exist so high-blast-radius operations can demand a stronger, fresher credential
    * than "you hold a valid token" — see `dev.aegiskms.iam.StepUpPolicy`. Both default to "unknown", which
    * every step-up check treats as not-satisfied: a token minted before Aegis understood step-up must not be
    * silently accepted as having passed it.
    *
    * @param amr
    *   Authentication Methods References — e.g. `Set("pwd", "mfa", "otp", "hwk")`. Empty means the issuer
    *   told us nothing about how this human authenticated.
    * @param authTime
    *   When the human actually authenticated, which is not the same as when the token was issued: a refresh
    *   can mint a new token hours after the last real login.
    */
  final case class Human(
      subject: String,
      groups: Set[String],
      amr: Set[String] = Set.empty,
      authTime: Option[Instant] = None
  ) extends Principal

  /** A long-lived service account, typically authenticated via mTLS or an API key.
    */
  final case class Service(subject: String, tenant: TenantId) extends Principal

  /** An AI agent acting on behalf of an operator.
    *
    * Agent credentials are always short-lived and carry an explicit allowlist of operations. Every audit
    * record written while acting as an agent includes both the agent subject and the operator subject, so the
    * chain of responsibility is traceable.
    */
  final case class Agent(
      subject: String,
      operator: Principal,
      purpose: String,
      issuedAt: Instant,
      ttl: Duration,
      allowedOps: Set[Operation],
      parent: Option[AgentId]
  ) extends Principal

opaque type TenantId = String
object TenantId:
  def apply(value: String): TenantId        = value
  extension (t: TenantId) def value: String = t

opaque type AgentId = String
object AgentId:
  def apply(value: String): AgentId        = value
  extension (a: AgentId) def value: String = a
