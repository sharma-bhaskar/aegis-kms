package dev.aegiskms.agent

import cats.effect.IO
import cats.syntax.all.*
import dev.aegiskms.audit.{AuditRecord, AuditSink}
import dev.aegiskms.core.{ErrorCode, KmsError, Operation, Principal}
import dev.aegiskms.iam.RevocationList
import org.slf4j.LoggerFactory

import java.time.Instant
import java.util.UUID

/** What the operator asked to kill.
  *
  * @param parent
  *   subject of the human whose agents should be revoked.
  * @param issuedAfter
  *   when set, only agents minted at or after this instant are killed. The incident-shaped question is
  *   usually "everything alice spawned since the breach started", not "everything alice has ever spawned" —
  *   the second would take out legitimate long-running work along with the compromised credentials.
  */
final case class KillSwitchRequest(parent: String, issuedAfter: Option[Instant] = None)

/** One agent the kill-switch acted on. */
final case class KilledAgent(agentId: String, label: String, expiresAt: Instant)

/** Outcome of a kill-switch sweep.
  *
  * `alreadyRevoked` and `expired` are reported separately from `killed` so the operator can tell "I stopped
  * 12 live credentials" from "I stopped 1 and the other 11 were already dead" — during an incident that
  * difference changes what you do next.
  */
final case class KillSwitchResult(
    parent: String,
    killed: List[KilledAgent],
    alreadyRevoked: Int,
    expired: Int
):
  def totalConsidered: Int = killed.size + alreadyRevoked + expired

/** The agent kill-switch (#102): revoke every live agent under a parent principal in one call.
  *
  * Before this, revocation was per-`jti`. In an incident the actual question is "kill everything `alice@org`
  * spawned in the last 24 hours", and answering it meant scripting over the audit log by hand — exactly the
  * kind of task nobody wants to be writing correctly at 3am.
  *
  * ## How it kills
  *
  * Enumeration comes from [[AgentRegistry]]; revocation goes through the [[RevocationList]] SPI, so this
  * works unchanged against the Redis-backed list that multi-node deployments use — every node consults the
  * same store on each verify, so a kill lands fleet-wide rather than on whichever replica served the request.
  *
  * Each `jti` is recorded with the token's own `expiresAt`, so entries self-purge once the token would have
  * died naturally and the list stays bounded.
  *
  * ## Audit
  *
  * One record per revoked agent, plus one summary record for the sweep. Both, deliberately: the per-agent
  * rows are what a later investigation joins against, and the summary is what tells a reviewer that a *bulk*
  * action occurred rather than a dozen coincidental individual ones.
  *
  * ## Partial failure
  *
  * A revocation-store error on one agent does not abort the sweep. Killing 9 of 10 credentials and reporting
  * the failure beats killing 0 because the 3rd call timed out — the operator can retry, and the operation is
  * idempotent (revoking an already-revoked `jti` is a no-op).
  */
trait AgentKillSwitch:
  /** Revoke every live agent under `request.parent`.
    *
    * Authorization (human-only, step-up) is the caller's responsibility — the HTTP layer enforces it. The
    * `caller` argument exists so the audit trail names who pulled the lever, including when that is the
    * auto-responder's system principal.
    */
  def revokeAll(caller: Principal, request: KillSwitchRequest): IO[Either[KmsError, KillSwitchResult]]

object AgentKillSwitch:
  /** The real implementation: enumerate through the registry, revoke through the revocation list. */
  def auditBacked(
      registry: AgentRegistry[IO],
      revocations: RevocationList[IO],
      auditSink: AuditSink[IO],
      now: IO[Instant] = IO.realTimeInstant
  ): AgentKillSwitch = new AuditBackedAgentKillSwitch(registry, revocations, auditSink, now)

final class AuditBackedAgentKillSwitch(
    registry: AgentRegistry[IO],
    revocations: RevocationList[IO],
    auditSink: AuditSink[IO],
    now: IO[Instant] = IO.realTimeInstant
) extends AgentKillSwitch:

  private val logger = LoggerFactory.getLogger(classOf[AuditBackedAgentKillSwitch])

  def revokeAll(caller: Principal, request: KillSwitchRequest): IO[Either[KmsError, KillSwitchResult]] =
    if request.parent.trim.isEmpty then
      IO.pure(Left(KmsError(ErrorCode.InvalidField, "parent must be non-empty")))
    else
      for
        t <- now
        agents <- registry.list(AgentRegistry.Filter(
          parent = Some(request.parent),
          limit = AgentRegistry.MaxLimit
        ))
        inWindow = agents.filter(a => request.issuedAfter.forall(!a.issuedAt.isBefore(_)))
        // Partition before acting so the counts describe the state we found, not the state we made.
        (live, dead) = inWindow.partition(_.status == AgentStatus.Active)
        results <- live.traverse(a => killOne(caller, a, t).map(a -> _))
        killed = results.collect { case (a, true) => KilledAgent(a.agentId, a.label, a.expiresAt) }
        failed = results.count { case (_, ok) => !ok }
        result = KillSwitchResult(
          parent = request.parent,
          killed = killed,
          alreadyRevoked = dead.count(_.status == AgentStatus.Revoked) + failed,
          expired = dead.count(_.status == AgentStatus.Expired)
        )
        _ <- writeSummaryAudit(caller, request, result, failed, t)
        _ <- IO(logger.warn(
          s"agent kill-switch: parent=${request.parent} killed=${killed.size} " +
            s"alreadyRevoked=${result.alreadyRevoked} expired=${result.expired} failed=$failed " +
            s"by=${caller.subject}"
        ))
      yield Right(result)

  /** Revoke one agent and write its audit row. Returns false if the revocation store rejected it. */
  private def killOne(caller: Principal, agent: AgentRecord, t: Instant): IO[Boolean] =
    revocations
      .revoke(agent.jti, agent.expiresAt)
      .as(true)
      .handleErrorWith { e =>
        IO(logger.error(
          s"agent kill-switch: failed to revoke agent=${agent.agentId}: ${e.getMessage}"
        )).as(false)
      }
      .flatTap(ok => writeAgentAudit(caller, agent, ok, t))

  private def writeAgentAudit(
      caller: Principal,
      agent: AgentRecord,
      ok: Boolean,
      t: Instant
  ): IO[Unit] =
    auditSink.write(AuditRecord(
      at = t,
      principal = caller,
      operation = Operation.Revoke,
      resource = s"agent:${agent.agentId}",
      outcome =
        if ok then s"Success killed agentId=${agent.agentId} via kill-switch"
        else s"Failed revocation store rejected agentId=${agent.agentId}",
      correlationId = UUID.randomUUID().toString,
      context = Map(
        "agent.id"                -> agent.agentId,
        "agent.jti"               -> agent.jti,
        "agent.killswitch"        -> "true",
        "agent.killswitch.parent" -> agent.parent
      )
    ))

  private def writeSummaryAudit(
      caller: Principal,
      request: KillSwitchRequest,
      result: KillSwitchResult,
      failed: Int,
      t: Instant
  ): IO[Unit] =
    auditSink.write(AuditRecord(
      at = t,
      principal = caller,
      operation = Operation.Revoke,
      // A parent-scoped resource, distinct from the per-agent `agent:<id>` rows, so a reviewer can find
      // the bulk action without wading through its individual effects.
      resource = s"parent:${request.parent}",
      outcome =
        s"Success kill-switch swept parent=${request.parent} killed=${result.killed.size} " +
          s"alreadyRevoked=${result.alreadyRevoked} expired=${result.expired} failed=$failed",
      correlationId = UUID.randomUUID().toString,
      context = Map(
        "agent.killswitch"             -> "true",
        "agent.killswitch.summary"     -> "true",
        "agent.killswitch.parent"      -> request.parent,
        "agent.killswitch.killed"      -> result.killed.size.toString,
        "agent.killswitch.considered"  -> result.totalConsidered.toString,
        "agent.killswitch.issuedAfter" -> request.issuedAfter.fold("none")(_.toString)
      )
    ))
