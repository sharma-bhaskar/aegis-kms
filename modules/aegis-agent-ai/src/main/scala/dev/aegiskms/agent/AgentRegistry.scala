package dev.aegiskms.agent

import cats.effect.IO
import cats.syntax.all.*
import dev.aegiskms.audit.{AuditQuery, AuditRecord}
import dev.aegiskms.core.Operation
import dev.aegiskms.iam.RevocationList

import java.time.{Duration, Instant}

/** Where an agent stands right now. Derived, never stored — see [[AgentRegistry]]. */
enum AgentStatus:
  /** Token is within its validity window and not on the revocation list. */
  case Active

  /** Past its `exp`. The token is already useless; the row is kept so operators can answer "what did this
    * agent have access to" after the fact.
    */
  case Expired

  /** Explicitly killed before its natural expiry — its `jti` is on the revocation list. */
  case Revoked

/** One agent as the operator sees it: who issued it, what it may do, how long it lives, and when it was last
  * seen doing anything.
  *
  * `lastSeenAt` is `None` for an agent that was minted but never used — a meaningfully different state from
  * "used a while ago", and one worth surfacing rather than collapsing into the issuance timestamp.
  */
final case class AgentRecord(
    agentId: String,
    /** The token's `jti`, which is what the revocation list is keyed by — the kill-switch (#102) needs it to
      * actually kill anything. Deliberately absent from `AgentSummaryDto`: the wire surface has no use for
      * it, and an identifier whose only purpose is revocation is not something to hand out for free.
      */
    jti: String,
    label: String,
    parent: String,
    scopes: Set[Operation],
    issuedAt: Instant,
    expiresAt: Instant,
    lastSeenAt: Option[Instant],
    status: AgentStatus
)

/** "Which agents exist right now, who issued them, and what can they touch?" — one answer, instead of the
  * operator cross-referencing issued JWTs against the audit log by hand (#101).
  *
  * ## Derived, not stored
  *
  * Aegis mints agent tokens statelessly: nothing writes an "agents" row, because the JWT itself is the
  * credential and the audit log is already the system of record for issuance. This registry reads that log
  * back rather than introducing a second write path that could disagree with it. Three consequences worth
  * knowing:
  *
  *   - Agents issued *before* this feature shipped still appear — there is no backfill to run.
  *   - The registry can never contradict the audit trail, which for a compliance-oriented KMS is the point.
  *   - It needs a **queryable** audit sink. On the default `stdout` sink there is nothing to read back, so
  *     the HTTP layer reports the capability as unavailable exactly the way `/v1/audit` already does.
  *
  * Retention cannot silently lose a live agent: `AgentTokenIssuer.DefaultMaxTtl` caps tokens at 24 hours
  * while audit retention defaults to 365 days, so any agent still valid was necessarily issued well inside
  * the retention window.
  */
trait AgentRegistry[F[_]]:
  def list(filter: AgentRegistry.Filter): F[List[AgentRecord]]

  /** Count of currently-active agents. Backs the Prometheus gauge; separated from [[list]] so the metrics
    * path doesn't pay for scope parsing and last-seen resolution.
    */
  def activeCount: F[Int]

object AgentRegistry:

  /** Filters compose with AND. `parent` matches the issuing human's subject exactly. */
  final case class Filter(
      parent: Option[String] = None,
      status: Option[AgentStatus] = None,
      limit: Int = DefaultLimit,
      offset: Int = 0
  )

  val DefaultLimit: Int = 100
  val MaxLimit: Int     = 500

  /** How far back to look for issuance records.
    *
    * Anything older than this cannot still be active, because agent TTLs are capped at
    * `AgentTokenIssuer.DefaultMaxTtl` (24 h). The extra margin covers operators who raised the cap and
    * ensures recently-expired agents remain visible for post-incident review rather than vanishing the
    * instant they expire.
    */
  val LookbackWindow: Duration = Duration.ofDays(7)

  /** Context keys written by `HttpRoutes.writeAgentIssueAudit` at issuance. This registry is the reader half
    * of that contract; the two must move together, so they are named in one place.
    */
  private[agent] object ContextKeys:
    val AgentId = "agent.id"
    val Jti     = "agent.jti"
    val Label   = "agent.issue.label"
    val Scopes  = "agent.issue.scopes"
    val TtlSecs = "agent.issue.ttlSeconds"

  /** The audit-log-backed implementation.
    *
    * Costs three round-trips regardless of how many agents come back: one page of issuance records, one
    * `GROUP BY` for last-seen across every agent in that page, and one revocation-list lookup per agent
    * (in-memory, or a Redis pipeline). No N+1 over the audit table.
    */
  def auditBacked(
      audit: AuditQuery[IO],
      revocations: RevocationList[IO],
      now: IO[Instant] = IO.realTimeInstant
  ): AgentRegistry[IO] = new AgentRegistry[IO]:

    def list(filter: Filter): IO[List[AgentRecord]] =
      for
        current   <- now
        issuances <- fetchIssuances(current)
        candidates = issuances.flatMap(parse)
        // Resolve status before paginating: "show me revoked agents" must consider every candidate,
        // not just those that happen to land on the first page.
        statuses <- candidates.traverse(c => statusOf(c, current).map(c -> _))
        filtered = statuses.filter { case (c, s) =>
          filter.parent.forall(_ == c.parent) && filter.status.forall(_ == s)
        }
        page = filtered.slice(
          math.max(0, filter.offset),
          math.max(0, filter.offset) + math.max(1, math.min(filter.limit, MaxLimit))
        )
        lastSeen <- audit.lastActivityBy(page.map(_._1.agentId).toSet, current.minus(LookbackWindow))
      yield page.map { case (c, status) =>
        AgentRecord(
          agentId = c.agentId,
          jti = c.jti,
          label = c.label,
          parent = c.parent,
          scopes = c.scopes,
          issuedAt = c.issuedAt,
          expiresAt = c.expiresAt,
          lastSeenAt = lastSeen.get(c.agentId),
          status = status
        )
      }

    def activeCount: IO[Int] =
      for
        current   <- now
        issuances <- fetchIssuances(current)
        candidates = issuances.flatMap(parse).filter(_.expiresAt.isAfter(current))
        revoked <- candidates.traverse(c => revocations.isRevoked(c.jti))
      yield candidates.zip(revoked).count { case (_, isRevoked) => !isRevoked }

    private def fetchIssuances(current: Instant): IO[List[AuditRecord]] =
      audit
        .query(AuditQuery.Filter(
          since = Some(current.minus(LookbackWindow)),
          resourcePrefix = Some("agent:"),
          operation = Some(Operation.Create),
          limit = AuditQuery.MaxLimit
        ))
        .map(_.records)

    private def statusOf(c: Candidate, current: Instant): IO[AgentStatus] =
      revocations.isRevoked(c.jti).map {
        case true                                   => AgentStatus.Revoked
        case false if !c.expiresAt.isAfter(current) => AgentStatus.Expired
        case false                                  => AgentStatus.Active
      }

  /** An issuance audit row that parsed into something usable. */
  final private case class Candidate(
      agentId: String,
      jti: String,
      label: String,
      parent: String,
      scopes: Set[Operation],
      issuedAt: Instant,
      expiresAt: Instant
  )

  /** Turn an issuance audit record into a [[Candidate]], or drop it.
    *
    * Rows are dropped rather than surfaced-with-holes when they lack `agent.id`, `agent.jti`, or a parseable
    * TTL: those are the *failed* issuance attempts (`writeAgentIssueAudit` records them with no agent id,
    * because no token was minted) and they are not agents. A registry that listed them would invent agents
    * that never existed.
    */
  private def parse(r: AuditRecord): Option[Candidate] =
    for
      agentId <- r.context.get(ContextKeys.AgentId)
      jti     <- r.context.get(ContextKeys.Jti)
      ttl     <- r.context.get(ContextKeys.TtlSecs).flatMap(_.toLongOption)
    yield Candidate(
      agentId = agentId,
      jti = jti,
      label = r.context.getOrElse(ContextKeys.Label, ""),
      parent = r.principal.subject,
      scopes = parseScopes(r.context.getOrElse(ContextKeys.Scopes, "")),
      issuedAt = r.at,
      expiresAt = r.at.plusSeconds(ttl)
    )

  /** Scopes are stored as a comma-joined list of `Operation` names. Unrecognised names are dropped: the
    * issuer already rejects unknown operations at mint time, so anything unparseable here is an enum that was
    * removed in a later version — better to show the operations that still mean something than to discard the
    * whole agent.
    */
  private def parseScopes(raw: String): Set[Operation] =
    raw.split(',').iterator
      .map(_.trim)
      .filter(_.nonEmpty)
      .flatMap(name => Operation.values.find(_.toString == name))
      .toSet
