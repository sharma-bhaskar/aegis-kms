package dev.aegiskms.agent

import cats.effect.IO
import dev.aegiskms.audit.{AuditQuery, AuditRecord}
import dev.aegiskms.core.Principal

import java.time.{Duration, Instant}

/** Read-only AI-advisor scan over the audit log (#28, ROADMAP 2.1.a).
  *
  * The v0.2.1 advisor is deliberately *deterministic*: it answers a bounded set of operator questions ("which
  * keys are idle", "which agents have unusually broad operation usage", "are there active anomalies", "who
  * are the riskiest agents") by aggregating the audit log — no LLM call, no mutation. The pluggable
  * [[LlmClient]] (#30) is layered on later for natural-language *narration* of these same facts (`advisor
  * explain`, #29); keeping the analysis deterministic means the headline demo runs in CI with no API key and
  * the numbers are reproducible and auditable.
  *
  * The contract is strictly read-only: `scan` reads via [[AuditQuery]] and never touches `KeyService`.
  */
trait AdvisorService[F[_]]:
  def scan(request: AdvisorScan.Request): F[AdvisorScan.Report]

object AdvisorService:

  /** Hard cap on the number of audit rows a single scan will pull into memory. A scan is an operator triage
    * action, not a bulk export; 50k rows is plenty to characterise a window. When the window holds more than
    * this, the report is marked `truncated = true` so the operator knows the analysis is over a partial
    * window rather than silently under-reporting (e.g. an idle key that only appears past the cap).
    */
  val MaxScan: Int = 50_000

  /** Page size for the underlying [[AuditQuery]] paging loop — the SPI's own per-request maximum. */
  val PageSize: Int = AuditQuery.MaxLimit

  /** Deterministic implementation backed by an [[AuditQuery]]. Pages through `[now - lookback, now)` up to
    * [[MaxScan]] rows, then folds the records into a [[AdvisorScan.Report]] via [[AdvisorScan.analyze]].
    */
  def deterministic(reader: AuditQuery[IO]): AdvisorService[IO] = new AdvisorService[IO]:
    def scan(request: AdvisorScan.Request): IO[AdvisorScan.Report] =
      val windowEnd   = request.now
      val windowStart = request.now.minus(request.lookback)

      def loop(offset: Int, acc: Vector[AuditRecord]): IO[(Vector[AuditRecord], Boolean)] =
        if acc.sizeIs >= MaxScan then IO.pure((acc, true))
        else
          reader
            .query(
              AuditQuery.Filter(
                since = Some(windowStart),
                until = Some(windowEnd),
                limit = PageSize,
                offset = offset
              )
            )
            .flatMap { page =>
              val next = acc ++ page.records
              if page.records.isEmpty then IO.pure((next, false)) // no progress; stop
              else if page.hasMore then loop(offset + page.records.size, next)
              else IO.pure((next, false)) // window exhausted
            }

      loop(0, Vector.empty).map { case (records, truncated) =>
        AdvisorScan.analyze(request, windowStart, windowEnd, records.toList, truncated)
      }

/** Request, result, and the pure analysis for an advisor scan. `analyze` is split out from the IO-bound
  * paging so the heuristics can be property-tested against synthetic records without a live audit store.
  */
object AdvisorScan:

  val DefaultLookback: Duration       = Duration.ofDays(90)
  val DefaultUnusedAfter: Duration    = Duration.ofDays(30)
  val DefaultBroadScopeThreshold: Int = 5
  val DefaultTopRiskiest: Int         = 5

  /** Scan parameters.
    *
    *   - `now` — the reference instant; the window is `[now - lookback, now)` and "idle for" is measured from
    *     `now`. Passed in (rather than read from the clock here) so the analysis stays pure and testable.
    *   - `lookback` — how far back to read the audit log. Must exceed `unusedAfter` for idle-key detection to
    *     see anything (a key whose last activity predates the window can't be observed).
    *   - `unusedAfter` — a key with no audit activity newer than `now - unusedAfter` is flagged "unused".
    *   - `broadScopeThreshold` — an agent using at least this many *distinct* operations is flagged "broad
    *     scope".
    *   - `topRiskiest` — number of agents to return in the riskiest ranking.
    */
  final case class Request(
      now: Instant,
      lookback: Duration = DefaultLookback,
      unusedAfter: Duration = DefaultUnusedAfter,
      broadScopeThreshold: Int = DefaultBroadScopeThreshold,
      topRiskiest: Int = DefaultTopRiskiest
  )

  /** A key with no audit activity newer than the cutoff. `idleDays` is whole days between `lastSeen` and
    * `now`.
    */
  final case class UnusedKey(keyId: String, lastSeen: Instant, idleDays: Long)

  /** An agent whose distinct-operation count met the broad-scope threshold; `operations` is the sorted set of
    * distinct KMIP operation names it invoked in the window.
    */
  final case class BroadScopeAgent(agent: String, operations: List[String])

  /** A single blocked / flagged operation surfaced as an active anomaly. */
  final case class ActiveAnomaly(at: Instant, actor: String, operation: String, outcome: String)

  /** An agent ranked by a transparent risk proxy. `score` combines failed-op weight, operation breadth, and
    * the maximum `risk.score` the scorer stamped on the agent's records (`failedOps`/`distinctOps` are
    * surfaced so the number is explainable rather than opaque).
    */
  final case class RiskyAgent(agent: String, score: Double, failedOps: Int, distinctOps: Int)

  /** The full scan result. `scannedRecords` + `truncated` describe the coverage so a thin report can be told
    * apart from a quiet window.
    */
  final case class Report(
      windowStart: Instant,
      windowEnd: Instant,
      scannedRecords: Int,
      truncated: Boolean,
      unusedKeys: List[UnusedKey],
      broadScopeAgents: List[BroadScopeAgent],
      activeAnomalies: List[ActiveAnomaly],
      riskiestAgents: List[RiskyAgent]
  )

  /** Fold a window of audit records into a [[Report]]. Pure; all heuristics live here.
    *
    *   - **Unused keys** — group `key:<id>` resources, take the latest `at` per key, flag those older than
    *     `now - unusedAfter`. Sorted most-idle first.
    *   - **Broad-scope agents** — over `Principal.Agent` records, agents whose distinct-operation count is
    *     `>= broadScopeThreshold`. Sorted widest first.
    *   - **Active anomalies** — records whose `outcome` signals a block / flag (see [[isAnomalous]]). Most
    *     recent first.
    *   - **Riskiest agents** — `failedOps * 2 + distinctOps + maxRiskScore * 10`, top `topRiskiest`.
    */
  def analyze(
      request: Request,
      windowStart: Instant,
      windowEnd: Instant,
      records: List[AuditRecord],
      truncated: Boolean
  ): Report =
    val cutoff = request.now.minus(request.unusedAfter)

    val latestByKey: Map[String, Instant] =
      records.iterator
        .filter(_.resource.startsWith("key:"))
        .map(r => r.resource.stripPrefix("key:") -> r.at)
        .toList
        .groupMapReduce(_._1)(_._2)((a, b) => if a.isAfter(b) then a else b)

    val unusedKeys =
      latestByKey.iterator.collect {
        case (keyId, lastSeen) if lastSeen.isBefore(cutoff) =>
          UnusedKey(keyId, lastSeen, Duration.between(lastSeen, request.now).toDays)
      }.toList
        .sortBy(k => (-k.idleDays, k.keyId))

    val agentRecords = records.filter(_.principal.isInstanceOf[Principal.Agent])

    val opsByAgent: Map[String, List[String]] =
      agentRecords
        .groupMap(_.principal.subject)(_.operation.toString)
        .map((subject, ops) => subject -> ops.distinct.sorted)

    val broadScopeAgents =
      opsByAgent.iterator.collect {
        case (agent, ops) if ops.sizeIs >= request.broadScopeThreshold => BroadScopeAgent(agent, ops)
      }.toList
        .sortBy(a => (-a.operations.size, a.agent))

    val activeAnomalies =
      records.iterator
        .filter(r => isAnomalous(r.outcome))
        .map(r => ActiveAnomaly(r.at, r.principal.subject, r.operation.toString, r.outcome))
        .toList
        .sortBy(_.at)(using Ordering[Instant].reverse)

    val riskiestAgents =
      agentRecords
        .groupBy(_.principal.subject)
        .iterator
        .map { (agent, rs) =>
          val failed   = rs.count(_.outcome.startsWith("Failed"))
          val distinct = rs.map(_.operation.toString).distinct.size
          val maxRisk =
            rs.flatMap(_.context.get("risk.score")).flatMap(_.toDoubleOption).maxOption.getOrElse(0.0)
          RiskyAgent(
            agent,
            score = failed * 2.0 + distinct + maxRisk * 10.0,
            failedOps = failed,
            distinctOps = distinct
          )
        }
        .toList
        .sortBy(a => (-a.score, a.agent))
        .take(request.topRiskiest)

    Report(
      windowStart = windowStart,
      windowEnd = windowEnd,
      scannedRecords = records.size,
      truncated = truncated,
      unusedKeys = unusedKeys,
      broadScopeAgents = broadScopeAgents,
      activeAnomalies = activeAnomalies,
      riskiestAgents = riskiestAgents
    )

  /** Whether an audit `outcome` reads as an active anomaly: a failed operation, or an outcome that names a
    * detector / decision-engine flag (anomaly, step-up, denial, alert). Conservative by design — a legit
    * success never matches.
    */
  def isAnomalous(outcome: String): Boolean =
    val lower = outcome.toLowerCase
    outcome.startsWith("Failed") ||
    lower.contains("anomaly") ||
    lower.contains("stepup") ||
    lower.contains("step-up") ||
    lower.contains("denied") ||
    lower.contains("alert")
