package dev.aegiskms.audit

import cats.data.NonEmptyList
import cats.effect.{IO, Resource}
import cats.syntax.all.*
import dev.aegiskms.core.{Operation, Principal, TenantId}
import dev.aegiskms.persistence.PostgresJournalConfig
import doobie.*
import doobie.hikari.HikariTransactor
import doobie.implicits.*
import doobie.postgres.circe.jsonb.implicits.*
import doobie.postgres.implicits.*
import doobie.util.fragment.Fragment
import io.circe.Json
import io.circe.syntax.*

import java.time.Instant

/** Doobie-backed Postgres implementation of `AuditSink[IO]` plus retention.
  *
  * Schema:
  * {{{
  *   aegis_audit_events (
  *     seq            BIGSERIAL    PRIMARY KEY,    -- monotonic insertion order
  *     correlation_id VARCHAR(64)  NOT NULL,       -- AuditRecord.correlationId
  *     occurred_at    TIMESTAMPTZ  NOT NULL,       -- AuditRecord.at (decision time)
  *     actor_subject  VARCHAR(256) NOT NULL,       -- Principal.subject
  *     actor_kind     VARCHAR(16)  NOT NULL,       -- 'Human' | 'Service' | 'Agent'
  *     operation      VARCHAR(32)  NOT NULL,       -- KMIP Operation enum name
  *     resource       VARCHAR(512) NOT NULL,       -- 'key:<id>' | 'agent:<id>' | 'pattern:...'
  *     outcome        TEXT         NOT NULL,
  *     context        JSONB        NOT NULL DEFAULT '{}'::jsonb,
  *     inserted_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
  *   )
  * }}}
  *
  * Indexes match the four #20 audit-read API filters: `actor`, `key` (resource), `op`, `since`. Time is
  * included in every actor/resource/op index so range scans stay cheap as the table grows.
  *
  * Why JSONB for `context`: `AuditRecord.context` is a `Map[String, String]` that downstream consumers (the
  * risk scorer, decision adapter, auto-responder, agent-issue endpoint) populate with arbitrary keys
  * (`risk.score`, `outcome.decision`, `agent.jti`, …). Keeping it as JSONB lets the surface grow without DDL
  * churn; SIEM consumers can pull individual keys via `context->>'risk.score'`.
  *
  * **Retention.** `pruneBefore(cutoff)` deletes rows with `occurred_at < cutoff`, returning the row count.
  * Operators wire a recurring `IO.sleep(24h) *> pruneBefore(now - retention)` fiber in `Server.boot` — see
  * `Server.scala` for the schedule.
  *
  * **Backpressure.** Writes are synchronous (the underlying `AuditingKeyService` calls `sink.write` inside
  * the request path). For high-throughput deployments add a buffered/batched fan-out sink in front of this
  * one (a `QueuedAuditSink` is on the roadmap behind #21).
  */
object PostgresAuditSink:

  /** Resource-managed Postgres-backed audit sink. Acquires its own HikariCP pool — the sink's pool is
    * separate from the journal's because audit writes and journal writes have independent lifecycles and rate
    * profiles (every request produces an audit row; only state-changing ops produce a journal entry).
    */
  def make(config: PostgresJournalConfig): Resource[IO, PostgresAuditSink] =
    for
      ec <- ExecutionContexts.fixedThreadPool[IO](config.poolSize)
      xa <- HikariTransactor.newHikariTransactor[IO](
        driverClassName = "org.postgresql.Driver",
        url = config.jdbcUrl,
        user = config.username,
        pass = config.password,
        connectEC = ec
      )
      _ <- Resource.eval(bootstrap(xa))
    yield new PostgresAuditSink(xa)

  /** Test seam — take an externally-owned `Transactor`, run the bootstrap, yield the sink. */
  def bootstrappedFor(xa: Transactor[IO]): IO[PostgresAuditSink] =
    bootstrap(xa).as(new PostgresAuditSink(xa))

  // ── Migration ─────────────────────────────────────────────────────────────

  private val createTable: doobie.ConnectionIO[Int] =
    sql"""
      CREATE TABLE IF NOT EXISTS aegis_audit_events (
        seq            BIGSERIAL    PRIMARY KEY,
        correlation_id VARCHAR(64)  NOT NULL,
        occurred_at    TIMESTAMPTZ  NOT NULL,
        actor_subject  VARCHAR(256) NOT NULL,
        actor_kind     VARCHAR(16)  NOT NULL,
        operation      VARCHAR(32)  NOT NULL,
        resource       VARCHAR(512) NOT NULL,
        outcome        TEXT         NOT NULL,
        context        JSONB        NOT NULL DEFAULT '{}'::jsonb,
        inserted_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
      )
    """.update.run

  // One composite index per (#20) query path. `occurred_at DESC` matches the common "most recent
  // first" pagination shape; the leading column scopes the scan.
  private val createActorIndex: doobie.ConnectionIO[Int] =
    sql"""
      CREATE INDEX IF NOT EXISTS aegis_audit_events_actor_idx
      ON aegis_audit_events(actor_subject, occurred_at DESC)
    """.update.run

  private val createResourceIndex: doobie.ConnectionIO[Int] =
    sql"""
      CREATE INDEX IF NOT EXISTS aegis_audit_events_resource_idx
      ON aegis_audit_events(resource, occurred_at DESC)
    """.update.run

  private val createOperationIndex: doobie.ConnectionIO[Int] =
    sql"""
      CREATE INDEX IF NOT EXISTS aegis_audit_events_operation_idx
      ON aegis_audit_events(operation, occurred_at DESC)
    """.update.run

  private val createOccurredIndex: doobie.ConnectionIO[Int] =
    sql"""
      CREATE INDEX IF NOT EXISTS aegis_audit_events_occurred_idx
      ON aegis_audit_events(occurred_at)
    """.update.run

  private def bootstrap(xa: Transactor[IO]): IO[Unit] =
    (createTable *> createActorIndex *> createResourceIndex *> createOperationIndex *> createOccurredIndex)
      .transact(xa)
      .void

  // ── Principal kind discriminator ──────────────────────────────────────────

  private def kindOf(p: Principal): String = p match
    case _: Principal.Human   => "Human"
    case _: Principal.Service => "Service"
    case _: Principal.Agent   => "Agent"

/** Doobie-backed `AuditSink[IO]` with a `pruneBefore` retention method.
  *
  * Constructed via `PostgresAuditSink.make(config)` (Resource-managed pool) or
  * `PostgresAuditSink.bootstrappedFor(xa)` (caller-owned transactor; used by tests).
  */
final class PostgresAuditSink private[audit] (xa: Transactor[IO])
    extends AuditSink[IO] with AuditQuery[IO]:

  import PostgresAuditSink.*

  def write(record: AuditRecord): IO[Unit] =
    val contextJson: Json = record.context.asJson
    sql"""
      INSERT INTO aegis_audit_events
        (correlation_id, occurred_at, actor_subject, actor_kind,
         operation, resource, outcome, context)
      VALUES
        (${record.correlationId}, ${record.at}, ${record.principal.subject}, ${kindOf(record.principal)},
         ${record.operation.toString}, ${record.resource}, ${record.outcome}, $contextJson)
    """.update.run.transact(xa).void

  /** Retention helper: delete rows whose `occurred_at` is strictly before `cutoff`. Returns the number of
    * rows deleted so the scheduler can log progress.
    *
    * Implementation note: this is a single `DELETE … WHERE occurred_at < ?` statement, which on a table
    * indexed by `occurred_at` is an index-scan delete — fast even on multi-million-row tables. If retention
    * deletes ever become slow, the next step is partitioning by month, but that's premature until we measure
    * it.
    */
  def pruneBefore(cutoff: Instant): IO[Long] =
    sql"""
      DELETE FROM aegis_audit_events WHERE occurred_at < $cutoff
    """.update.run.transact(xa).map(_.toLong)

  // ── Query (read side, backs GET /v1/audit) ────────────────────────────────

  /** Composes a parameterised `WHERE` clause from the filter's optional fields and runs a single SELECT. The
    * "limit + 1 trick" fetches one extra row so we can set `hasMore` without a follow-up COUNT query — fine
    * for offset-based pagination, would change for cursor-based.
    *
    * Filter columns line up 1:1 with the composite indexes created at bootstrap, so the common paths
    * (filter-by-actor, filter-by-resource, filter-by-operation, filter-by-since) are index-scans even on a
    * million-row table. A query with no filters at all is a full-table `ORDER BY occurred_at DESC LIMIT n
    * OFFSET m`, supported by the `aegis_audit_events_occurred_idx` (DESC ordering is read backwards through
    * the ascending index — Postgres handles this).
    */
  def query(filter: AuditQuery.Filter): IO[AuditQuery.Page] =
    val safeLimit  = math.max(1, math.min(filter.limit, AuditQuery.MaxLimit))
    val safeOffset = math.max(0, filter.offset)

    val whereFrags: List[Fragment] = List(
      filter.since.map(s => fr"occurred_at >= $s"),
      filter.until.map(u => fr"occurred_at < $u"),
      filter.actor.map(a => fr"actor_subject = $a"),
      filter.resource.map(r => fr"resource = $r"),
      // `LIKE 'prefix%'` with an explicit ESCAPE so a literal % or _ in the prefix can't act as a
      // wildcard. A left-anchored pattern still uses the `resource` btree index (on C collation, or
      // via a text_pattern_ops index) — which is exactly why only prefix matching is exposed.
      filter.resourcePrefix.map(p =>
        fr"resource LIKE ${AuditQuery.escapeLikePrefix(p) + "%"} ESCAPE '\'"
      ),
      filter.operation.map(o => fr"operation = ${o.toString}")
    ).flatten

    val whereSql: Fragment =
      if whereFrags.isEmpty then Fragment.empty
      else fr"WHERE " ++ whereFrags.intercalate(fr" AND ")

    // limit + 1 so hasMore is derivable without a COUNT(*) round-trip.
    val q =
      fr"""
        SELECT correlation_id, occurred_at, actor_subject, actor_kind,
               operation, resource, outcome, context
        FROM aegis_audit_events
      """ ++ whereSql ++ fr" ORDER BY occurred_at DESC, seq DESC " ++
        fr" LIMIT ${safeLimit + 1} OFFSET $safeOffset"

    q.query[(String, Instant, String, String, String, String, String, Json)]
      .to[List]
      .transact(xa)
      .map { rows =>
        val hasMore   = rows.size > safeLimit
        val displayed = if hasMore then rows.take(safeLimit) else rows
        val records = displayed.map { case (corrId, at, subj, kind, op, res, outcome, ctx) =>
          AuditRecord(
            at = at,
            principal = principalFor(kind, subj),
            operation = Operation.values.find(_.toString == op).getOrElse(Operation.Query),
            resource = res,
            outcome = outcome,
            correlationId = corrId,
            context = contextFromJson(ctx)
          )
        }
        AuditQuery.Page(records, safeLimit, safeOffset, hasMore)
      }

  /** One `GROUP BY` over the `actor_subject` index. Empty `actors` short-circuits without a round-trip — `IN
    * ()` is a syntax error in Postgres, and the answer is knowable without asking.
    */
  def lastActivityBy(actors: Set[String], since: Instant): IO[Map[String, Instant]] =
    NonEmptyList.fromList(actors.toList) match
      case None => IO.pure(Map.empty)
      case Some(nel) =>
        val q =
          fr"""
          SELECT actor_subject, MAX(occurred_at)
          FROM aegis_audit_events
          WHERE occurred_at >= $since AND
        """ ++ Fragments.in(fr"actor_subject", nel) ++ fr" GROUP BY actor_subject"
        q.query[(String, Instant)].to[List].transact(xa).map(_.toMap)

  /** Reconstruct a `Principal` from the denormalised `(actor_kind, actor_subject)` columns. We lose fidelity
    * here — the original `Principal.Agent` carries parent/purpose/allowedOps/jti which we don't round-trip
    * (those fields, if needed by audit consumers, live in the `context` JSONB under `agent.*` keys). For
    * `Agent` we synthesise a placeholder operator subject of `"unknown"`; readers who need the real chain
    * should query the context map.
    */
  private def principalFor(kind: String, subject: String): Principal = kind match
    case "Human"   => Principal.Human(subject, Set.empty)
    case "Service" => Principal.Service(subject, TenantId("audit-query"))
    case "Agent" =>
      Principal.Agent(
        subject = subject,
        operator = Principal.Human("unknown", Set.empty),
        purpose = "(reconstructed from audit row; see context map for original details)",
        issuedAt = Instant.EPOCH,
        ttl = scala.concurrent.duration.Duration.Zero,
        allowedOps = Set.empty,
        parent = None
      )
    case other => Principal.Service(subject, TenantId(s"unknown-kind=$other"))

  /** Decode the JSONB context column back into a `Map[String, String]`. Non-string values are dropped
    * (defensive — the writer always serialises strings, but if a future writer logs e.g. a number or array
    * we'd rather drop the entry than fail the whole query).
    */
  private def contextFromJson(json: Json): Map[String, String] =
    json.asObject
      .map(_.toMap.flatMap { case (k, v) => v.asString.map(k -> _) })
      .getOrElse(Map.empty)
