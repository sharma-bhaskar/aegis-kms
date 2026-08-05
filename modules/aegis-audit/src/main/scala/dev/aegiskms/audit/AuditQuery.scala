package dev.aegiskms.audit

import dev.aegiskms.core.Operation

import java.time.Instant

/** Query SPI for reading from a queryable audit sink — the read side of the audit pipeline.
  *
  * `AuditSink[F]` writes records; `AuditQuery[F]` reads them back with filter + pagination. Implementations
  * that support both (notably `PostgresAuditSink`) extend both traits; sinks that are write-only
  * (`StdoutAuditSink`, the future `SiemWebhookAuditSink`) implement only `AuditSink`. The HTTP audit-read
  * endpoint takes an `Option[AuditQuery[IO]]` and returns 501 NotImplemented when none is configured (mirrors
  * how `agentIssuer` is wired).
  *
  * Filters compose with AND (all supplied filters must match). The endpoint maps each filter to a column with
  * a backing index in `aegis_audit_events`, so even on a multi-million-row table the common filter
  * combinations are fast.
  *
  * Pagination is offset-based for v0.2.0. Cursor-based pagination is a later optimisation when we have a
  * customer pulling enough data to feel the cost of `LIMIT … OFFSET …` over deep pages.
  */
trait AuditQuery[F[_]]:
  def query(filter: AuditQuery.Filter): F[AuditQuery.Page]

  /** Most recent `occurred_at` per actor, for the given actors, restricted to activity at or after `since`.
    * Actors with no activity in the window are absent from the result rather than mapped to a sentinel.
    *
    * This exists because the alternative — one `query` per actor, or one broad `query` scanned client-side —
    * is either N+1 round-trips or silently wrong. A broad query is capped by [[MaxLimit]], so a busy agent
    * can push a quiet one's last activity off the page and the caller would under-report it as "never seen".
    * A `GROUP BY` answers it exactly in one round-trip against the existing `actor_subject` index.
    *
    * Used by the agent registry (#101) to fill in each agent's last-seen timestamp.
    */
  def lastActivityBy(actors: Set[String], since: Instant): F[Map[String, Instant]]

object AuditQuery:

  /** Hard-cap on the per-request page size. 1 000 is generous for an operator triage UI; SIEM exporters that
    * need more should poll incrementally rather than asking for one giant page.
    */
  val MaxLimit: Int = 1000

  /** Default page size when the client doesn't specify one. */
  val DefaultLimit: Int = 100

  /** All filters are optional; absent ones are not part of the WHERE clause. `limit` is clamped to `[1,
    * MaxLimit]` at the route layer, and `offset` is clamped to `[0, ∞)`.
    *
    *   - `since` / `until` — half-open interval on `occurred_at` (`since <= ts < until`).
    *   - `actor` — exact match on `actor_subject`. (Future: prefix match via a `LIKE` overload.)
    *   - `resource` — exact match on `resource` (e.g. `"key:abc-123"` or `"agent:agent-7a3"`).
    *   - `resourcePrefix` — prefix match on `resource` (e.g. `"agent:"` for every agent-scoped record).
    *     Combines with `resource` as AND, though supplying both is almost always a caller bug. Prefix
    *     matching keeps the `resource` btree index usable; an infix or suffix match would not, which is why
    *     only prefixes are offered.
    *   - `operation` — exact match on the KMIP `Operation` enum name (`Sign`, `Get`, …).
    */
  final case class Filter(
      since: Option[Instant] = None,
      until: Option[Instant] = None,
      actor: Option[String] = None,
      resource: Option[String] = None,
      resourcePrefix: Option[String] = None,
      operation: Option[Operation] = None,
      limit: Int = DefaultLimit,
      offset: Int = 0
  )

  /** Escape the LIKE metacharacters (`%`, `_`) and the escape character itself in a user-supplied prefix, so
    * `resourcePrefix = "agent:100%"` matches the literal string rather than acting as a wildcard.
    */
  def escapeLikePrefix(prefix: String): String =
    prefix.flatMap {
      case c @ ('%' | '_' | '\\') => s"\\$c"
      case c                      => c.toString
    }

  /** A page of audit records. `hasMore` is true iff there's at least one more matching record past the
    * current window — useful for "show more" UIs without forcing a separate COUNT query.
    */
  final case class Page(
      records: List[AuditRecord],
      limit: Int,
      offset: Int,
      hasMore: Boolean
  )
