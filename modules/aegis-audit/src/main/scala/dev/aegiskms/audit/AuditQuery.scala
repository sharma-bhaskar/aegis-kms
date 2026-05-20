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
    *   - `operation` — exact match on the KMIP `Operation` enum name (`Sign`, `Get`, …).
    */
  final case class Filter(
      since: Option[Instant] = None,
      until: Option[Instant] = None,
      actor: Option[String] = None,
      resource: Option[String] = None,
      operation: Option[Operation] = None,
      limit: Int = DefaultLimit,
      offset: Int = 0
  )

  /** A page of audit records. `hasMore` is true iff there's at least one more matching record past the
    * current window — useful for "show more" UIs without forcing a separate COUNT query.
    */
  final case class Page(
      records: List[AuditRecord],
      limit: Int,
      offset: Int,
      hasMore: Boolean
  )
