package dev.aegiskms.audit

import dev.aegiskms.core.{Operation, Principal}

import java.time.Instant

/** A single audit record. Append-only; the sink must never offer a mutation API. Writing must be crash-safe
  * before the originating operation is acknowledged to the client.
  */
final case class AuditRecord(
    at: Instant,
    principal: Principal,
    operation: Operation,
    resource: String,
    outcome: String,
    correlationId: String
)

/** SPI for an audit-record sink. Bundled implementations: Postgres (via `aegis-persistence`) and
  * standard-out. Community backends expected: Kafka, S3 object store, OpenTelemetry logs.
  */
trait AuditSink[F[_]]:
  def write(record: AuditRecord): F[Unit]
