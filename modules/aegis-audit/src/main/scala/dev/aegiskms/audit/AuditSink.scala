package dev.aegiskms.audit

import dev.aegiskms.core.{Operation, Principal}

import java.time.Instant

/** A single audit record. Append-only; the sink must never offer a mutation API. Writing must be crash-safe
  * before the originating operation is acknowledged to the client.
  *
  * `context` is a free-form bag of per-request metadata (source IP, user agent, request id, MCP session id,
  * KMIP correlation id, ...). It's additive with a default of `Map.empty` so older callers compile unchanged;
  * downstream consumers (the `BaselineDetector`'s SourceIp baseline, the SIEM webhook fan-out planned for
  * v0.2.0) read specific keys from it. The well-known keys live alongside their producers — `"source.ip"` is
  * set by the HTTP layer when the v0.1.x request-context plumbing PR lands.
  */
final case class AuditRecord(
    at: Instant,
    principal: Principal,
    operation: Operation,
    resource: String,
    outcome: String,
    correlationId: String,
    context: Map[String, String] = Map.empty
)

/** SPI for an audit-record sink. Bundled implementations: Postgres (via `aegis-persistence`) and
  * standard-out. Community backends expected: Kafka, S3 object store, OpenTelemetry logs.
  */
trait AuditSink[F[_]]:
  def write(record: AuditRecord): F[Unit]
