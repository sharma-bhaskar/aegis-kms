package dev.aegiskms.audit

import cats.effect.IO
import org.slf4j.LoggerFactory

/** Compose one primary sink with N best-effort secondaries.
  *
  * Asymmetric semantics by design:
  *   - The **primary** sink is the durable one (typically `PostgresAuditSink` or `StdoutAuditSink`). Its
  *     failures propagate to the caller so the originating KMS operation fails with a clear error and can be
  *     retried — this is what makes the audit trail crash-safe under the contract documented in
  *     `AuditingKeyService`.
  *   - **Secondary** sinks are best-effort fan-out (typically `WebhookAuditSink` to a SIEM). Their failures
  *     are logged at WARN and swallowed so a downed SIEM cannot stall the request path. The webhook sink owns
  *     its own queue + retry + dead-letter strategy; from `FanOutAuditSink`'s perspective each secondary
  *     `write` is fire-and-forget.
  *
  * Use [[FanOutAuditSink.of]] to construct — the convenience method enforces that at least one sink is
  * provided (an empty fan-out is almost certainly a bug, not a feature).
  */
final class FanOutAuditSink(
    primary: AuditSink[IO],
    secondaries: List[AuditSink[IO]]
) extends AuditSink[IO]:

  private val logger = LoggerFactory.getLogger(getClass)

  def write(record: AuditRecord): IO[Unit] =
    for
      _ <- primary.write(record)
      _ <- secondaries.traverse_(s => writeSecondary(s, record))
    yield ()

  private def writeSecondary(sink: AuditSink[IO], record: AuditRecord): IO[Unit] =
    sink.write(record).handleErrorWith { t =>
      IO {
        logger.warn(
          s"audit fan-out: secondary sink ${sink.getClass.getSimpleName} failed " +
            s"(correlationId=${record.correlationId}, op=${record.operation}): ${t.getMessage}",
          t
        )
      }
    }

  // Hand-written `traverse_` over the `secondaries` list to avoid pulling in `cats.syntax.all.*` just
  // for this one call site. Sequential by construction — webhook sinks must observe records in the
  // order the underlying KeyService emitted them, so a downstream SIEM can join on `correlationId`
  // without re-sorting.
  extension (xs: List[AuditSink[IO]])
    private def traverse_(f: AuditSink[IO] => IO[Unit]): IO[Unit] =
      xs.foldLeft(IO.unit)((acc, s) => acc *> f(s))

object FanOutAuditSink:

  /** Pass-through when the secondaries list is empty (no fan-out configured — return the primary as-is so the
    * boot composition can branch on a single config check without wrapping unconditionally).
    */
  def of(primary: AuditSink[IO], secondaries: List[AuditSink[IO]]): AuditSink[IO] =
    if secondaries.isEmpty then primary
    else new FanOutAuditSink(primary, secondaries)
