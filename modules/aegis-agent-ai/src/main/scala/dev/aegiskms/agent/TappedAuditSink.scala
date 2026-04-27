package dev.aegiskms.agent

import cats.effect.IO
import cats.syntax.all.*
import dev.aegiskms.audit.{AuditRecord, AuditSink}

/** An `AuditSink` decorator that flows every record through a `BaselineDetector` and publishes any resulting
  * `AgentRecommendation`s to a `RecommendationSink`.
  *
  * Order: write to inner audit sink first, then observe in the detector, then publish recommendations. If the
  * inner write fails the audit record is the source of truth — the detector should never see a record the
  * audit log doesn't have. Recommendation publish failures are non-fatal: the detection has been logged via
  * the inner sink (assuming the detector emits its events into the audit log too in PR W1.b), so a failed
  * publish does not roll back the audit write.
  */
final class TappedAuditSink(
    inner: AuditSink[IO],
    detector: BaselineDetector,
    recommendations: RecommendationSink
) extends AuditSink[IO]:

  def write(record: AuditRecord): IO[Unit] =
    for
      _    <- inner.write(record)
      recs <- detector.observe(record)
      _    <- recs.traverse_(recommendations.publish)
    yield ()
