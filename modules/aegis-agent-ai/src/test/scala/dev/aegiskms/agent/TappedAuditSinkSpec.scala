package dev.aegiskms.agent

import cats.effect.unsafe.implicits.global
import dev.aegiskms.audit.{AuditRecord, InMemoryAuditSink}
import dev.aegiskms.core.{Operation, Principal}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import scala.concurrent.duration.*

/** End-to-end test for the W1 anomaly path: every audit record flows through the inner sink AND through the
  * detector, and the detector's recommendations land in a `RecommendationSink`.
  *
  * This is the test that validates the README's "Claude goes rogue" demo: scope baseline established, then
  * the rogue call produces a High-severity Revoke recommendation while still being recorded in audit.
  */
final class TappedAuditSinkSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private val claude: Principal = Principal.Agent(
    subject = "claude-session-7a3",
    operator = alice,
    purpose = "invoice-signing",
    issuedAt = Instant.parse("2026-04-25T02:55:00Z"),
    ttl = 1.hour,
    allowedOps = Set(Operation.Get),
    parent = None
  )

  test("every audit record reaches the inner sink AND the detector") {
    val auditSink = InMemoryAuditSink.make.unsafeRunSync()
    val recSink   = InMemoryRecommendationSink.make.unsafeRunSync()
    val detector  = BaselineDetector.make().unsafeRunSync()
    val tap       = TappedAuditSink(auditSink, detector, recSink)

    val baseTs = Instant.parse("2026-04-25T03:00:00Z")
    val rec1 = AuditRecord(baseTs, claude, Operation.Get, "key:invoice-2026", "Success", "c1")
    val rec2 = AuditRecord(baseTs.plusSeconds(60), claude, Operation.Get, "key:treasury-master", "Failed code=PermissionDenied", "c2")

    tap.write(rec1).unsafeRunSync()
    tap.write(rec2).unsafeRunSync()

    auditSink.all.unsafeRunSync().size shouldBe 2
    val recs = recSink.all.unsafeRunSync()
    recs.exists(r => r.detector == "ScopeBaseline" && r.severity == Severity.High) shouldBe true
    recs.find(_.detector == "ScopeBaseline").get.suggestedAction shouldBe SuggestedAction.Revoke
  }

  test("recommendations carry the full Agent identity so consumers can trace back to the parent human") {
    val auditSink = InMemoryAuditSink.make.unsafeRunSync()
    val recSink   = InMemoryRecommendationSink.make.unsafeRunSync()
    val detector  = BaselineDetector.make().unsafeRunSync()
    val tap       = TappedAuditSink(auditSink, detector, recSink)

    val baseTs = Instant.parse("2026-04-25T03:00:00Z")
    tap.write(AuditRecord(baseTs, claude, Operation.Get, "key:invoice-2026", "Success", "c1")).unsafeRunSync()
    tap.write(AuditRecord(baseTs.plusSeconds(1), claude, Operation.Get, "key:treasury-master", "Failed", "c2")).unsafeRunSync()

    val rec = recSink.all.unsafeRunSync().find(_.detector == "ScopeBaseline").get
    rec.actor match
      case Principal.Agent(_, parent, _, _, _, _, _) =>
        parent.subject shouldBe "alice@org"
      case other => fail(s"expected Agent principal, got $other")
  }
