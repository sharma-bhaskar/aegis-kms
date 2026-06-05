package dev.aegiskms.app

import cats.effect.unsafe.IORuntime
import dev.aegiskms.agent.{
  AutoResponder,
  BaselineDetector,
  HoneyKeyRegistry,
  InMemoryRecommendationSink,
  Severity,
  TappedAuditSink
}
import dev.aegiskms.audit.{AuditingKeyService, InMemoryAuditSink}
import dev.aegiskms.core.*
import dev.aegiskms.iam.AuthorizingKeyService
import dev.aegiskms.persistence.EventJournal
import org.apache.pekko.actor.testkit.typed.scaladsl.ScalaTestWithActorTestKit
import org.apache.pekko.util.Timeout
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpecLike

import java.time.Instant
import scala.concurrent.duration.*

/** End-to-end test for the flagship "rogue agent → auto-revoke" wedge (UC-1 in docs/USE-CASES.md).
  *
  * The individual pieces are unit-tested elsewhere (`BaselineDetectorSpec` for honey-key detection,
  * `AutoResponderSpec` for High → Revoke). This spec proves they compose: an *agent* touching a honey key
  * produces a High-severity `HoneyKey` recommendation, which the auto-responder turns into a real `revoke` on
  * the assembled stack — so the key ends up `Deactivated` and the agent's next signing attempt is refused on
  * the key's state.
  *
  * It also pins the honest v0.2.0 boundary: the auto-responder revokes the **key**, not the agent's JWT. JTI
  * auto-revoke is deferred to #24; this test asserts the key-state outcome, not a 401.
  */
final class HoneyKeyAutoRevokeE2ESpec extends ScalaTestWithActorTestKit with AnyWordSpecLike with Matchers:

  private given IORuntime = IORuntime.global
  private given Timeout   = 5.seconds

  private val alice: Principal = Principal.Human("alice@org", Set.empty)

  private def invoiceBot(): Principal.Agent = Principal.Agent(
    subject = "invoice-bot",
    operator = alice,
    purpose = "invoice-signing",
    issuedAt = Instant.parse("2026-05-31T10:00:00Z"),
    ttl = 1.hour,
    allowedOps = Set(Operation.Get, Operation.Sign),
    parent = None
  )

  "Honey-key auto-revoke (UC-1)" should {

    "revoke the key when an agent touches a honey-listed key, and refuse the agent's next op" in {
      // ── Assemble the lower stack (no detector yet) so we can create + activate the canary first. ──
      val journal     = EventJournal.inMemory.unsafeRunSync()
      val keyOpsActor = spawn(KeyOpsActor.behavior(journal, replayed = Nil))
      val actorBacked = new ActorBackedKeyService(keyOpsActor)(using summon[Timeout], system.scheduler)
      val authorizing = new AuthorizingKeyService(actorBacked, new DevPolicyEngine)

      val created = authorizing.create(KeySpec.rsa2048("prod-signing-canary"), alice).unsafeRunSync()
      val honeyId = created.toOption.get.id
      authorizing.activate(honeyId, alice).unsafeRunSync()

      // ── Register the canary and wire detector → auto-responder → audit around the SAME actor. ──
      val recStore  = InMemoryRecommendationSink.make.unsafeRunSync()
      val innerSink = InMemoryAuditSink.make.unsafeRunSync()
      val detector = BaselineDetector.make(honeyKeys = HoneyKeyRegistry.fromSet(Set(honeyId))).unsafeRunSync()
      val responder = AutoResponder
        .make(
          rules = AutoResponder.DefaultRules,
          inner = recStore,
          keyService =
            authorizing, // revoke runs as AutoResponder.SystemPrincipal (a Service → allowed by DevPolicyEngine)
          auditSink = innerSink
        )
        .unsafeRunSync()
      val tapped   = TappedAuditSink(innerSink, detector, responder)
      val auditing = new AuditingKeyService(authorizing, tapped)

      val msg = "approve invoice 0042".getBytes("UTF-8")

      // ── The agent touches the honey key. The sign itself succeeds (key is Active)… ──
      val firstSign = auditing.sign(honeyId, msg, SigAlgorithm.RsaPssSha256, invoiceBot()).unsafeRunSync()
      firstSign.isRight shouldBe true

      // …but writing that audit record runs the detector, which fires HoneyKey/High, which the
      // auto-responder turns into a revoke — synchronously, inside the same audit write.
      val recs = recStore.all.unsafeRunSync()
      recs.exists(r => r.detector == "HoneyKey" && r.severity == Severity.High) shouldBe true

      // The key is now Deactivated (revoke → Deactivated; there is no separate Revoked state).
      val afterState = actorBacked.get(honeyId, alice).unsafeRunSync().toOption.get.state
      afterState shouldBe KeyState.Deactivated

      // The agent's NEXT sign is refused on the key's state (sign requires Active), not on the token.
      val secondSign = auditing.sign(honeyId, msg, SigAlgorithm.RsaPssSha256, invoiceBot()).unsafeRunSync()
      secondSign.isLeft shouldBe true
      secondSign.swap.toOption.get.code shouldBe ErrorCode.IllegalOperation

      // The auto-response itself is audited under the system principal so operators can grep the timeline.
      val auditRows = innerSink.all.unsafeRunSync()
      auditRows.exists(r =>
        r.principal == AutoResponder.SystemPrincipal && r.operation == Operation.Revoke
      ) shouldBe true
    }
  }
