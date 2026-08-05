package dev.aegiskms.agent

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import dev.aegiskms.audit.InMemoryAuditSink
import dev.aegiskms.core.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import scala.concurrent.duration.*

/** Tests for `AutoResponseAction.KillAgentFleet` — automatic fleet-wide revocation (#102).
  *
  * This is the widest-blast-radius action in the system: one firing revokes every credential an operator
  * owns. The tests are weighted accordingly — most of them assert that it does **not** fire. The default
  * configuration, a missing kill-switch, and a non-agent actor must each result in nothing being revoked, and
  * each must say why in the audit trail rather than failing silently.
  */
final class AutoResponderKillFleetSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def agentActor(operator: Principal = alice): Principal.Agent =
    Principal.Agent(
      subject = "claude-session-7a3",
      operator = operator,
      purpose = "invoice-signing",
      issuedAt = Instant.parse("2026-05-01T10:00:00Z"),
      ttl = 1.hour,
      allowedOps = Set(Operation.Get, Operation.Sign),
      parent = None
    )

  private def rec(actor: Principal = agentActor()): AgentRecommendation =
    AgentRecommendation(
      eventId = java.util.UUID.randomUUID().toString,
      at = Instant.parse("2026-05-01T10:30:00Z"),
      actor = actor,
      detector = "RateSpike",
      severity = Severity.High,
      summary = "rate spike",
      details = Map("resource" -> "key:invoice-2026"),
      suggestedAction = SuggestedAction.Alert
    )

  /** Records the sweeps it was asked to perform; never revokes anything. */
  final private class SpyKillSwitch extends AgentKillSwitch:
    val sweeps = scala.collection.mutable.ListBuffer[KillSwitchRequest]()

    def revokeAll(
        caller: Principal,
        request: KillSwitchRequest
    ): IO[Either[KmsError, KillSwitchResult]] =
      IO {
        sweeps += request
        Right(KillSwitchResult(request.parent, List(KilledAgent("agent-1", "l", Instant.EPOCH)), 0, 0))
      }

  private val killFleetRule =
    List(AutoResponseRule("RateSpike", Severity.High, AutoResponseAction.KillAgentFleet))

  private def responderWith(
      killSwitch: Option[AgentKillSwitch],
      rules: List[AutoResponseRule] = killFleetRule
  ): (AutoResponder, InMemoryAuditSink) =
    val sink = InMemoryAuditSink.make.unsafeRunSync()
    val responder = AutoResponder.make(
      rules = rules,
      inner = InMemoryRecommendationSink.make.unsafeRunSync(),
      keyService = KeyService.inMemory.unsafeRunSync(),
      auditSink = sink,
      killSwitch = killSwitch
    ).unsafeRunSync()
    (responder, sink)

  private def killFleetAudit(sink: InMemoryAuditSink) =
    sink.all.unsafeRunSync().filter(_.outcome.contains("KillAgentFleet"))

  // ── It must not fire ──────────────────────────────────────────────────────

  test("KillAgentFleet is absent from the default rules — an operator must opt in explicitly") {
    AutoResponder.DefaultRules.map(_.action) should not contain AutoResponseAction.KillAgentFleet
  }

  test("with no kill-switch wired, nothing is revoked and the audit row says why") {
    val (responder, sink) = responderWith(killSwitch = None)

    responder.publish(rec()).unsafeRunSync()

    val rows = killFleetAudit(sink)
    rows should have size 1
    rows.head.outcome should include("Failed")
    rows.head.outcome should include("kill-fleet not enabled")
  }

  test("a human actor has no fleet to sweep and is refused") {
    val ks                = new SpyKillSwitch
    val (responder, sink) = responderWith(Some(ks))

    responder.publish(rec(actor = alice)).unsafeRunSync()

    ks.sweeps shouldBe empty
    killFleetAudit(sink).head.outcome should include("only applies to agent actors")
  }

  test("a service actor has no fleet to sweep and is refused") {
    val ks                = new SpyKillSwitch
    val (responder, sink) = responderWith(Some(ks))
    val service           = Principal.Service("ci-runner", TenantId("acme"))

    responder.publish(rec(actor = service)).unsafeRunSync()

    ks.sweeps shouldBe empty
    killFleetAudit(sink).head.outcome should include("only applies to agent actors")
  }

  test("a recommendation with no matching rule never reaches the kill-switch") {
    val ks             = new SpyKillSwitch
    val (responder, _) = responderWith(Some(ks), rules = Nil)

    responder.publish(rec()).unsafeRunSync()

    ks.sweeps shouldBe empty
  }

  test("a Medium-severity spike does not trip a High-severity kill-fleet rule") {
    val ks             = new SpyKillSwitch
    val (responder, _) = responderWith(Some(ks))

    responder.publish(rec().copy(severity = Severity.Medium)).unsafeRunSync()

    ks.sweeps shouldBe empty
  }

  // ── It fires correctly when it should ─────────────────────────────────────

  test("an agent actor sweeps its parent operator's fleet, not its own subject") {
    val ks             = new SpyKillSwitch
    val (responder, _) = responderWith(Some(ks))

    responder.publish(rec()).unsafeRunSync()

    ks.sweeps.map(_.parent).toList shouldBe List("alice@org")
  }

  test("the sweep is unbounded in time — an incident kills the whole live fleet") {
    val ks             = new SpyKillSwitch
    val (responder, _) = responderWith(Some(ks))

    responder.publish(rec()).unsafeRunSync()

    ks.sweeps.head.issuedAfter shouldBe None
  }

  test("a successful sweep is audited with the count it killed") {
    val ks                = new SpyKillSwitch
    val (responder, sink) = responderWith(Some(ks))

    responder.publish(rec()).unsafeRunSync()

    val row = killFleetAudit(sink).head
    row.outcome should include("Success")
    row.outcome should include("killed=1")
    row.operation shouldBe Operation.Revoke
  }

  test("the audit row names the system principal, so a fleet wipe is attributable to automation") {
    val ks                = new SpyKillSwitch
    val (responder, sink) = responderWith(Some(ks))

    responder.publish(rec()).unsafeRunSync()

    killFleetAudit(sink).head.principal shouldBe AutoResponder.SystemPrincipal
  }

  test("the cooldown stops a burst of anomalies from sweeping the same fleet repeatedly") {
    val ks             = new SpyKillSwitch
    val (responder, _) = responderWith(Some(ks))

    (1 to 5).foreach(_ => responder.publish(rec()).unsafeRunSync())

    ks.sweeps should have size 1
  }

  test("a kill-switch failure is captured in the audit row rather than thrown") {
    val failing = new AgentKillSwitch:
      def revokeAll(
          caller: Principal,
          request: KillSwitchRequest
      ): IO[Either[KmsError, KillSwitchResult]] =
        IO.pure(Left(KmsError(ErrorCode.GeneralFailure, "revocation store unreachable")))

    val (responder, sink) = responderWith(Some(failing))

    noException should be thrownBy responder.publish(rec()).unsafeRunSync()
    killFleetAudit(sink).head.outcome should include("kill-switch failed")
  }
