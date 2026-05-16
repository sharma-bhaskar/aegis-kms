package dev.aegiskms.agent

import cats.effect.unsafe.implicits.global
import dev.aegiskms.core.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Tests for `ThresholdDecisionEngine` — the W2.b risk decision adapter.
  *
  * The properties exercised here pin the wedge demo's blast radius: a low score on a routine op must Allow
  * (no false positives); a composite high-risk score must Deny (no missed alerts); destructive ops step up
  * earlier than read-only ones (irreversibility tax).
  */
final class ThresholdDecisionEngineSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def factor(name: String, weight: Double): RiskFactor =
    RiskFactor(name, weight, s"$name fired")

  private val engine = ThresholdDecisionEngine.make()

  test("Allow when score is below stepUpAt (default 0.60)") {
    val score = RiskScore(0.30, List(factor("AgentPrincipal", 0.20), factor("DestructiveOp", 0.10)))
    val d     = engine.decide(score, alice, Operation.Get).unsafeRunSync()
    d shouldBe Decision.Allow
  }

  test("StepUp when score is between stepUpAt and denyAt (default [0.60, 0.85))") {
    val score = RiskScore(0.70, List(factor("ScopeBaseline", 0.50), factor("AgentPrincipal", 0.20)))
    val d     = engine.decide(score, alice, Operation.Get).unsafeRunSync()
    d shouldBe a[Decision.StepUpRequired]
    d.asInstanceOf[Decision.StepUpRequired].reason should include("threshold=0.60")
    d.asInstanceOf[Decision.StepUpRequired].reason should include("ScopeBaseline:0.5")
  }

  test("Deny when score is at or above denyAt (default 0.85)") {
    val score = RiskScore(0.90, List(factor("ScopeBaseline", 0.50), factor("RateSpike", 0.40)))
    val d     = engine.decide(score, alice, Operation.Get).unsafeRunSync()
    d shouldBe a[Decision.Deny]
    d.asInstanceOf[Decision.Deny].reason should include("threshold=0.85")
  }

  test("destructive ops trip step-up earlier than read-only ones") {
    // Score 0.50 is below the default stepUpAt of 0.60 — for Get it Allows.
    val score = RiskScore(0.50, List(factor("AgentPrincipal", 0.20), factor("ScopeBaseline", 0.30)))
    engine.decide(score, alice, Operation.Get).unsafeRunSync() shouldBe Decision.Allow
    // But for Destroy (a DestructiveOp) the threshold drops by 0.15 → effective stepUpAt = 0.45.
    val onDestroy = engine.decide(score, alice, Operation.Destroy).unsafeRunSync()
    onDestroy shouldBe a[Decision.StepUpRequired]
  }

  test("destructive ops trip deny earlier than read-only ones") {
    // Score 0.72 is below denyAt 0.85 for Get (StepUp), but above the destructive-adjusted denyAt of 0.70.
    val score = RiskScore(0.72, List(factor("ScopeBaseline", 0.50), factor("RateSpike", 0.22)))
    engine.decide(score, alice, Operation.Get).unsafeRunSync() shouldBe a[Decision.StepUpRequired]
    engine.decide(score, alice, Operation.Rotate).unsafeRunSync() shouldBe a[Decision.Deny]
  }

  test("Thresholds requires denyAt >= stepUpAt") {
    an[IllegalArgumentException] should be thrownBy
      ThresholdDecisionEngine.Thresholds(denyAt = 0.3, stepUpAt = 0.5)
  }

  test("Thresholds requires non-negative destructiveOpOffset") {
    an[IllegalArgumentException] should be thrownBy
      ThresholdDecisionEngine.Thresholds(destructiveOpOffset = -0.1)
  }

  test("reason string carries the rendered factor list for operator readability") {
    val score = RiskScore(
      0.70,
      List(factor("ScopeBaseline", 0.50), factor("AgentPrincipal", 0.20))
    )
    val d = engine.decide(score, alice, Operation.Get).unsafeRunSync()
    d.asInstanceOf[Decision.StepUpRequired].reason should include(
      "factors=ScopeBaseline:0.5;AgentPrincipal:0.2"
    )
  }

  test("custom thresholds override defaults") {
    val strict = ThresholdDecisionEngine.make(
      ThresholdDecisionEngine.Thresholds(denyAt = 0.50, stepUpAt = 0.20, destructiveOpOffset = 0.0)
    )
    val score = RiskScore(0.30, List(factor("AgentPrincipal", 0.20), factor("BroadScope", 0.10)))
    strict.decide(score, alice, Operation.Get).unsafeRunSync() shouldBe a[Decision.StepUpRequired]
  }
