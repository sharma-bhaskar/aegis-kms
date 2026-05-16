package dev.aegiskms.agent

import cats.effect.unsafe.implicits.global
import dev.aegiskms.audit.AuditRecord
import dev.aegiskms.core.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import scala.concurrent.duration.*

/** Tests for `BaselineRiskScorer` — the W2 risk-scoring SPI.
  *
  * The two big properties exercised here:
  *
  *   1. Cold-start humans on a routine op produce `RiskScore.Zero`. We never want the demo to falsely alert
  *      on the very first request from a brand-new actor. 2. The "Claude goes rogue" composite (agent + new
  *      key + new hour + destructive op + old credential) produces a high score with reasoning the demo can
  *      show.
  */
final class BaselineRiskScorerSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def agent(issuedAt: Instant, ttl: scala.concurrent.duration.FiniteDuration = 1.hour) =
    Principal.Agent(
      subject = "claude-session-7a3",
      operator = alice,
      purpose = "invoice-signing",
      issuedAt = issuedAt,
      ttl = ttl,
      allowedOps = Set(Operation.Get, Operation.Sign),
      parent = None
    )

  private def rec(
      at: Instant,
      principal: Principal,
      op: Operation,
      key: String,
      ctx: Map[String, String] = Map.empty
  ) =
    AuditRecord(
      at = at,
      principal = principal,
      operation = op,
      resource = s"key:$key",
      outcome = "Success",
      correlationId = java.util.UUID.randomUUID().toString,
      context = ctx
    )

  // Establish a tiny baseline (one Get on `invoice-2026` from IP 10.0.0.1 at hour 10 UTC).
  private def primeBaseline(det: BaselineDetector, p: Principal): Unit =
    det.observe(rec(
      at = Instant.parse("2026-04-25T10:00:00Z"),
      principal = p,
      op = Operation.Get,
      key = "invoice-2026",
      ctx = Map(BaselineDetector.SourceIpContextKey -> "10.0.0.1")
    )).unsafeRunSync()
    ()

  test("cold-start human on a routine op scores 0.0 with no factors") {
    val det    = BaselineDetector.make().unsafeRunSync()
    val scorer = BaselineRiskScorer.make(det)
    val req = RiskScorer.Request(
      principal = alice,
      operation = Operation.Get,
      keyId = Some(KeyId.fromString("invoice-2026").toOption.get),
      at = Instant.parse("2026-04-25T10:00:00Z")
    )
    val score = scorer.score(req).unsafeRunSync()
    score.value shouldBe 0.0
    score.factors shouldBe empty
  }

  test("known human touching a NEW key fires ScopeBaseline") {
    val det = BaselineDetector.make().unsafeRunSync()
    primeBaseline(det, alice)
    val scorer = BaselineRiskScorer.make(det)
    val req = RiskScorer.Request(
      principal = alice,
      operation = Operation.Get,
      keyId = Some(KeyId.fromString("paystubs-2026").toOption.get), // not in baseline
      at = Instant.parse("2026-04-25T10:05:00Z"),
      context = Map(BaselineDetector.SourceIpContextKey -> "10.0.0.1") // same IP
    )
    val score = scorer.score(req).unsafeRunSync()
    score.factors.map(_.name) should contain("ScopeBaseline")
    score.value should be > 0.0
  }

  test("agent on a destructive op gets agent + destructive contextual factors") {
    val det    = BaselineDetector.make().unsafeRunSync()
    val ag     = agent(Instant.parse("2026-04-25T10:00:00Z"))
    val scorer = BaselineRiskScorer.make(det)
    val req = RiskScorer.Request(
      principal = ag,
      operation = Operation.Destroy,
      keyId = Some(KeyId.fromString("invoice-2026").toOption.get),
      at = Instant.parse("2026-04-25T10:05:00Z")
    )
    val score = scorer.score(req).unsafeRunSync()
    val names = score.factors.map(_.name).toSet
    names should contain allOf ("AgentPrincipal", "DestructiveOp")
  }

  test("agent past 80% of TTL fires CredentialAge") {
    val det    = BaselineDetector.make().unsafeRunSync()
    val ag     = agent(issuedAt = Instant.parse("2026-04-25T10:00:00Z"), ttl = 1.hour)
    val scorer = BaselineRiskScorer.make(det)
    val req = RiskScorer.Request(
      principal = ag,
      operation = Operation.Get,
      keyId = Some(KeyId.fromString("invoice-2026").toOption.get),
      at = Instant.parse("2026-04-25T10:55:00Z") // 91% of TTL elapsed
    )
    val score = scorer.score(req).unsafeRunSync()
    score.factors.map(_.name) should contain("CredentialAge")
  }

  test("the demo composite (agent + new key + new IP + destructive + old credential) scores high") {
    val det = BaselineDetector.make().unsafeRunSync()
    val ag  = agent(issuedAt = Instant.parse("2026-04-25T10:00:00Z"), ttl = 1.hour)
    // Prime baseline: agent has done Get from 10.0.0.1 on invoice-2026 at hour 10.
    det.observe(rec(
      at = Instant.parse("2026-04-25T10:01:00Z"),
      principal = ag,
      op = Operation.Get,
      key = "invoice-2026",
      ctx = Map(BaselineDetector.SourceIpContextKey -> "10.0.0.1")
    )).unsafeRunSync()

    val scorer = BaselineRiskScorer.make(det)
    val req = RiskScorer.Request(
      principal = ag,
      operation = Operation.Rotate,                                 // destructive, never done
      keyId = Some(KeyId.fromString("paystubs-2026").toOption.get), // not in baseline
      at = Instant.parse("2026-04-25T10:55:00Z"),                   // past 80% TTL
      context = Map(BaselineDetector.SourceIpContextKey -> "203.0.113.42") // new IP
    )
    val score = scorer.score(req).unsafeRunSync()
    val names = score.factors.map(_.name).toSet
    names should contain allOf (
      "ScopeBaseline",
      "OpHistogramBaseline",
      "SourceIpBaseline",
      "AgentPrincipal",
      "CredentialAge",
      "DestructiveOp"
    )
    score.value should be >= 0.7
    score.value should be <= 1.0 // clamped
  }

  test("renderedScore is fixed to 2 decimal places") {
    val s = RiskScore(0.6234567, Nil)
    s.renderedScore shouldBe "0.62"
  }

  test("renderedFactors is a semicolon-separated name:weight list") {
    val s = RiskScore(
      0.5,
      List(
        RiskFactor("A", 0.3, "first"),
        RiskFactor("B", 0.2, "second")
      )
    )
    s.renderedFactors shouldBe "A:0.3;B:0.2"
  }

  test("RiskScore.fromFactors clamps to [0, 1]") {
    val s = RiskScore.fromFactors(List(
      RiskFactor("A", 0.7, ""),
      RiskFactor("B", 0.6, "")
    ))
    s.value shouldBe 1.0
  }

  test("RateSpike fires when the actor exceeds the burst threshold inside the burst window") {
    val det    = BaselineDetector.make().unsafeRunSync()
    val baseTs = Instant.parse("2026-04-25T10:00:00Z")
    // Prime: 30 Gets on the same key, IP, and hour — 1 per second through baseTs..baseTs+29s.
    // This puts all 30 inside the default 60s burst window when we score at baseTs+30s.
    (0 until 30).foreach { i =>
      det.observe(rec(
        at = baseTs.plusSeconds(i.toLong),
        principal = alice,
        op = Operation.Get,
        key = "invoice-2026",
        ctx = Map(BaselineDetector.SourceIpContextKey -> "10.0.0.1")
      )).unsafeRunSync()
    }

    val scorer = BaselineRiskScorer.make(det)
    val req = RiskScorer.Request(
      principal = alice,
      operation = Operation.Get,                                   // not a new op
      keyId = Some(KeyId.fromString("invoice-2026").toOption.get), // not a new key
      at = baseTs.plusSeconds(30),                                 // hour 10, same baseline
      context = Map(BaselineDetector.SourceIpContextKey -> "10.0.0.1") // same IP
    )
    val score = scorer.score(req).unsafeRunSync()

    val rateFactor = score.factors.find(_.name == "RateSpike")
    rateFactor shouldBe defined
    rateFactor.get.weight should be > 0.0
    rateFactor.get.weight should be <= 0.40 // capped at rateMax
    // Only RateSpike should have fired — the other dimensions are unchanged.
    score.factors.map(_.name).toSet shouldBe Set("RateSpike")
  }

  test("RateSpike at 3× burst saturates at rateMax (0.40 default)") {
    val det    = BaselineDetector.make().unsafeRunSync()
    val baseTs = Instant.parse("2026-04-25T10:00:00Z")
    // 90 requests in 60s = 3× the default threshold of 30. Per the scorer formula
    // `min(rateMax, rateMax * (factor/3.0))`, factor=3.0 → scaledWeight = rateMax = 0.40.
    (0 until 90).foreach { i =>
      det.observe(rec(
        at = baseTs.plusMillis(i.toLong * 666), // ~666ms apart so all 90 fit in 60s
        principal = alice,
        op = Operation.Get,
        key = "invoice-2026",
        ctx = Map(BaselineDetector.SourceIpContextKey -> "10.0.0.1")
      )).unsafeRunSync()
    }

    val scorer = BaselineRiskScorer.make(det)
    val req = RiskScorer.Request(
      principal = alice,
      operation = Operation.Get,
      keyId = Some(KeyId.fromString("invoice-2026").toOption.get),
      at = baseTs.plusSeconds(60),
      context = Map(BaselineDetector.SourceIpContextKey -> "10.0.0.1")
    )
    val score      = scorer.score(req).unsafeRunSync()
    val rateFactor = score.factors.find(_.name == "RateSpike").get
    rateFactor.weight shouldBe 0.40 +- 1e-9
  }

  test("TimeOfDayBaseline fires when actor is active in a UTC hour outside their seen set") {
    val det = BaselineDetector.make().unsafeRunSync()
    // Prime baseline: alice has only ever been active at UTC hour 10.
    det.observe(rec(
      at = Instant.parse("2026-04-25T10:00:00Z"),
      principal = alice,
      op = Operation.Get,
      key = "invoice-2026",
      ctx = Map(BaselineDetector.SourceIpContextKey -> "10.0.0.1")
    )).unsafeRunSync()

    val scorer = BaselineRiskScorer.make(det)
    val req = RiskScorer.Request(
      principal = alice,
      operation = Operation.Get,                                   // not a new op
      keyId = Some(KeyId.fromString("invoice-2026").toOption.get), // not a new key
      // Next day at 03:00 UTC — hour 3 is not in {10}. Same key & IP so only TimeOfDay fires.
      at = Instant.parse("2026-04-26T03:00:00Z"),
      context = Map(BaselineDetector.SourceIpContextKey -> "10.0.0.1")
    )
    val score = scorer.score(req).unsafeRunSync()

    score.factors.map(_.name) should contain("TimeOfDayBaseline")
    val todFactor = score.factors.find(_.name == "TimeOfDayBaseline").get
    todFactor.weight shouldBe 0.20 +- 1e-9
    todFactor.evidence should include("hour 3")
  }
