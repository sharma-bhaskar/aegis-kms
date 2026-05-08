package dev.aegiskms.agent

import cats.effect.unsafe.implicits.global
import dev.aegiskms.audit.AuditRecord
import dev.aegiskms.core.{Operation, Principal}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.{Duration, Instant}
import scala.concurrent.duration.*

/** Tests for `BaselineDetector` — the W1 anomaly engine.
  *
  * The most important property is the "Claude goes rogue" path from the README: an Agent principal touching a
  * key it has never touched before produces a High-severity ScopeBaseline recommendation with suggested
  * action Revoke.
  */
final class BaselineDetectorSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def agent(parent: Principal): Principal.Agent =
    Principal.Agent(
      subject = "claude-session-7a3",
      operator = parent,
      purpose = "invoice-signing",
      issuedAt = Instant.parse("2026-04-25T02:55:00Z"),
      ttl = 1.hour,
      allowedOps = Set(Operation.Create, Operation.Get),
      parent = None
    )

  private def rec(at: Instant, principal: Principal, op: Operation, key: String, outcome: String) =
    AuditRecord(
      at = at,
      principal = principal,
      operation = op,
      resource = s"key:$key",
      outcome = outcome,
      correlationId = java.util.UUID.randomUUID().toString
    )

  test("first observation establishes baseline; no recommendation emitted") {
    val det  = BaselineDetector.make().unsafeRunSync()
    val r    = rec(Instant.parse("2026-04-25T02:55:01Z"), alice, Operation.Create, "invoice-2026", "Success")
    val recs = det.observe(r).unsafeRunSync()
    recs shouldBe Nil
  }

  test("Agent touching a key not in its baseline emits a High-severity ScopeBaseline rec with Revoke") {
    val det = BaselineDetector.make().unsafeRunSync()
    val ag  = agent(alice)

    // Establish baseline: 5 ops on invoice-2026.
    val baseTs = Instant.parse("2026-04-25T03:00:00Z")
    (0 until 5).foreach { i =>
      val r = rec(baseTs.plusSeconds(i.toLong), ag, Operation.Get, "invoice-2026", "Success")
      det.observe(r).unsafeRunSync()
    }

    // The new key triggers ScopeBaseline.
    val rogue =
      rec(baseTs.plusSeconds(60), ag, Operation.Get, "treasury-master", "Failed code=PermissionDenied")
    val recs = det.observe(rogue).unsafeRunSync()

    recs.size shouldBe 1
    recs.head.detector shouldBe "ScopeBaseline"
    recs.head.severity shouldBe Severity.High
    recs.head.suggestedAction shouldBe SuggestedAction.Revoke
    recs.head.actor shouldBe ag
  }

  test("Human touching a new key emits Low-severity Alert (not Revoke)") {
    val det = BaselineDetector.make().unsafeRunSync()

    val baseTs = Instant.parse("2026-04-25T03:00:00Z")
    det.observe(rec(baseTs, alice, Operation.Get, "invoice-2026", "Success")).unsafeRunSync()

    val recs =
      det.observe(rec(baseTs.plusSeconds(10), alice, Operation.Get, "exotic-key", "Success")).unsafeRunSync()
    recs.size shouldBe 1
    recs.head.detector shouldBe "ScopeBaseline"
    recs.head.severity shouldBe Severity.Low
    recs.head.suggestedAction shouldBe SuggestedAction.Alert
  }

  test("RateSpike emits when the configured threshold is exceeded in the burst window") {
    // Tiny config: 5 requests in 10s is a burst.
    val cfg = BaselineDetector.Config(
      rateRetention = Duration.ofMinutes(5),
      rateBurstWindow = Duration.ofSeconds(10),
      rateBurstThreshold = 5
    )
    val det = BaselineDetector.make(cfg).unsafeRunSync()
    val ag  = agent(alice)

    val baseTs = Instant.parse("2026-04-25T03:00:00Z")
    val recsCollected = (0 until 6).map { i =>
      det.observe(rec(baseTs.plusSeconds(i.toLong), ag, Operation.Get, "invoice-2026", "Success"))
        .unsafeRunSync()
    }
    val all = recsCollected.flatten
    all.exists(_.detector == "RateSpike") shouldBe true
  }

  test("snapshot reflects keys and ops the actor has been seen using") {
    val det    = BaselineDetector.make().unsafeRunSync()
    val baseTs = Instant.parse("2026-04-25T03:00:00Z")

    det.observe(rec(baseTs, alice, Operation.Create, "k1", "Success")).unsafeRunSync()
    det.observe(rec(baseTs.plusSeconds(1), alice, Operation.Get, "k1", "Success")).unsafeRunSync()
    det.observe(rec(baseTs.plusSeconds(2), alice, Operation.Get, "k2", "Success")).unsafeRunSync()

    val snap          = det.snapshot.unsafeRunSync()
    val aliceBaseline = snap("alice@org")
    aliceBaseline.keysSeen should contain allOf ("key:k1", "key:k2")
    aliceBaseline.opsSeen(Operation.Get) shouldBe 2
    aliceBaseline.opsSeen(Operation.Create) shouldBe 1
  }

  // ── New v0.1.1 detectors ───────────────────────────────────────────────────

  test("Agent's first novel Operation emits a High-severity OpHistogramBaseline rec with Revoke") {
    val det = BaselineDetector.make().unsafeRunSync()
    val ag  = agent(alice)
    // Establish baseline with `Get`.
    det.observe(rec(Instant.parse("2026-04-25T03:00:00Z"), ag, Operation.Get, "k1", "Success"))
      .unsafeRunSync()
    // Now perform a `Sign` — never seen before for this agent.
    val recs = det
      .observe(rec(Instant.parse("2026-04-25T03:00:05Z"), ag, Operation.Sign, "k1", "Success"))
      .unsafeRunSync()

    val opRec = recs.find(_.detector == "OpHistogramBaseline").get
    opRec.severity shouldBe Severity.High
    opRec.suggestedAction shouldBe SuggestedAction.Revoke
    opRec.details("newOperation") shouldBe "Sign"
  }

  test("OpHistogramBaseline does NOT fire on the actor's very first call (cold-start guard)") {
    val det = BaselineDetector.make().unsafeRunSync()
    val recs = det
      .observe(rec(Instant.parse("2026-04-25T03:00:00Z"), alice, Operation.Sign, "k1", "Success"))
      .unsafeRunSync()
    recs.exists(_.detector == "OpHistogramBaseline") shouldBe false
  }

  test("TimeOfDayBaseline fires when actor active in a UTC hour-of-day they've never used") {
    val det = BaselineDetector.make().unsafeRunSync()
    val ag  = agent(alice)
    // Establish baseline at hour 03 UTC.
    det.observe(rec(Instant.parse("2026-04-25T03:14:00Z"), ag, Operation.Sign, "k1", "Success"))
      .unsafeRunSync()
    // Move to hour 17 UTC — completely outside the agent's known schedule.
    val recs = det
      .observe(rec(Instant.parse("2026-04-25T17:00:00Z"), ag, Operation.Sign, "k1", "Success"))
      .unsafeRunSync()

    val todRec = recs.find(_.detector == "TimeOfDayBaseline").get
    todRec.severity shouldBe Severity.High
    todRec.details("newHourUtc") shouldBe "17"
    todRec.details("hoursSeen") shouldBe "3"
  }

  test("TimeOfDayBaseline does NOT fire on the actor's first call (cold-start guard)") {
    val det = BaselineDetector.make().unsafeRunSync()
    val recs = det
      .observe(rec(Instant.parse("2026-04-25T03:00:00Z"), alice, Operation.Sign, "k1", "Success"))
      .unsafeRunSync()
    recs.exists(_.detector == "TimeOfDayBaseline") shouldBe false
  }

  test("SourceIpBaseline fires when context.source.ip is new for this actor") {
    val det = BaselineDetector.make().unsafeRunSync()
    val ag  = agent(alice)
    // Establish baseline IP via context.
    val first = AuditRecord(
      at = Instant.parse("2026-04-25T03:00:00Z"),
      principal = ag,
      operation = Operation.Sign,
      resource = "key:k1",
      outcome = "Success",
      correlationId = "c1",
      context = Map("source.ip" -> "10.0.5.10")
    )
    det.observe(first).unsafeRunSync()

    val second = first.copy(
      at = Instant.parse("2026-04-25T03:00:05Z"),
      correlationId = "c2",
      context = Map("source.ip" -> "203.0.113.99")
    )
    val recs = det.observe(second).unsafeRunSync()

    val ipRec = recs.find(_.detector == "SourceIpBaseline").get
    ipRec.severity shouldBe Severity.High
    ipRec.details("sourceIp") shouldBe "203.0.113.99"
    ipRec.details("priorIpCount") shouldBe "1"
  }

  test("SourceIpBaseline stays inert when records carry no source.ip context") {
    val det = BaselineDetector.make().unsafeRunSync()
    val ag  = agent(alice)
    det.observe(rec(Instant.parse("2026-04-25T03:00:00Z"), ag, Operation.Sign, "k1", "Success"))
      .unsafeRunSync()
    val recs = det
      .observe(rec(Instant.parse("2026-04-25T03:00:05Z"), ag, Operation.Sign, "k1", "Success"))
      .unsafeRunSync()
    recs.exists(_.detector == "SourceIpBaseline") shouldBe false
  }

  test("a single observation can fire multiple detectors at once (compound anomaly)") {
    val det = BaselineDetector.make().unsafeRunSync()
    val ag  = agent(alice)
    // Establish a tight baseline.
    det.observe(AuditRecord(
      at = Instant.parse("2026-04-25T03:14:00Z"),
      principal = ag,
      operation = Operation.Get,
      resource = "key:invoice-2026",
      outcome = "Success",
      correlationId = "c0",
      context = Map("source.ip" -> "10.0.5.10")
    )).unsafeRunSync()

    // Now: new key + new operation + new hour + new source IP, all in one record.
    val anomaly = AuditRecord(
      at = Instant.parse("2026-04-25T17:30:00Z"),
      principal = ag,
      operation = Operation.Sign,
      resource = "key:treasury-master",
      outcome = "Success",
      correlationId = "c1",
      context = Map("source.ip" -> "203.0.113.99")
    )
    val recs = det.observe(anomaly).unsafeRunSync()

    val detectors = recs.map(_.detector).toSet
    detectors should contain allOf (
      "ScopeBaseline",
      "OpHistogramBaseline",
      "TimeOfDayBaseline",
      "SourceIpBaseline"
    )
  }
