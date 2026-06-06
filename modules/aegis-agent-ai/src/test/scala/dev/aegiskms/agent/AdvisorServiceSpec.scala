package dev.aegiskms.agent

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import dev.aegiskms.audit.{AuditQuery, AuditRecord}
import dev.aegiskms.core.{Operation, Principal}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.{Duration, Instant}
import scala.concurrent.duration.*

/** Tests for the deterministic `advisor scan` analysis (#28).
  *
  * The heuristics live in the pure `AdvisorScan.analyze`, so most assertions drive it directly with synthetic
  * records. One test exercises the IO paging path through a stub `AuditQuery` to confirm the loop assembles a
  * multi-page window and surfaces the `truncated` flag.
  */
final class AdvisorServiceSpec extends AnyFunSuite with Matchers:

  private val now: Instant     = Instant.parse("2026-06-01T00:00:00Z")
  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def agent(subject: String): Principal.Agent =
    Principal.Agent(
      subject = subject,
      operator = alice,
      purpose = "test",
      issuedAt = now.minus(Duration.ofDays(1)),
      ttl = 1.hour,
      allowedOps = Set(Operation.Get),
      parent = None
    )

  private def rec(
      at: Instant,
      principal: Principal,
      op: Operation,
      resource: String,
      outcome: String = "Success",
      context: Map[String, String] = Map.empty
  ): AuditRecord =
    AuditRecord(at, principal, op, resource, outcome, "corr", context)

  private val req = AdvisorScan.Request(now = now, lookback = Duration.ofDays(90))

  private def analyze(records: List[AuditRecord], truncated: Boolean = false): AdvisorScan.Report =
    AdvisorScan.analyze(req, now.minus(req.lookback), now, records, truncated)

  test("a key whose last activity predates the unused-after cutoff is flagged, idle days computed from now") {
    val lastSeen = now.minus(Duration.ofDays(45))
    val report = analyze(
      List(
        rec(now.minus(Duration.ofDays(60)), alice, Operation.Create, "key:stale"),
        rec(lastSeen, alice, Operation.Get, "key:stale"), // newest activity for the key
        rec(now.minus(Duration.ofDays(2)), alice, Operation.Get, "key:fresh")
      )
    )
    report.unusedKeys.map(_.keyId) shouldBe List("stale")
    report.unusedKeys.head.lastSeen shouldBe lastSeen
    report.unusedKeys.head.idleDays shouldBe 45L
  }

  test("a key used within the cutoff is not flagged unused") {
    val report = analyze(List(rec(now.minus(Duration.ofDays(3)), alice, Operation.Sign, "key:active")))
    report.unusedKeys shouldBe empty
  }

  test("broad-scope agents are those whose distinct-op count meets the threshold") {
    val wide   = agent("agent-wide")
    val narrow = agent("agent-narrow")
    val ops    = List(Operation.Get, Operation.Sign, Operation.Encrypt, Operation.Decrypt, Operation.Wrap)
    val records =
      ops.map(o => rec(now.minus(Duration.ofHours(1)), wide, o, "key:k1")) ++
        List(rec(now, narrow, Operation.Get, "key:k2"), rec(now, narrow, Operation.Sign, "key:k2"))
    val report = analyze(records) // default broadScopeThreshold = 5
    report.broadScopeAgents.map(_.agent) shouldBe List("agent-wide")
    report.broadScopeAgents.head.operations shouldBe ops.map(_.toString).sorted
  }

  test("human principals never count toward broad-scope or riskiest agents") {
    val records =
      List(
        Operation.Get,
        Operation.Sign,
        Operation.Encrypt,
        Operation.Decrypt,
        Operation.Wrap,
        Operation.Rotate
      )
        .map(o => rec(now, alice, o, "key:k"))
    val report = analyze(records)
    report.broadScopeAgents shouldBe empty
    report.riskiestAgents shouldBe empty
  }

  test("active anomalies pick up failed / flagged outcomes, newest first; clean window reports none") {
    val a     = agent("agent-x")
    val clean = analyze(List(rec(now, a, Operation.Get, "key:k", "Success")))
    clean.activeAnomalies shouldBe empty

    val flagged = analyze(
      List(
        rec(now.minus(Duration.ofMinutes(10)), a, Operation.Sign, "key:k", "Failed code=PermissionDenied"),
        rec(now.minus(Duration.ofMinutes(5)), a, Operation.Get, "key:k", "AnomalyAlert(scope)"),
        rec(now.minus(Duration.ofMinutes(1)), a, Operation.Get, "key:k", "Success")
      )
    )
    flagged.activeAnomalies.map(_.outcome) shouldBe List(
      "AnomalyAlert(scope)",
      "Failed code=PermissionDenied"
    )
  }

  test("riskiest agents rank by failed-ops + breadth + max risk.score, capped at topRiskiest") {
    val risky = agent("agent-risky")
    val calm  = agent("agent-calm")
    val records = List(
      rec(now, risky, Operation.Sign, "key:k", "Failed code=PermissionDenied", Map("risk.score" -> "0.9")),
      rec(now, risky, Operation.Get, "key:k", "Success", Map("risk.score" -> "0.4")),
      rec(now, calm, Operation.Get, "key:k", "Success", Map("risk.score" -> "0.1"))
    )
    val report = analyze(records).copy() // explicit; default topRiskiest = 5
    report.riskiestAgents.head.agent shouldBe "agent-risky"
    report.riskiestAgents.head.failedOps shouldBe 1
    report.riskiestAgents.map(_.agent) should contain theSameElementsAs List("agent-risky", "agent-calm")
  }

  test("deterministic service pages through multiple audit pages and reports coverage") {
    // Stub reader returns two pages of 1 record then signals exhaustion.
    val page1 = AuditQuery.Page(
      List(rec(now.minus(Duration.ofDays(50)), alice, Operation.Get, "key:stale")),
      1000,
      0,
      true
    )
    val page2 = AuditQuery.Page(
      List(rec(now.minus(Duration.ofDays(1)), alice, Operation.Get, "key:fresh")),
      1000,
      1,
      false
    )
    val reader = new AuditQuery[IO]:
      def query(filter: AuditQuery.Filter): IO[AuditQuery.Page] =
        IO.pure(if filter.offset == 0 then page1 else page2)

    val report = AdvisorService.deterministic(reader).scan(req).unsafeRunSync()
    report.scannedRecords shouldBe 2
    report.truncated shouldBe false
    report.unusedKeys.map(_.keyId) shouldBe List("stale")
  }
