package dev.aegiskms.agent

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import dev.aegiskms.audit.{AuditQuery, AuditRecord}
import dev.aegiskms.core.{Operation, Principal}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.{Duration, Instant}
import scala.concurrent.duration.*

/** Tests for `advisor explain` (#29) — the agent-session timeline + optional LLM narration.
  *
  * The deterministic timeline is exercised via `AdvisorExplain.timeline`; the IO path (audit paging + LLM
  * narration + graceful fallback) goes through `AdvisorService.deterministic` with a stub `AuditQuery` and a
  * stub `LlmClient`.
  */
final class AdvisorExplainSpec extends AnyFunSuite with Matchers:

  private val now: Instant     = Instant.parse("2026-06-01T00:00:00Z")
  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def agent(subject: String): Principal.Agent =
    Principal.Agent(subject, alice, "test", now.minus(Duration.ofDays(1)), 1.hour, Set(Operation.Get), None)

  private def rec(
      at: Instant,
      principal: Principal,
      op: Operation,
      resource: String,
      outcome: String = "Success",
      context: Map[String, String] = Map.empty
  ): AuditRecord =
    AuditRecord(at, principal, op, resource, outcome, "corr", context)

  private val claude = agent("claude-session-7a3")
  private val req    = AdvisorExplain.Request(agentId = "claude-session-7a3", now = now)

  private def reader(records: List[AuditRecord]): AuditQuery[IO] = new AuditQuery[IO]:
    def query(filter: AuditQuery.Filter): IO[AuditQuery.Page] =
      // Honour the actor filter the service sends, and the offset (single page is enough here).
      val matched = records.filter(r => filter.actor.forall(_ == r.principal.subject))
      IO.pure(AuditQuery.Page(
        if filter.offset == 0 then matched else Nil,
        AuditQuery.MaxLimit,
        filter.offset,
        false
      ))

  test("timeline builds chronological events, flags anomalies, and rolls up a summary") {
    val report = AdvisorExplain.timeline(
      req,
      now.minus(req.lookback),
      now,
      List(
        rec(
          now.minus(Duration.ofMinutes(10)),
          claude,
          Operation.Get,
          "key:invoice",
          "Success",
          Map("risk.score" -> "0.2")
        ),
        rec(
          now.minus(Duration.ofMinutes(5)),
          claude,
          Operation.Sign,
          "key:treasury",
          "Failed code=PermissionDenied"
        )
      ),
      truncated = false
    )
    report.events.map(_.operation) shouldBe List("Get", "Sign") // chronological
    report.events.head.riskScore shouldBe Some(0.2)
    report.events(1).anomaly shouldBe true
    report.summary.totalEvents shouldBe 2
    report.summary.anomalies shouldBe 1
    report.summary.distinctOps shouldBe List("Get", "Sign")
    report.narrative shouldBe None
  }

  test("explain without an LLM returns the deterministic timeline (no narrative)") {
    val records = List(rec(now.minus(Duration.ofMinutes(1)), claude, Operation.Get, "key:invoice"))
    val report  = AdvisorService.deterministic(reader(records), llm = None).explain(req).unsafeRunSync()
    report.agentId shouldBe "claude-session-7a3"
    report.events should have size 1
    report.narrative shouldBe None
  }

  test("explain only reads the requested agent's records (actor filter)") {
    val records = List(
      rec(now.minus(Duration.ofMinutes(2)), claude, Operation.Get, "key:invoice"),
      rec(now.minus(Duration.ofMinutes(1)), agent("other-agent"), Operation.Get, "key:other")
    )
    val report = AdvisorService.deterministic(reader(records)).explain(req).unsafeRunSync()
    report.events should have size 1
    report.events.head.resource shouldBe "key:invoice"
  }

  test("explain with an LLM adds the narrative and passes the read-only system prompt + timeline context") {
    var capturedPrompt  = ""
    var capturedContext = ""
    val stubLlm = new LlmClient[IO]:
      def plan(prompt: String, context: String): IO[String] =
        capturedPrompt = prompt; capturedContext = context
        IO.pure("  Claude read one invoice key and was denied a treasury signature.  ")
    val records = List(
      rec(
        now.minus(Duration.ofMinutes(5)),
        claude,
        Operation.Sign,
        "key:treasury",
        "Failed code=PermissionDenied"
      )
    )
    val report = AdvisorService.deterministic(reader(records), Some(stubLlm)).explain(req).unsafeRunSync()
    report.narrative shouldBe Some(
      "Claude read one invoice key and was denied a treasury signature."
    ) // trimmed
    capturedPrompt should include("read-only")
    capturedContext should include("claude-session-7a3")
    capturedContext should include("[ANOMALY]")
  }

  test("explain degrades to the bare timeline when the LLM call fails") {
    val failingLlm = new LlmClient[IO]:
      def plan(prompt: String, context: String): IO[String] = IO.raiseError(LlmError("provider down"))
    val records = List(rec(now.minus(Duration.ofMinutes(1)), claude, Operation.Get, "key:invoice"))
    val report  = AdvisorService.deterministic(reader(records), Some(failingLlm)).explain(req).unsafeRunSync()
    report.narrative shouldBe None // fell back, did not raise
    report.events should have size 1
  }

  test("explain skips the LLM entirely when the agent has no events") {
    var called = false
    val llm = new LlmClient[IO]:
      def plan(prompt: String, context: String): IO[String] = { called = true; IO.pure("x") }
    val report = AdvisorService.deterministic(reader(Nil), Some(llm)).explain(req).unsafeRunSync()
    report.events shouldBe empty
    report.narrative shouldBe None
    called shouldBe false
  }
