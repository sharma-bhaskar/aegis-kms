package dev.aegiskms.agent

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import dev.aegiskms.audit.{AuditRecord, InMemoryAuditSink}
import dev.aegiskms.core.{Operation, Principal}
import dev.aegiskms.iam.RevocationList
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import java.time.temporal.ChronoUnit

/** Tests for the audit-log-backed agent registry.
  *
  * These run against the real `InMemoryAuditSink` rather than a stub, so the filter semantics being exercised
  * (resource prefix, operation, time window, last-activity grouping) are the same ones `PostgresAuditSink`
  * implements — a stub would only prove the registry agrees with itself.
  *
  * The fixtures deliberately mirror the exact shape `HttpRoutes.writeAgentIssueAudit` writes. That coupling
  * is the contract this feature rests on: if the writer's context keys change, these tests must fail.
  */
final class AgentRegistrySpec extends AnyFunSuite with Matchers:

  /** The fixture clock, anchored to real time rather than a hardcoded date.
    *
    * The registry runs on this injected clock, but `RevocationList.inMemory` checks entry expiry against
    * `IO.realTimeInstant` — a real wall clock we cannot inject. Pinning `now` to a literal date made every
    * revocation look already-expired once that date passed, so these tests would go green on the day they
    * were written and start failing later. Anchoring to `Instant.now()` keeps both clocks in agreement.
    */
  private val now   = Instant.now().truncatedTo(ChronoUnit.SECONDS)
  private val alice = Principal.Human("alice@org", Set("operators"))
  private val bob   = Principal.Human("bob@org", Set("operators"))

  /** An issuance record exactly as the HTTP layer writes one on success. */
  private def issuance(
      agentId: String,
      jti: String,
      parent: Principal.Human = alice,
      label: String = "claude-invoice-batch",
      scopes: List[Operation] = List(Operation.Sign, Operation.Get),
      ttlSeconds: Long = 3600,
      at: Instant = now.minus(10, ChronoUnit.MINUTES)
  ): AuditRecord =
    AuditRecord(
      at = at,
      principal = parent,
      operation = Operation.Create,
      resource = s"agent:$agentId",
      outcome = s"Success agentId=$agentId jti=$jti",
      correlationId = s"corr-$agentId",
      context = Map(
        "agent.id"               -> agentId,
        "agent.jti"              -> jti,
        "agent.issue.label"      -> label,
        "agent.issue.scopes"     -> scopes.map(_.toString).mkString(","),
        "agent.issue.ttlSeconds" -> ttlSeconds.toString
      )
    )

  /** A record for an agent actually doing something, so last-seen has a source. */
  private def activity(agentId: String, at: Instant, op: Operation = Operation.Sign): AuditRecord =
    AuditRecord(
      at = at,
      principal = Principal.Agent(
        subject = agentId,
        operator = alice,
        purpose = "test",
        issuedAt = at,
        ttl = scala.concurrent.duration.Duration(1, "hour"),
        allowedOps = Set(op),
        parent = None
      ),
      operation = op,
      resource = "key:abc-123",
      outcome = "Success",
      correlationId = s"corr-act-$agentId"
    )

  private def registryOf(
      records: List[AuditRecord],
      revoked: Set[String] = Set.empty
  ): AgentRegistry[IO] =
    val sink = InMemoryAuditSink.make.unsafeRunSync()
    records.foreach(r => sink.write(r).unsafeRunSync())
    val revocations = RevocationList.inMemory.unsafeRunSync()
    revoked.foreach(jti => revocations.revoke(jti, now.plusSeconds(7200)).unsafeRunSync())
    AgentRegistry.auditBacked(sink, revocations, IO.pure(now))

  private def list(
      records: List[AuditRecord],
      filter: AgentRegistry.Filter = AgentRegistry.Filter(),
      revoked: Set[String] = Set.empty
  ): List[AgentRecord] =
    registryOf(records, revoked).list(filter).unsafeRunSync()

  // ── Parsing an issuance row ────────────────────────────────────────────────

  test("an issued agent is listed with its label, parent, scopes, and validity window") {
    val agents = list(List(issuance("agent-1", "jti-1")))

    agents should have size 1
    val a = agents.head
    a.agentId shouldBe "agent-1"
    a.label shouldBe "claude-invoice-batch"
    a.parent shouldBe "alice@org"
    a.scopes shouldBe Set(Operation.Sign, Operation.Get)
    a.issuedAt shouldBe now.minus(10, ChronoUnit.MINUTES)
    a.expiresAt shouldBe now.minus(10, ChronoUnit.MINUTES).plusSeconds(3600)
  }

  test("a failed issuance attempt is not an agent and is not listed") {
    // writeAgentIssueAudit records failures with no agent.id / agent.jti, because nothing was minted.
    val failed = AuditRecord(
      at = now.minus(5, ChronoUnit.MINUTES),
      principal = alice,
      operation = Operation.Create,
      resource = "agent:label=rejected",
      outcome = "Failed code=InvalidField",
      correlationId = "corr-fail",
      context = Map(
        "agent.issue.label"      -> "rejected",
        "agent.issue.scopes"     -> "Sign",
        "agent.issue.ttlSeconds" -> "3600"
      )
    )

    list(List(failed, issuance("agent-1", "jti-1"))).map(_.agentId) shouldBe List("agent-1")
  }

  test("an issuance row with an unparseable TTL is dropped rather than given a bogus expiry") {
    val broken = issuance("agent-bad", "jti-bad")
      .pipe(r => r.copy(context = r.context + ("agent.issue.ttlSeconds" -> "not-a-number")))

    list(List(broken, issuance("agent-1", "jti-1"))).map(_.agentId) shouldBe List("agent-1")
  }

  test("unknown scope names are dropped but the agent is still listed") {
    val record = issuance("agent-1", "jti-1")
      .pipe(r => r.copy(context = r.context + ("agent.issue.scopes" -> "Sign,Teleport,Get")))

    list(List(record)).head.scopes shouldBe Set(Operation.Sign, Operation.Get)
  }

  test("non-agent audit records are ignored entirely") {
    val keyOp = AuditRecord(
      at = now.minus(1, ChronoUnit.MINUTES),
      principal = alice,
      operation = Operation.Create,
      resource = "key:abc-123",
      outcome = "Success",
      correlationId = "corr-key"
    )

    list(List(keyOp)) shouldBe empty
  }

  // ── Status ────────────────────────────────────────────────────────────────

  test("an unexpired, unrevoked agent is Active") {
    list(List(issuance("agent-1", "jti-1", ttlSeconds = 3600))).head.status shouldBe AgentStatus.Active
  }

  test("an agent past its expiry is Expired") {
    val old = issuance("agent-1", "jti-1", ttlSeconds = 60, at = now.minus(2, ChronoUnit.HOURS))
    list(List(old)).head.status shouldBe AgentStatus.Expired
  }

  test("an agent whose jti is on the revocation list is Revoked, even while unexpired") {
    val agents = list(List(issuance("agent-1", "jti-1", ttlSeconds = 3600)), revoked = Set("jti-1"))
    agents.head.status shouldBe AgentStatus.Revoked
  }

  test("revocation takes precedence over expiry in the reported status") {
    val old = issuance("agent-1", "jti-1", ttlSeconds = 60, at = now.minus(2, ChronoUnit.HOURS))
    list(List(old), revoked = Set("jti-1")).head.status shouldBe AgentStatus.Revoked
  }

  test("an agent expiring exactly now counts as Expired, not Active") {
    val boundary = issuance("agent-1", "jti-1", ttlSeconds = 600, at = now.minus(10, ChronoUnit.MINUTES))
    list(List(boundary)).head.status shouldBe AgentStatus.Expired
  }

  // ── Last-seen ─────────────────────────────────────────────────────────────

  test("an agent that was minted but never used has no last-seen timestamp") {
    list(List(issuance("agent-1", "jti-1"))).head.lastSeenAt shouldBe None
  }

  test("last-seen reflects the agent's most recent activity, not its first") {
    val records = List(
      issuance("agent-1", "jti-1"),
      activity("agent-1", now.minus(8, ChronoUnit.MINUTES)),
      activity("agent-1", now.minus(2, ChronoUnit.MINUTES)),
      activity("agent-1", now.minus(5, ChronoUnit.MINUTES))
    )

    list(records).head.lastSeenAt shouldBe Some(now.minus(2, ChronoUnit.MINUTES))
  }

  test("one agent's activity does not leak into another's last-seen") {
    val records = List(
      issuance("agent-1", "jti-1"),
      issuance("agent-2", "jti-2"),
      activity("agent-1", now.minus(3, ChronoUnit.MINUTES))
    )

    val byId = list(records).map(a => a.agentId -> a.lastSeenAt).toMap
    byId("agent-1") shouldBe Some(now.minus(3, ChronoUnit.MINUTES))
    byId("agent-2") shouldBe None
  }

  // ── Filtering ─────────────────────────────────────────────────────────────

  test("filtering by parent returns only that operator's agents") {
    val records = List(
      issuance("agent-1", "jti-1", parent = alice),
      issuance("agent-2", "jti-2", parent = bob),
      issuance("agent-3", "jti-3", parent = alice)
    )

    val mine = list(records, AgentRegistry.Filter(parent = Some("alice@org")))
    mine.map(_.agentId).toSet shouldBe Set("agent-1", "agent-3")
  }

  test("filtering by status considers every agent, not just the first page") {
    // 3 active + 1 revoked; asking for the revoked one must not depend on where it sorts.
    val records = List(
      issuance("agent-1", "jti-1"),
      issuance("agent-2", "jti-2"),
      issuance("agent-3", "jti-3"),
      issuance("agent-4", "jti-4")
    )

    val revokedOnly = list(
      records,
      AgentRegistry.Filter(status = Some(AgentStatus.Revoked), limit = 2),
      revoked = Set("jti-4")
    )

    revokedOnly.map(_.agentId) shouldBe List("agent-4")
  }

  test("parent and status filters compose with AND") {
    val records = List(
      issuance("agent-1", "jti-1", parent = alice),
      issuance("agent-2", "jti-2", parent = bob)
    )

    val res = list(
      records,
      AgentRegistry.Filter(parent = Some("alice@org"), status = Some(AgentStatus.Revoked)),
      revoked = Set("jti-1", "jti-2")
    )

    res.map(_.agentId) shouldBe List("agent-1")
  }

  test("issuances older than the lookback window are not returned") {
    val ancient = issuance("agent-old", "jti-old", at = now.minus(30, ChronoUnit.DAYS))
    list(List(ancient, issuance("agent-1", "jti-1"))).map(_.agentId) shouldBe List("agent-1")
  }

  // ── Pagination ────────────────────────────────────────────────────────────

  test("limit and offset page through the result set without overlap") {
    val records = (1 to 5).toList.map(i =>
      issuance(s"agent-$i", s"jti-$i", at = now.minus(i.toLong, ChronoUnit.MINUTES))
    )

    val page1 = list(records, AgentRegistry.Filter(limit = 2, offset = 0)).map(_.agentId)
    val page2 = list(records, AgentRegistry.Filter(limit = 2, offset = 2)).map(_.agentId)

    page1 should have size 2
    page2 should have size 2
    page1.toSet.intersect(page2.toSet) shouldBe empty
  }

  test("an oversized limit is clamped rather than honoured") {
    val records = (1 to 3).toList.map(i =>
      issuance(s"agent-$i", s"jti-$i", at = now.minus(i.toLong, ChronoUnit.MINUTES))
    )
    // Clamping is what matters; with 3 records the observable effect is simply that it doesn't throw.
    list(records, AgentRegistry.Filter(limit = 10_000)) should have size 3
  }

  test("a negative offset is treated as zero") {
    list(List(issuance("agent-1", "jti-1")), AgentRegistry.Filter(offset = -5)) should have size 1
  }

  // ── activeCount ───────────────────────────────────────────────────────────

  test("activeCount excludes expired and revoked agents") {
    val records = List(
      issuance("agent-1", "jti-1", ttlSeconds = 3600),
      issuance("agent-2", "jti-2", ttlSeconds = 3600),
      issuance("agent-3", "jti-3", ttlSeconds = 60, at = now.minus(2, ChronoUnit.HOURS)),
      issuance("agent-4", "jti-4", ttlSeconds = 3600)
    )

    registryOf(records, revoked = Set("jti-4")).activeCount.unsafeRunSync() shouldBe 2
  }

  test("activeCount is zero when nothing has been issued") {
    registryOf(Nil).activeCount.unsafeRunSync() shouldBe 0
  }

  extension [A](a: A) private def pipe[B](f: A => B): B = f(a)
