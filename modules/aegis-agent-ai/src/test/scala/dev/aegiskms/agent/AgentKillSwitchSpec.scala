package dev.aegiskms.agent

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import dev.aegiskms.audit.{AuditRecord, InMemoryAuditSink}
import dev.aegiskms.core.{ErrorCode, Operation, Principal}
import dev.aegiskms.iam.RevocationList
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import java.time.temporal.ChronoUnit

/** Tests for the agent kill-switch (#102).
  *
  * The properties that matter here are all about *not overreaching*: killing exactly the agents in scope,
  * leaving other operators' fleets alone, honouring the time bound, and reporting honestly what was actually
  * stopped versus what was already dead.
  */
final class AgentKillSwitchSpec extends AnyFunSuite with Matchers:

  /** The fixture clock, anchored to real time rather than a hardcoded date.
    *
    * The registry runs on this injected clock, but `RevocationList.inMemory` checks entry expiry against
    * `IO.realTimeInstant` — a real wall clock we cannot inject. Pinning `now` to a literal date made every
    * revocation look already-expired once that date passed, so these tests would go green on the day they
    * were written and start failing later. Anchoring to `Instant.now()` keeps both clocks in agreement.
    */
  private val now   = Instant.now().truncatedTo(ChronoUnit.SECONDS)
  private val alice = Principal.Human("alice@org", Set("operators"), Set("mfa"), Some(now))
  private val bob   = Principal.Human("bob@org", Set("operators"))

  private def issuance(
      agentId: String,
      jti: String,
      parent: Principal.Human = alice,
      ttlSeconds: Long = 3600,
      at: Instant = now.minus(10, ChronoUnit.MINUTES)
  ): AuditRecord =
    AuditRecord(
      at = at,
      principal = parent,
      operation = Operation.Create,
      resource = s"agent:$agentId",
      outcome = s"Success agentId=$agentId",
      correlationId = s"corr-$agentId",
      context = Map(
        "agent.id"               -> agentId,
        "agent.jti"              -> jti,
        "agent.issue.label"      -> s"label-$agentId",
        "agent.issue.scopes"     -> "Sign,Get",
        "agent.issue.ttlSeconds" -> ttlSeconds.toString
      )
    )

  final private case class Fixture(
      killSwitch: AgentKillSwitch,
      revocations: RevocationList[IO],
      sink: InMemoryAuditSink
  )

  private def fixture(records: List[AuditRecord], preRevoked: Set[String] = Set.empty): Fixture =
    val sink = InMemoryAuditSink.make.unsafeRunSync()
    records.foreach(r => sink.write(r).unsafeRunSync())
    val revocations = RevocationList.inMemory.unsafeRunSync()
    preRevoked.foreach(j => revocations.revoke(j, now.plusSeconds(7200)).unsafeRunSync())
    val registry = AgentRegistry.auditBacked(sink, revocations, IO.pure(now))
    Fixture(AgentKillSwitch.auditBacked(registry, revocations, sink, IO.pure(now)), revocations, sink)

  // ── Killing ───────────────────────────────────────────────────────────────

  test("every live agent under the parent is revoked") {
    val f = fixture(List(issuance("agent-1", "jti-1"), issuance("agent-2", "jti-2")))

    val res = f.killSwitch.revokeAll(alice, KillSwitchRequest("alice@org")).unsafeRunSync()

    res.toOption.get.killed.map(_.agentId).toSet shouldBe Set("agent-1", "agent-2")
    f.revocations.isRevoked("jti-1").unsafeRunSync() shouldBe true
    f.revocations.isRevoked("jti-2").unsafeRunSync() shouldBe true
  }

  test("another operator's agents are left completely alone") {
    val f = fixture(List(
      issuance("agent-1", "jti-1", parent = alice),
      issuance("agent-2", "jti-2", parent = bob)
    ))

    val res = f.killSwitch.revokeAll(alice, KillSwitchRequest("alice@org")).unsafeRunSync()

    res.toOption.get.killed.map(_.agentId) shouldBe List("agent-1")
    f.revocations.isRevoked("jti-2").unsafeRunSync() shouldBe false
  }

  test("issuedAfter bounds the sweep to agents minted in the window") {
    val f = fixture(List(
      issuance("agent-old", "jti-old", at = now.minus(6, ChronoUnit.HOURS), ttlSeconds = 86400),
      issuance("agent-new", "jti-new", at = now.minus(30, ChronoUnit.MINUTES))
    ))

    val res = f.killSwitch
      .revokeAll(alice, KillSwitchRequest("alice@org", Some(now.minus(1, ChronoUnit.HOURS))))
      .unsafeRunSync()

    res.toOption.get.killed.map(_.agentId) shouldBe List("agent-new")
    f.revocations.isRevoked("jti-old").unsafeRunSync() shouldBe false
  }

  test("an agent issued exactly at the issuedAfter boundary is included") {
    val boundary = now.minus(1, ChronoUnit.HOURS)
    val f        = fixture(List(issuance("agent-1", "jti-1", at = boundary, ttlSeconds = 86400)))

    val res = f.killSwitch
      .revokeAll(alice, KillSwitchRequest("alice@org", Some(boundary)))
      .unsafeRunSync()

    res.toOption.get.killed should have size 1
  }

  // ── Honest reporting ──────────────────────────────────────────────────────

  test("already-revoked and expired agents are counted separately, not reported as kills") {
    val f = fixture(
      List(
        issuance("agent-live", "jti-live"),
        issuance("agent-dead", "jti-dead"),
        issuance("agent-old", "jti-old", ttlSeconds = 60, at = now.minus(2, ChronoUnit.HOURS))
      ),
      preRevoked = Set("jti-dead")
    )

    val r = f.killSwitch.revokeAll(alice, KillSwitchRequest("alice@org")).unsafeRunSync().toOption.get

    r.killed.map(_.agentId) shouldBe List("agent-live")
    r.alreadyRevoked shouldBe 1
    r.expired shouldBe 1
    r.totalConsidered shouldBe 3
  }

  test("a sweep that finds nothing live succeeds with an empty kill list") {
    val f = fixture(List(issuance("agent-1", "jti-1")), preRevoked = Set("jti-1"))

    val r = f.killSwitch.revokeAll(alice, KillSwitchRequest("alice@org")).unsafeRunSync().toOption.get

    r.killed shouldBe empty
    r.alreadyRevoked shouldBe 1
  }

  test("a parent with no agents at all is not an error") {
    val f = fixture(Nil)

    val r = f.killSwitch.revokeAll(alice, KillSwitchRequest("nobody@org")).unsafeRunSync().toOption.get

    r.killed shouldBe empty
    r.totalConsidered shouldBe 0
  }

  test("re-running the kill-switch is idempotent") {
    val f = fixture(List(issuance("agent-1", "jti-1")))

    val first  = f.killSwitch.revokeAll(alice, KillSwitchRequest("alice@org")).unsafeRunSync().toOption.get
    val second = f.killSwitch.revokeAll(alice, KillSwitchRequest("alice@org")).unsafeRunSync().toOption.get

    first.killed should have size 1
    second.killed shouldBe empty
    second.alreadyRevoked shouldBe 1
  }

  test("an empty parent is rejected rather than interpreted as 'everyone'") {
    val f   = fixture(List(issuance("agent-1", "jti-1")))
    val res = f.killSwitch.revokeAll(alice, KillSwitchRequest("   ")).unsafeRunSync()

    res.left.toOption.get.code shouldBe ErrorCode.InvalidField
    f.revocations.isRevoked("jti-1").unsafeRunSync() shouldBe false
  }

  // ── Audit ─────────────────────────────────────────────────────────────────

  /** Records the kill-switch itself wrote. We cannot simply clear the sink first: the kill-switch reads that
    * same audit log to find the agents, so wiping it would leave nothing to kill.
    */
  private def killSwitchRecords(f: Fixture): List[AuditRecord] =
    f.sink.all.unsafeRunSync().filter(_.context.get("agent.killswitch").contains("true"))

  test("one audit record per revoked agent, plus one summary for the sweep") {
    val f = fixture(List(issuance("agent-1", "jti-1"), issuance("agent-2", "jti-2")))

    f.killSwitch.revokeAll(alice, KillSwitchRequest("alice@org")).unsafeRunSync()

    val records  = killSwitchRecords(f)
    val perAgent = records.filter(_.context.get("agent.killswitch.summary").isEmpty)
    val summary  = records.filter(_.context.get("agent.killswitch.summary").contains("true"))

    perAgent.map(_.resource).toSet shouldBe Set("agent:agent-1", "agent:agent-2")
    summary should have size 1
    summary.head.resource shouldBe "parent:alice@org"
    summary.head.context("agent.killswitch.killed") shouldBe "2"
  }

  test("the audit trail names who pulled the lever") {
    val f = fixture(List(issuance("agent-1", "jti-1")))

    f.killSwitch.revokeAll(alice, KillSwitchRequest("alice@org")).unsafeRunSync()

    val records = killSwitchRecords(f)
    records should not be empty
    records.foreach(_.principal.subject shouldBe "alice@org")
  }

  test("per-agent audit rows carry the jti so a later investigation can join on it") {
    val f = fixture(List(issuance("agent-1", "jti-1")))

    f.killSwitch.revokeAll(alice, KillSwitchRequest("alice@org")).unsafeRunSync()

    val row = killSwitchRecords(f).find(_.resource == "agent:agent-1").get
    row.context("agent.jti") shouldBe "jti-1"
    row.operation shouldBe Operation.Revoke
  }

  test("the summary records the issuedAfter bound that was applied") {
    val cutoff = now.minus(1, ChronoUnit.HOURS)
    val f      = fixture(List(issuance("agent-1", "jti-1")))

    f.killSwitch.revokeAll(alice, KillSwitchRequest("alice@org", Some(cutoff))).unsafeRunSync()

    val summary = killSwitchRecords(f)
      .find(_.context.get("agent.killswitch.summary").contains("true")).get
    summary.context("agent.killswitch.issuedAfter") shouldBe cutoff.toString
  }

  // ── Partial failure ───────────────────────────────────────────────────────

  test("a revocation-store failure on one agent does not abort the rest of the sweep") {
    val sink = InMemoryAuditSink.make.unsafeRunSync()
    List(issuance("agent-1", "jti-1"), issuance("agent-2", "jti-2"), issuance("agent-3", "jti-3"))
      .foreach(r => sink.write(r).unsafeRunSync())

    val inner = RevocationList.inMemory.unsafeRunSync()
    // Fails only for agent-2's token; the others must still be revoked.
    val flaky = new RevocationList[IO]:
      def isRevoked(jti: String): IO[Boolean] = inner.isRevoked(jti)
      def revoke(jti: String, expiresAt: Instant): IO[Unit] =
        if jti == "jti-2" then IO.raiseError(new RuntimeException("redis down"))
        else inner.revoke(jti, expiresAt)

    val registry   = AgentRegistry.auditBacked(sink, flaky, IO.pure(now))
    val killSwitch = AgentKillSwitch.auditBacked(registry, flaky, sink, IO.pure(now))

    val r = killSwitch.revokeAll(alice, KillSwitchRequest("alice@org")).unsafeRunSync().toOption.get

    r.killed.map(_.agentId).toSet shouldBe Set("agent-1", "agent-3")
    inner.isRevoked("jti-1").unsafeRunSync() shouldBe true
    inner.isRevoked("jti-3").unsafeRunSync() shouldBe true
    // The failure is surfaced in the counts rather than silently dropped.
    r.alreadyRevoked shouldBe 1
  }
