package dev.aegiskms.audit

import cats.effect.unsafe.implicits.global
import dev.aegiskms.core.{Operation, Principal}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import java.time.temporal.ChronoUnit

/** Tests for the `AuditQuery` read side implemented by `InMemoryAuditSink`.
  *
  * These matter beyond the in-memory sink itself: the agent registry, the advisor, and the audit-read
  * endpoint are all unit-tested against this implementation, so if its filter semantics drift from
  * `PostgresAuditSink`'s, every one of those suites starts proving the wrong thing. The assertions here are
  * written as the *contract* both implementations must satisfy.
  */
final class InMemoryAuditQuerySpec extends AnyFunSuite with Matchers:

  private val now   = Instant.parse("2026-08-05T12:00:00Z")
  private val alice = Principal.Human("alice@org", Set("operators"))
  private val bob   = Principal.Human("bob@org", Set.empty)

  private def rec(
      at: Instant = now,
      principal: Principal = alice,
      operation: Operation = Operation.Sign,
      resource: String = "key:abc"
  ): AuditRecord =
    AuditRecord(at, principal, operation, resource, "Success", java.util.UUID.randomUUID().toString)

  private def sinkOf(records: AuditRecord*): InMemoryAuditSink =
    val s = InMemoryAuditSink.make.unsafeRunSync()
    records.foreach(r => s.write(r).unsafeRunSync())
    s

  private def query(s: InMemoryAuditSink, f: AuditQuery.Filter) = s.query(f).unsafeRunSync()

  // ── Filters ───────────────────────────────────────────────────────────────

  test("with no filters every record comes back, newest first") {
    val s = sinkOf(
      rec(at = now.minus(3, ChronoUnit.MINUTES), resource = "key:a"),
      rec(at = now.minus(1, ChronoUnit.MINUTES), resource = "key:b"),
      rec(at = now.minus(2, ChronoUnit.MINUTES), resource = "key:c")
    )

    query(s, AuditQuery.Filter()).records.map(_.resource) shouldBe List("key:b", "key:c", "key:a")
  }

  test("since is inclusive and until is exclusive") {
    val s = sinkOf(
      rec(at = now.minus(10, ChronoUnit.MINUTES), resource = "key:before"),
      rec(at = now.minus(5, ChronoUnit.MINUTES), resource = "key:lower"),
      rec(at = now, resource = "key:upper")
    )

    val page = query(
      s,
      AuditQuery.Filter(since = Some(now.minus(5, ChronoUnit.MINUTES)), until = Some(now))
    )

    page.records.map(_.resource) shouldBe List("key:lower")
  }

  test("actor matches the principal subject exactly") {
    val s = sinkOf(rec(principal = alice), rec(principal = bob, resource = "key:bob"))

    query(s, AuditQuery.Filter(actor = Some("bob@org"))).records.map(_.resource) shouldBe List("key:bob")
  }

  test("resource is an exact match, not a prefix") {
    val s = sinkOf(rec(resource = "key:abc"), rec(resource = "key:abcdef"))

    query(s, AuditQuery.Filter(resource = Some("key:abc"))).records.map(_.resource) shouldBe
      List("key:abc")
  }

  test("resourcePrefix matches left-anchored and nothing else") {
    val s = sinkOf(
      rec(resource = "agent:agent-1"),
      rec(resource = "agent:agent-2"),
      rec(resource = "key:agent-lookalike"),
      rec(resource = "parent:alice@org")
    )

    val got = query(s, AuditQuery.Filter(resourcePrefix = Some("agent:"))).records.map(_.resource)
    got.toSet shouldBe Set("agent:agent-1", "agent:agent-2")
  }

  test("operation matches exactly") {
    val s = sinkOf(rec(operation = Operation.Sign), rec(operation = Operation.Create, resource = "key:c"))

    query(s, AuditQuery.Filter(operation = Some(Operation.Create))).records.map(_.resource) shouldBe
      List("key:c")
  }

  test("filters compose with AND") {
    val s = sinkOf(
      rec(principal = alice, operation = Operation.Create, resource = "agent:a1"),
      rec(principal = bob, operation = Operation.Create, resource = "agent:a2"),
      rec(principal = alice, operation = Operation.Sign, resource = "agent:a3")
    )

    val page = query(
      s,
      AuditQuery.Filter(
        actor = Some("alice@org"),
        operation = Some(Operation.Create),
        resourcePrefix = Some("agent:")
      )
    )

    page.records.map(_.resource) shouldBe List("agent:a1")
  }

  // ── Pagination ────────────────────────────────────────────────────────────

  test("hasMore is true only when records remain past the window") {
    val s = sinkOf((1 to 5).map(i => rec(at = now.minusSeconds(i.toLong), resource = s"key:$i"))*)

    query(s, AuditQuery.Filter(limit = 2)).hasMore shouldBe true
    query(s, AuditQuery.Filter(limit = 5)).hasMore shouldBe false
    query(s, AuditQuery.Filter(limit = 10)).hasMore shouldBe false
  }

  test("offset walks the result set without repeating or skipping") {
    val s = sinkOf((1 to 5).map(i => rec(at = now.minusSeconds(i.toLong), resource = s"key:$i"))*)

    val p1 = query(s, AuditQuery.Filter(limit = 2, offset = 0)).records.map(_.resource)
    val p2 = query(s, AuditQuery.Filter(limit = 2, offset = 2)).records.map(_.resource)
    val p3 = query(s, AuditQuery.Filter(limit = 2, offset = 4)).records.map(_.resource)

    (p1 ++ p2 ++ p3) should have size 5
    (p1 ++ p2 ++ p3).distinct should have size 5
  }

  test("limit is clamped to MaxLimit and a non-positive limit becomes 1") {
    val s = sinkOf(rec())

    query(s, AuditQuery.Filter(limit = 99_999)).limit shouldBe AuditQuery.MaxLimit
    query(s, AuditQuery.Filter(limit = 0)).limit shouldBe 1
    query(s, AuditQuery.Filter(limit = -5)).limit shouldBe 1
  }

  test("a negative offset is treated as zero") {
    val s = sinkOf(rec())
    query(s, AuditQuery.Filter(offset = -3)).records should have size 1
  }

  test("an offset past the end returns an empty page rather than erroring") {
    val s = sinkOf(rec())
    query(s, AuditQuery.Filter(offset = 100)).records shouldBe empty
  }

  // ── lastActivityBy ────────────────────────────────────────────────────────

  test("lastActivityBy returns the most recent timestamp per actor") {
    val s = sinkOf(
      rec(at = now.minus(9, ChronoUnit.MINUTES), principal = alice),
      rec(at = now.minus(2, ChronoUnit.MINUTES), principal = alice),
      rec(at = now.minus(5, ChronoUnit.MINUTES), principal = bob)
    )

    val got = s.lastActivityBy(Set("alice@org", "bob@org"), now.minusSeconds(3600)).unsafeRunSync()

    got("alice@org") shouldBe now.minus(2, ChronoUnit.MINUTES)
    got("bob@org") shouldBe now.minus(5, ChronoUnit.MINUTES)
  }

  test("an actor with no activity in the window is absent, not mapped to a sentinel") {
    val s = sinkOf(rec(principal = alice))

    val got = s.lastActivityBy(Set("alice@org", "nobody@org"), now.minusSeconds(3600)).unsafeRunSync()

    got.keySet shouldBe Set("alice@org")
  }

  test("lastActivityBy honours the since bound") {
    val s = sinkOf(rec(at = now.minus(2, ChronoUnit.HOURS), principal = alice))

    s.lastActivityBy(Set("alice@org"), now.minusSeconds(60)).unsafeRunSync() shouldBe empty
  }

  test("an empty actor set short-circuits to an empty map") {
    val s = sinkOf(rec())
    s.lastActivityBy(Set.empty, now.minusSeconds(3600)).unsafeRunSync() shouldBe empty
  }

  test("actors not asked about are never returned") {
    val s   = sinkOf(rec(principal = alice), rec(principal = bob))
    val got = s.lastActivityBy(Set("alice@org"), now.minusSeconds(3600)).unsafeRunSync()

    got.keySet shouldBe Set("alice@org")
  }

  // ── LIKE-escaping ─────────────────────────────────────────────────────────

  test("escapeLikePrefix neutralises SQL LIKE wildcards so they match literally") {
    AuditQuery.escapeLikePrefix("agent:100%") shouldBe """agent:100\%"""
    AuditQuery.escapeLikePrefix("a_b") shouldBe """a\_b"""
    AuditQuery.escapeLikePrefix("""back\slash""") shouldBe """back\\slash"""
  }

  test("escapeLikePrefix leaves ordinary prefixes untouched") {
    AuditQuery.escapeLikePrefix("agent:") shouldBe "agent:"
    AuditQuery.escapeLikePrefix("") shouldBe ""
  }

  test("a prefix that is all wildcards is escaped rather than matching everything") {
    AuditQuery.escapeLikePrefix("%") shouldBe """\%"""
    AuditQuery.escapeLikePrefix("%_%") shouldBe """\%\_\%"""
  }

  test("the in-memory prefix filter treats wildcards literally, matching the escaped SQL semantics") {
    val s = sinkOf(rec(resource = "agent:100%special"), rec(resource = "agent:100xspecial"))

    // '%' must not act as a wildcard: only the literal row matches.
    val got = query(s, AuditQuery.Filter(resourcePrefix = Some("agent:100%"))).records.map(_.resource)
    got shouldBe List("agent:100%special")
  }
