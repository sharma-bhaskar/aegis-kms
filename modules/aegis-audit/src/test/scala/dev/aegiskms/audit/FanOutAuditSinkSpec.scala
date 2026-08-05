package dev.aegiskms.audit

import cats.effect.unsafe.implicits.global
import cats.effect.{IO, Ref}
import dev.aegiskms.core.{Operation, Principal}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant

/** Unit tests for `FanOutAuditSink` (#21). The asymmetric semantics — primary failures propagate, secondary
  * failures are swallowed — are the load-bearing contract that lets operators run a flaky SIEM webhook
  * alongside a durable Postgres primary without the request path stalling.
  */
final class FanOutAuditSinkSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def sampleRecord(corr: String): AuditRecord =
    AuditRecord(
      at = Instant.parse("2026-05-26T10:14:53Z"),
      principal = alice,
      operation = Operation.Sign,
      resource = "key:k1",
      outcome = "Success",
      correlationId = corr,
      context = Map("source.ip" -> "203.0.113.42")
    )

  /** Test sink that always raises. Captures the records it was asked to write so we can assert it was
    * actually called.
    */
  final private class FailingSink(label: String) extends AuditSink[IO]:
    val ref: Ref[IO, Vector[AuditRecord]] =
      Ref.unsafe[IO, Vector[AuditRecord]](Vector.empty)
    def write(record: AuditRecord): IO[Unit] =
      ref.update(_ :+ record) *>
        IO.raiseError(new RuntimeException(s"$label-boom"))

  test("happy path: every record is written to the primary AND every secondary") {
    val primary    = InMemoryAuditSink.make.unsafeRunSync()
    val secondary1 = InMemoryAuditSink.make.unsafeRunSync()
    val secondary2 = InMemoryAuditSink.make.unsafeRunSync()
    val fanout     = FanOutAuditSink.of(primary, List(secondary1, secondary2))

    fanout.write(sampleRecord("c-1")).unsafeRunSync()
    fanout.write(sampleRecord("c-2")).unsafeRunSync()

    primary.all.unsafeRunSync().map(_.correlationId) shouldBe List("c-1", "c-2")
    secondary1.all.unsafeRunSync().map(_.correlationId) shouldBe List("c-1", "c-2")
    secondary2.all.unsafeRunSync().map(_.correlationId) shouldBe List("c-1", "c-2")
  }

  test("primary failure propagates to the caller (durability contract)") {
    val primary   = new FailingSink("primary")
    val secondary = InMemoryAuditSink.make.unsafeRunSync()
    val fanout    = FanOutAuditSink.of(primary, List(secondary))

    val thrown = intercept[RuntimeException] {
      fanout.write(sampleRecord("c-1")).unsafeRunSync()
    }
    thrown.getMessage should include("primary-boom")
    // The secondary was NOT called — primary failed first and we short-circuit so the caller's
    // retry doesn't double-deliver to the SIEM.
    secondary.all.unsafeRunSync() shouldBe empty
  }

  test("secondary failure is swallowed — caller sees success, primary still wrote") {
    val primary   = InMemoryAuditSink.make.unsafeRunSync()
    val secondary = new FailingSink("siem")
    val fanout    = FanOutAuditSink.of(primary, List(secondary))

    // No exception escapes — best-effort semantics.
    fanout.write(sampleRecord("c-1")).unsafeRunSync()

    primary.all.unsafeRunSync().map(_.correlationId) shouldBe List("c-1")
    // The secondary was actually called — we just swallowed its failure.
    secondary.ref.get.unsafeRunSync().map(_.correlationId) shouldBe Vector("c-1")
  }

  test("when one secondary fails, OTHER secondaries still receive the record") {
    val primary = InMemoryAuditSink.make.unsafeRunSync()
    val flaky   = new FailingSink("flaky-siem")
    val healthy = InMemoryAuditSink.make.unsafeRunSync()
    val fanout  = FanOutAuditSink.of(primary, List(flaky, healthy))

    fanout.write(sampleRecord("c-1")).unsafeRunSync()

    primary.all.unsafeRunSync().map(_.correlationId) shouldBe List("c-1")
    flaky.ref.get.unsafeRunSync().map(_.correlationId) shouldBe Vector("c-1")
    healthy.all.unsafeRunSync().map(_.correlationId) shouldBe List("c-1")
  }

  test("empty secondaries list collapses to the primary (no wrapping cost)") {
    val primary = InMemoryAuditSink.make.unsafeRunSync()
    val sink    = FanOutAuditSink.of(primary, Nil)

    // Identity: the returned sink IS the primary, not a wrapping FanOutAuditSink.
    sink should be theSameInstanceAs primary
  }

  test("AuditQuery capability of the primary is NOT preserved by the wrapper — Server.boot must " +
    "match on `primarySink`, not the wrapped sink, to recover the GET /v1/audit endpoint") {
    // Regression guard for the Server.boot wiring: when webhook fan-out is enabled, the primary
    // (typically PostgresAuditSink, which implements both AuditSink AND AuditQuery) gets wrapped
    // in FanOutAuditSink. The wrapper does NOT carry the AuditQuery capability — by design, so
    // Server.boot is forced to keep a reference to the unwrapped primary for the
    // `primarySink match { case q: AuditQuery ... }` lookup. If a refactor ever switches that
    // pattern-match back to the wrapped sink, GET /v1/audit silently returns 501 even with
    // aegis.audit.kind=postgres.

    // Fake sink that implements BOTH SPIs — same shape as PostgresAuditSink but with no DB.
    final class QueryableInMemorySink extends AuditSink[IO] with AuditQuery[IO]:
      def write(record: AuditRecord): IO[Unit] = IO.unit
      def query(filter: AuditQuery.Filter): IO[AuditQuery.Page] =
        IO.pure(AuditQuery.Page(Nil, filter.limit, filter.offset, hasMore = false))
      def lastActivityBy(actors: Set[String], since: java.time.Instant): IO[Map[String, java.time.Instant]] =
        IO.pure(Map.empty)

    val primary: AuditSink[IO]   = new QueryableInMemorySink
    val secondary: AuditSink[IO] = InMemoryAuditSink.make.unsafeRunSync()
    val wrapped: AuditSink[IO]   = FanOutAuditSink.of(primary, List(secondary))

    // The wrapped sink is NOT recognized as AuditQuery — this is what would have broken
    // `GET /v1/audit` if Server.boot pattern-matched on the wrapped value.
    wrapped match
      case _: AuditQuery[IO @unchecked] =>
        fail("FanOutAuditSink should NOT be an AuditQuery — wrapping is supposed to hide the capability")
      case _ => succeed

    // Conversely, the original primary still is — and Server.boot relies on this.
    primary match
      case _: AuditQuery[IO @unchecked] => succeed
      case _ =>
        fail("primary sink lost AuditQuery capability (this would break GET /v1/audit unconditionally)")
  }
