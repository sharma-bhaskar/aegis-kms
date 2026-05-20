package dev.aegiskms.audit

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import com.dimafeng.testcontainers.PostgreSQLContainer
import dev.aegiskms.core.{Operation, Principal, TenantId}
import doobie.*
import doobie.implicits.*
import doobie.postgres.circe.jsonb.implicits.*
import doobie.postgres.implicits.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import org.testcontainers.utility.DockerImageName

import java.time.Instant
import scala.util.Try

/** Integration tests for [[PostgresAuditSink]] against a real Postgres in Docker.
  *
  * Container lifecycle is managed manually (matching `PostgresEventJournalSpec`) so the suite skips cleanly
  * via `assume(...)` on machines without Docker.
  */
final class PostgresAuditSinkSpec extends AnyFunSuite with Matchers:

  given IORuntime = IORuntime.global

  private val dockerAvailable: Boolean =
    Try(org.testcontainers.DockerClientFactory.instance().isDockerAvailable).getOrElse(false)

  private def withPostgres(body: Transactor[IO] => Unit): Unit =
    assume(dockerAvailable, "Docker is not available; skipping Postgres audit sink integration test")
    val container = PostgreSQLContainer(
      dockerImageNameOverride = DockerImageName.parse("postgres:16-alpine"),
      databaseName = "aegis_audit_test",
      username = "aegis",
      password = "aegis"
    )
    container.start()
    try
      val xa = Transactor.fromDriverManager[IO](
        driver = "org.postgresql.Driver",
        url = container.jdbcUrl,
        user = container.username,
        password = container.password,
        logHandler = None
      )
      body(xa)
    finally container.stop()

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))
  private val agent: Principal = Principal.Agent(
    subject = "agent-7a3",
    operator = alice,
    purpose = "invoice-signing",
    issuedAt = Instant.parse("2026-05-20T10:00:00Z"),
    ttl = scala.concurrent.duration.FiniteDuration(1, scala.concurrent.duration.HOURS),
    allowedOps = Set(Operation.Sign),
    parent = None
  )
  private val system: Principal = Principal.Service("aegis-system", TenantId("system"))

  private val baseTs = Instant.parse("2026-05-20T10:00:00Z")

  private def record(
      at: Instant,
      principal: Principal,
      op: Operation,
      resource: String,
      outcome: String = "Success",
      context: Map[String, String] = Map.empty
  ): AuditRecord =
    AuditRecord(
      at = at,
      principal = principal,
      operation = op,
      resource = resource,
      outcome = outcome,
      correlationId = java.util.UUID.randomUUID().toString,
      context = context
    )

  // ── Schema + basic write ─────────────────────────────────────────────────

  test("bootstrap creates table + 4 indexes idempotently") {
    withPostgres { xa =>
      val program =
        for
          _    <- PostgresAuditSink.bootstrappedFor(xa) // first time creates
          _    <- PostgresAuditSink.bootstrappedFor(xa) // second time is a no-op
          rows <- sql"SELECT COUNT(*) FROM aegis_audit_events".query[Int].unique.transact(xa)
          idxCnt <- sql"""
                      SELECT COUNT(*) FROM pg_indexes
                      WHERE tablename = 'aegis_audit_events'
                        AND indexname LIKE 'aegis_audit_events_%'
                    """.query[Int].unique.transact(xa)
        yield (rows, idxCnt)

      val (rowsAfter, idxAfter) = program.unsafeRunSync()
      rowsAfter shouldBe 0
      idxAfter shouldBe 4 // actor, resource, operation, occurred_at
    }
  }

  test("write persists every column with the expected values") {
    withPostgres { xa =>
      val program =
        for
          sink <- PostgresAuditSink.bootstrappedFor(xa)
          rec = record(
            at = baseTs,
            principal = alice,
            op = Operation.Sign,
            resource = "key:abc-123",
            outcome = "Success alg=RsaPssSha256 msgLen=5",
            context = Map(
              "risk.score"       -> "0.42",
              "risk.factors"     -> "AgentPrincipal:0.2;DestructiveOp:0.1",
              "outcome.decision" -> "Allow"
            )
          )
          _ <- sink.write(rec)
          row <- sql"""
                   SELECT correlation_id, actor_subject, actor_kind, operation,
                          resource, outcome, context::text
                   FROM aegis_audit_events
                 """
            .query[(String, String, String, String, String, String, String)]
            .unique
            .transact(xa)
        yield (rec, row)

      val (rec, (corr, actor, kind, op, res, outcome, ctx)) = program.unsafeRunSync()
      corr shouldBe rec.correlationId
      actor shouldBe "alice@org"
      kind shouldBe "Human"
      op shouldBe "Sign"
      res shouldBe "key:abc-123"
      outcome should include("Success alg=RsaPssSha256")
      ctx should include(""""risk.score":"0.42"""")
      ctx should include(""""outcome.decision":"Allow"""")
    }
  }

  test("actor_kind correctly discriminates Human, Service, Agent principals") {
    withPostgres { xa =>
      val program =
        for
          sink <- PostgresAuditSink.bootstrappedFor(xa)
          _    <- sink.write(record(baseTs, alice, Operation.Get, "key:k1"))
          _    <- sink.write(record(baseTs, agent, Operation.Sign, "key:k2"))
          _    <- sink.write(record(baseTs, system, Operation.Revoke, "key:k3"))
          rows <- sql"""
                    SELECT actor_subject, actor_kind FROM aegis_audit_events
                    ORDER BY seq ASC
                  """.query[(String, String)].to[List].transact(xa)
        yield rows

      program.unsafeRunSync() shouldBe List(
        ("alice@org", "Human"),
        ("agent-7a3", "Agent"),
        ("aegis-system", "Service")
      )
    }
  }

  test("write accepts an empty context map (default empty JSONB object)") {
    withPostgres { xa =>
      val program =
        for
          sink <- PostgresAuditSink.bootstrappedFor(xa)
          _    <- sink.write(record(baseTs, alice, Operation.Get, "key:k1")) // context = Map.empty
          ctx  <- sql"SELECT context::text FROM aegis_audit_events".query[String].unique.transact(xa)
        yield ctx

      program.unsafeRunSync() shouldBe "{}"
    }
  }

  test("multiple writes are persisted in insertion order via seq") {
    withPostgres { xa =>
      val program =
        for
          sink <- PostgresAuditSink.bootstrappedFor(xa)
          _    <- sink.write(record(baseTs.plusSeconds(0), alice, Operation.Create, "key:a"))
          _    <- sink.write(record(baseTs.plusSeconds(1), alice, Operation.Activate, "key:a"))
          _    <- sink.write(record(baseTs.plusSeconds(2), alice, Operation.Sign, "key:a"))
          ops <- sql"""
                   SELECT operation FROM aegis_audit_events ORDER BY seq ASC
                 """.query[String].to[List].transact(xa)
        yield ops

      program.unsafeRunSync() shouldBe List("Create", "Activate", "Sign")
    }
  }

  // ── Retention ─────────────────────────────────────────────────────────────

  test("pruneBefore deletes only rows with occurred_at strictly before the cutoff") {
    withPostgres { xa =>
      val program =
        for
          sink <- PostgresAuditSink.bootstrappedFor(xa)
          _    <- sink.write(record(baseTs.minusSeconds(7200), alice, Operation.Get, "key:old1"))
          _    <- sink.write(record(baseTs.minusSeconds(3600), alice, Operation.Get, "key:old2"))
          _    <- sink.write(record(baseTs, alice, Operation.Get, "key:boundary"))
          _    <- sink.write(record(baseTs.plusSeconds(3600), alice, Operation.Get, "key:new"))
          // Cutoff is exactly baseTs → strictly-before excludes the boundary row.
          deleted <- sink.pruneBefore(baseTs)
          remaining <- sql"""
                         SELECT resource FROM aegis_audit_events ORDER BY occurred_at ASC
                       """.query[String].to[List].transact(xa)
        yield (deleted, remaining)

      val (deleted, remaining) = program.unsafeRunSync()
      deleted shouldBe 2L
      remaining shouldBe List("key:boundary", "key:new")
    }
  }

  test("pruneBefore on an empty table returns 0 rows deleted") {
    withPostgres { xa =>
      val program =
        for
          sink    <- PostgresAuditSink.bootstrappedFor(xa)
          deleted <- sink.pruneBefore(Instant.now())
        yield deleted

      program.unsafeRunSync() shouldBe 0L
    }
  }

  test("write tolerates large context maps + special characters (JSONB round-trip)") {
    withPostgres { xa =>
      val tricky = Map(
        "newline"                      -> "line1\nline2",
        "quotes"                       -> "she said \"hi\"",
        "unicode"                      -> "café — açaí — 漢字",
        "very.long.key.name.with.dots" -> ("x" * 1000)
      )
      val program =
        for
          sink <- PostgresAuditSink.bootstrappedFor(xa)
          _    <- sink.write(record(baseTs, alice, Operation.Get, "key:k1", context = tricky))
          ctx  <- sql"SELECT context::jsonb FROM aegis_audit_events".query[io.circe.Json].unique.transact(xa)
        yield ctx

      val back = program.unsafeRunSync()
      back.hcursor.downField("newline").as[String].toOption shouldBe Some("line1\nline2")
      back.hcursor.downField("quotes").as[String].toOption shouldBe Some("she said \"hi\"")
      back.hcursor.downField("unicode").as[String].toOption shouldBe Some("café — açaí — 漢字")
      back.hcursor.downField("very.long.key.name.with.dots").as[String].toOption.get.length shouldBe 1000
    }
  }
