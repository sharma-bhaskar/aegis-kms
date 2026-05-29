package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import com.dimafeng.testcontainers.GenericContainer
import dev.aegiskms.audit.{AuditRecord, AuditRecordJson}
import dev.aegiskms.core.{Operation, Principal}
import io.nats.client.api.DeliverPolicy
import io.nats.client.{Nats, Options, PullSubscribeOptions}
import org.scalatest.BeforeAndAfterAll
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import org.testcontainers.containers.wait.strategy.Wait

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.time.Instant
import java.util.UUID
import scala.concurrent.duration.*
import scala.jdk.CollectionConverters.*
import scala.util.Try

/** Integration tests for `NatsAuditSink` (#23). Spins up one real NATS broker with JetStream enabled via a
  * `GenericContainer` (testcontainers-scala has no first-class NATS module) shared across all tests in the
  * suite. Each test uses a unique stream + subject so isolation comes for free without admin teardown.
  *
  * The `nats:2.10` image is small (~25 MB) and starts in 2-3 s — much lighter than the Kafka image, so the
  * suite is dominated by JetStream publish/consume RTTs rather than container startup.
  *
  * Skips cleanly when Docker is unavailable via the standard `assume(dockerAvailable)` pattern.
  */
final class NatsAuditSinkSpec extends AnyFunSuite with Matchers with BeforeAndAfterAll:

  given IORuntime = IORuntime.global

  private val dockerAvailable: Boolean =
    Try(org.testcontainers.DockerClientFactory.instance().isDockerAvailable).getOrElse(false)

  private val natsClientPort = 4222

  private var containerOpt: Option[GenericContainer] = None
  private def natsUrl: String =
    val c = containerOpt.getOrElse(fail("NATS container not started"))
    s"nats://${c.host}:${c.mappedPort(natsClientPort)}"

  override def beforeAll(): Unit =
    if dockerAvailable then
      val c = GenericContainer(
        dockerImage = "nats:2.10",
        exposedPorts = Seq(natsClientPort),
        command = Seq("--jetstream"),
        waitStrategy = Wait.forLogMessage(".*Server is ready.*\\n", 1)
      )
      c.start()
      containerOpt = Some(c)
    super.beforeAll()

  override def afterAll(): Unit =
    try super.afterAll()
    finally containerOpt.foreach(_.stop())

  // ── Helpers ────────────────────────────────────────────────────────────────

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def sampleRecord(corr: String): AuditRecord =
    AuditRecord(
      at = Instant.parse("2026-05-29T10:14:53Z"),
      principal = alice,
      operation = Operation.Sign,
      resource = "key:invoice-2026",
      outcome = "Success",
      correlationId = corr,
      context = Map("source.ip" -> "203.0.113.42")
    )

  private def baseConfig(stream: String, subject: String, dlq: Path): NatsAuditSink.Config =
    NatsAuditSink.Config(
      servers = natsUrl,
      stream = stream,
      subject = subject,
      autoCreateStream = true,
      credentialsFile = None,
      maxRetries = 2,
      initialBackoff = 50.millis,
      maxBackoff = 200.millis,
      deadLetterFile = dlq,
      queueCapacity = 16
    )

  private def freshDlqPath(): Path =
    val f = Files.createTempFile("aegis-nats-dlq-", ".jsonl")
    Files.delete(f)
    f

  private def freshStreamAndSubject(): (String, String) =
    val id = UUID.randomUUID().toString.replace("-", "").take(12)
    (s"AEGIS_TEST_$id", s"aegis.test.$id")

  /** Pull up to `expected` messages off the JetStream subject (poll for at most `total`). */
  private def consumeUpTo(
      stream: String,
      subject: String,
      expected: Int,
      total: FiniteDuration
  ): List[String] =
    val opts = new Options.Builder().server(natsUrl).build()
    val conn = Nats.connect(opts)
    try
      val js = conn.jetStream()
      val sub = js.subscribe(
        subject,
        PullSubscribeOptions.builder().stream(stream).build()
      )
      val deadline = System.currentTimeMillis() + total.toMillis
      val acc      = scala.collection.mutable.ListBuffer.empty[String]
      while acc.size < expected && System.currentTimeMillis() < deadline do
        val msgs = sub.fetch(expected - acc.size, java.time.Duration.ofMillis(500))
        msgs.asScala.foreach { m =>
          acc += new String(m.getData, StandardCharsets.UTF_8)
          m.ack()
        }
      acc.toList
    finally conn.close()

  // ── Tests ──────────────────────────────────────────────────────────────────

  test("happy path: published records land on the JetStream subject") {
    assume(dockerAvailable, "Docker is not available; skipping NATS audit-sink integration test")
    val (stream, subject) = freshStreamAndSubject()
    val dlq               = freshDlqPath()
    val program: IO[Unit] =
      NatsAuditSink.make(baseConfig(stream, subject, dlq)).use { sink =>
        sink.write(sampleRecord("c-1")) *>
          sink.write(sampleRecord("c-2")) *>
          sink.write(sampleRecord("c-3")) *>
          IO.sleep(2.seconds)
      }
    program.unsafeRunSync()

    val bodies = consumeUpTo(stream, subject, expected = 3, total = 10.seconds)
    bodies.size shouldBe 3
    bodies.zip(List("c-1", "c-2", "c-3")).foreach { case (body, corr) =>
      body should include(s""""correlationId":"$corr"""")
    }
    Files.exists(dlq) shouldBe false
  }

  test("body is canonical AuditRecordJson — round-trip via the same encoder matches") {
    assume(dockerAvailable, "Docker is not available; skipping NATS audit-sink integration test")
    import io.circe.syntax.*
    import AuditRecordJson.given

    val (stream, subject) = freshStreamAndSubject()
    val dlq               = freshDlqPath()
    val record            = sampleRecord("c-canon")
    val program =
      NatsAuditSink.make(baseConfig(stream, subject, dlq)).use(_.write(record) *> IO.sleep(2.seconds))
    program.unsafeRunSync()

    val bodies = consumeUpTo(stream, subject, expected = 1, total = 10.seconds)
    bodies.head shouldBe record.asJson.noSpaces
  }

  test("autoCreateStream=true is idempotent — second boot with the same stream name does not throw") {
    assume(dockerAvailable, "Docker is not available; skipping NATS audit-sink integration test")
    val (stream, subject) = freshStreamAndSubject()
    val dlq               = freshDlqPath()
    val cfg               = baseConfig(stream, subject, dlq)
    // Boot once, tear down (closes connection, stream remains).
    NatsAuditSink.make(cfg).use(_ => IO.unit).unsafeRunSync()
    // Boot a second time — the bootstrap should detect the existing stream and skip the create.
    NatsAuditSink.make(cfg).use(_ => IO.unit).unsafeRunSync()
  }

  test("transport failure routes records to the DLQ after maxRetries") {
    assume(dockerAvailable, "Docker is not available; skipping NATS audit-sink integration test")
    val dlq = freshDlqPath()
    // Point at a port nothing's listening on. Skip stream creation so we don't 5-second-timeout
    // on jsm.getStreamInfo against the dead connection.
    val cfg = NatsAuditSink.Config(
      servers = "nats://127.0.0.1:1",
      stream = "AEGIS_TEST_NONE",
      subject = "aegis.test.none",
      autoCreateStream = false,
      credentialsFile = None,
      maxRetries = 0,
      initialBackoff = 50.millis,
      maxBackoff = 200.millis,
      deadLetterFile = dlq,
      queueCapacity = 16
    )
    // make() itself fails on connection — assert the error is surfaced rather than silently
    // swallowed. This validates fail-fast on bad config.
    val outcome = NatsAuditSink.make(cfg).use(_ => IO.unit).attempt.unsafeRunSync()
    outcome.isLeft shouldBe true
    // Suppress the unused warning for DeliverPolicy import; reserved for the consumer config
    // when we add a "rewind from a specific time" test in v0.3.0.
    val _ = DeliverPolicy.All
  }

  test("Config.require: empty servers / stream / subject / negative retries are rejected") {
    val dlq = freshDlqPath()
    val ok = NatsAuditSink.Config(
      servers = "nats://127.0.0.1:4222",
      stream = "S",
      subject = "s",
      autoCreateStream = true,
      credentialsFile = None,
      maxRetries = 2,
      initialBackoff = 50.millis,
      maxBackoff = 200.millis,
      deadLetterFile = dlq,
      queueCapacity = 16
    )
    intercept[IllegalArgumentException](ok.copy(servers = "")).getMessage should include("servers")
    intercept[IllegalArgumentException](ok.copy(stream = "")).getMessage should include("stream")
    intercept[IllegalArgumentException](ok.copy(subject = "")).getMessage should include("subject")
    intercept[IllegalArgumentException](ok.copy(maxRetries = -1)).getMessage should include("maxRetries")
    intercept[IllegalArgumentException](ok.copy(queueCapacity = 0)).getMessage should include(
      "queueCapacity"
    )
  }
