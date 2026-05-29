package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import com.dimafeng.testcontainers.KafkaContainer
import dev.aegiskms.audit.{AuditRecord, AuditRecordJson}
import dev.aegiskms.core.{Operation, Principal}
import org.apache.kafka.clients.consumer.{ConsumerConfig, KafkaConsumer}
import org.apache.kafka.common.serialization.{ByteArrayDeserializer, StringDeserializer}
import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.actor.typed.scaladsl.Behaviors
import org.scalatest.BeforeAndAfterAll
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import org.testcontainers.utility.DockerImageName

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.time.{Duration as JDuration, Instant}
import java.util.{Properties, UUID}
import scala.concurrent.duration.*
import scala.jdk.CollectionConverters.*
import scala.util.Try

/** Integration tests for `KafkaAuditSink` (#22). Spins up one real Kafka broker via Testcontainers shared
  * across all tests in the suite; each test publishes to a unique topic so isolation comes for free without
  * admin-client teardown.
  *
  * The Kafka image (`confluentinc/cp-kafka:7.6.1`) is heavy (~600 MB) and takes ~20 s to come up — the
  * shared-container pattern is what keeps the suite under a minute on CI.
  *
  * Skips cleanly when Docker is unavailable via the standard `assume(dockerAvailable)` pattern.
  */
final class KafkaAuditSinkSpec extends AnyFunSuite with Matchers with BeforeAndAfterAll:

  given IORuntime = IORuntime.global

  private val dockerAvailable: Boolean =
    Try(org.testcontainers.DockerClientFactory.instance().isDockerAvailable).getOrElse(false)

  implicit private lazy val system: ActorSystem[Nothing] =
    ActorSystem(Behaviors.empty[Nothing], "KafkaAuditSinkSpec")

  private var containerOpt: Option[KafkaContainer] = None
  private def bootstrapServers: String =
    containerOpt.getOrElse(fail("Kafka container not started")).bootstrapServers

  override def beforeAll(): Unit =
    if dockerAvailable then
      val c = KafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:7.6.1"))
      c.start()
      containerOpt = Some(c)
    super.beforeAll()

  override def afterAll(): Unit =
    try super.afterAll()
    finally
      containerOpt.foreach(_.stop())
      system.terminate()

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

  private def baseConfig(topic: String, dlq: Path): KafkaAuditSink.Config =
    KafkaAuditSink.Config(
      bootstrapServers = bootstrapServers,
      topic = topic,
      clientId = s"aegis-test-${UUID.randomUUID()}",
      maxRetries = 2,
      initialBackoff = 50.millis,
      maxBackoff = 200.millis,
      deadLetterFile = dlq,
      queueCapacity = 16
    )

  private def freshDlqPath(): Path =
    val f = Files.createTempFile("aegis-kafka-dlq-", ".jsonl")
    Files.delete(f)
    f

  private def freshTopic(): String =
    s"aegis-audit-${UUID.randomUUID()}"

  /** Consume up to `expected` records from `topic` (poll for at most `total`). Returns the body strings in
    * arrival order.
    */
  private def consumeUpTo(topic: String, expected: Int, total: FiniteDuration): List[String] =
    val props = new Properties()
    props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers)
    props.put(ConsumerConfig.GROUP_ID_CONFIG, s"aegis-test-consumer-${UUID.randomUUID()}")
    props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")
    props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "false")
    props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, classOf[StringDeserializer].getName)
    props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, classOf[ByteArrayDeserializer].getName)
    val consumer = new KafkaConsumer[String, Array[Byte]](props)
    try
      consumer.subscribe(List(topic).asJava)
      val deadline = System.currentTimeMillis() + total.toMillis
      val acc      = scala.collection.mutable.ListBuffer.empty[String]
      while acc.size < expected && System.currentTimeMillis() < deadline do
        val records = consumer.poll(JDuration.ofMillis(250))
        records.iterator().asScala.foreach { r =>
          acc += new String(r.value(), StandardCharsets.UTF_8)
        }
      acc.toList
    finally consumer.close()

  // ── Tests ──────────────────────────────────────────────────────────────────

  test("happy path: published records are consumable from the configured topic") {
    assume(dockerAvailable, "Docker is not available; skipping Kafka audit-sink integration test")
    val topic = freshTopic()
    val dlq   = freshDlqPath()
    val program: IO[Unit] =
      KafkaAuditSink.make(baseConfig(topic, dlq)).use { sink =>
        sink.write(sampleRecord("c-1")) *>
          sink.write(sampleRecord("c-2")) *>
          sink.write(sampleRecord("c-3")) *>
          // Tiny pause so the drain fiber's send completes before the Resource closes.
          IO.sleep(2.seconds)
      }
    program.unsafeRunSync()

    val bodies = consumeUpTo(topic, expected = 3, total = 10.seconds)
    bodies.size shouldBe 3
    bodies.zip(List("c-1", "c-2", "c-3")).foreach { case (body, corr) =>
      body should include(s""""correlationId":"$corr"""")
    }
    Files.exists(dlq) shouldBe false
  }

  test("body is canonical AuditRecordJson — round-trip via the same encoder matches") {
    assume(dockerAvailable, "Docker is not available; skipping Kafka audit-sink integration test")
    import io.circe.syntax.*
    import AuditRecordJson.given

    val topic   = freshTopic()
    val dlq     = freshDlqPath()
    val record  = sampleRecord("c-canon")
    val program = KafkaAuditSink.make(baseConfig(topic, dlq)).use(_.write(record) *> IO.sleep(2.seconds))
    program.unsafeRunSync()

    val bodies = consumeUpTo(topic, expected = 1, total = 10.seconds)
    bodies.head shouldBe record.asJson.noSpaces
  }

  test("transport failure routes records to the DLQ after maxRetries") {
    // Point the sink at a port that nothing is listening on. The producer surfaces the failure
    // synchronously after its internal retries; the drain loop retries `maxRetries=2` more
    // times then writes to DLQ.
    assume(dockerAvailable, "Docker is not available; skipping Kafka audit-sink integration test")
    val dlq = freshDlqPath()
    val cfg = baseConfig(freshTopic(), dlq).copy(
      bootstrapServers = "127.0.0.1:1", // closed port
      maxRetries = 0,                   // fail fast for a quick test
      initialBackoff = 50.millis
    )
    val program = KafkaAuditSink.make(cfg).use { sink =>
      sink.write(sampleRecord("c-fail")) *> IO {
        val deadline = System.currentTimeMillis() + 30.seconds.toMillis
        while !Files.exists(dlq) && System.currentTimeMillis() < deadline do Thread.sleep(100)
      }
    }
    program.unsafeRunSync()

    Files.exists(dlq) shouldBe true
    val dlqLines = Files.readAllLines(dlq)
    dlqLines.size shouldBe 1
    dlqLines.get(0) should include(""""correlationId":"c-fail"""")
  }

  test("Config.require: empty bootstrapServers / topic / negative retries are rejected") {
    // Pure unit test — does not depend on a running container.
    val ok = KafkaAuditSink.Config(
      bootstrapServers = "127.0.0.1:9092",
      topic = "topic-ok",
      clientId = "test",
      maxRetries = 2,
      initialBackoff = 50.millis,
      maxBackoff = 200.millis,
      deadLetterFile = freshDlqPath(),
      queueCapacity = 16
    )
    intercept[IllegalArgumentException](ok.copy(bootstrapServers = ""))
      .getMessage should include("bootstrapServers")
    intercept[IllegalArgumentException](ok.copy(topic = ""))
      .getMessage should include("topic")
    intercept[IllegalArgumentException](ok.copy(maxRetries = -1))
      .getMessage should include("maxRetries")
    intercept[IllegalArgumentException](ok.copy(queueCapacity = 0))
      .getMessage should include("queueCapacity")
  }
