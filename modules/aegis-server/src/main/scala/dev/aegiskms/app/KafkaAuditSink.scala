package dev.aegiskms.app

import cats.effect.std.Queue
import cats.effect.{IO, Resource}
import dev.aegiskms.audit.AuditRecordJson.given
import dev.aegiskms.audit.{AuditRecord, AuditSink}
import io.circe.syntax.*
import org.apache.kafka.clients.producer.{ProducerConfig, ProducerRecord}
import org.apache.kafka.common.serialization.{ByteArraySerializer, StringSerializer}
import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.kafka.ProducerSettings
import org.apache.pekko.kafka.scaladsl.SendProducer
import org.slf4j.LoggerFactory

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, StandardOpenOption}
import scala.concurrent.duration.*

/** Kafka audit fan-out sink (#22). Records are enqueued by `write` and drained by a single background fiber
  * that publishes them — one record per Kafka message — to the configured topic. Closes ROADMAP 2.0.j.
  *
  * Why a queue + background fiber instead of inline publish: same reason as `WebhookAuditSink` — broker
  * delivery latency is decoupled from the KMS request path. The Kafka client's own idempotent producer
  * (enabled by default in this sink, `acks=all + enable.idempotence=true`) handles in-broker retries and
  * exactly-once delivery semantics; our outer retry loop catches the case where the producer itself surfaces
  * a terminal failure (broker unreachable, ACL rejection, etc.) and falls back to the disk dead-letter for
  * operator intervention.
  *
  * Idempotent producer config:
  *   - `acks=all` — wait for ISR replication before ack
  *   - `enable.idempotence=true` — broker dedupes producer epochs
  *   - `max.in.flight.requests.per.connection=5` (Kafka requires ≤ 5 for idempotence)
  *   - `retries=Int.MaxValue` — producer retries internally up to `delivery.timeout.ms`
  *
  * Key strategy: each record's Kafka key is the `correlationId`. This co-locates records from the same KMS
  * request onto the same partition, preserving order for downstream consumers.
  *
  * Dead-letter file: one JSON object per line, appended to `deadLetterFile` after `maxRetries` consecutive
  * transport failures. Format identical to [[WebhookAuditSink]] for operator parity.
  */
final class KafkaAuditSink private (
    queue: Queue[IO, AuditRecord]
) extends AuditSink[IO]:
  def write(record: AuditRecord): IO[Unit] = queue.offer(record)

object KafkaAuditSink:

  final case class Config(
      bootstrapServers: String,
      topic: String,
      clientId: String,
      maxRetries: Int,
      initialBackoff: FiniteDuration,
      maxBackoff: FiniteDuration,
      deadLetterFile: Path,
      queueCapacity: Int,
      /** Controls how long `Producer.send()` blocks waiting for metadata before surfacing a
        * `TimeoutException`. Kafka default is 60 s, which is reasonable for production (gives
        * a brief broker outage time to recover) but pathological for tests that point at a
        * closed port. Operators rarely need to tune this; tests override it to a small value
        * to validate the transport-failure → DLQ path deterministically.
        */
      maxBlockMs: Long = 60000L
  ):
    require(bootstrapServers.nonEmpty, "bootstrapServers must be non-empty")
    require(topic.nonEmpty, "topic must be non-empty")
    require(maxRetries >= 0, s"maxRetries must be >= 0, was $maxRetries")
    require(queueCapacity > 0, s"queueCapacity must be > 0, was $queueCapacity")
    require(maxBlockMs > 0, s"maxBlockMs must be > 0, was $maxBlockMs")

  private val logger = LoggerFactory.getLogger(classOf[KafkaAuditSink])

  /** Build the sink. Acquires queue + SendProducer + drain fiber; release flushes and closes the SendProducer
    * (waits up to 10s for in-flight messages to be ack'd) and cancels the fiber.
    */
  def make(config: Config)(using system: ActorSystem[?]): Resource[IO, AuditSink[IO]] =
    for
      producer <- producerResource(config)
      q        <- Resource.eval(Queue.bounded[IO, AuditRecord](config.queueCapacity))
      _ <- Resource.eval(IO {
        logger.info(
          s"audit kafka: bootstrap=${config.bootstrapServers}, topic=${config.topic}, " +
            s"client-id=${config.clientId}, max-retries=${config.maxRetries}, " +
            s"queue-capacity=${config.queueCapacity}, dead-letter=${config.deadLetterFile}"
        )
      })
      _ <- Resource.make(drainLoop(q, producer, config).start)(f => f.cancel)
    yield new KafkaAuditSink(q)

  // ── SendProducer Resource ─────────────────────────────────────────────────

  private def producerResource(config: Config)(using
      system: ActorSystem[?]
  ): Resource[IO, SendProducer[String, Array[Byte]]] =
    val classicSystem = system.classicSystem
    val baseSettings = ProducerSettings(
      classicSystem,
      new StringSerializer(),
      new ByteArraySerializer()
    )
      .withBootstrapServers(config.bootstrapServers)
      .withProperties(
        ProducerConfig.CLIENT_ID_CONFIG                      -> config.clientId,
        ProducerConfig.ACKS_CONFIG                           -> "all",
        ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG             -> "true",
        ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION -> "5",
        ProducerConfig.RETRIES_CONFIG                        -> Int.MaxValue.toString,
        ProducerConfig.COMPRESSION_TYPE_CONFIG               -> "lz4",
        ProducerConfig.MAX_BLOCK_MS_CONFIG                   -> config.maxBlockMs.toString
      )
    Resource.make(
      IO(SendProducer(baseSettings)(classicSystem))
    ) { producer =>
      IO.fromFuture(IO(producer.close())).void.handleErrorWith { t =>
        IO(logger.warn(s"audit kafka: producer shutdown reported error: ${t.getMessage}", t))
      }
    }

  // ── Drain loop ────────────────────────────────────────────────────────────

  private def drainLoop(
      queue: Queue[IO, AuditRecord],
      producer: SendProducer[String, Array[Byte]],
      config: Config
  ): IO[Unit] =
    val tick: IO[Unit] =
      for
        record <- queue.take
        _ <- attemptWithRetry(record, producer, config, attempt = 0).handleErrorWith { t =>
          IO(logger.error(
            "audit kafka: unhandled error draining record " +
              s"(correlationId=${record.correlationId}): ${t.getMessage}",
            t
          )) *> writeDeadLetter(record, config)
        }
      yield ()
    tick.foreverM

  private def attemptWithRetry(
      record: AuditRecord,
      producer: SendProducer[String, Array[Byte]],
      config: Config,
      attempt: Int
  ): IO[Unit] =
    publish(record, producer, config).attempt.flatMap {
      case Right(_) =>
        IO.unit
      case Left(t) =>
        if attempt >= config.maxRetries then
          IO(logger.warn(
            s"audit kafka: max retries (${config.maxRetries}) exhausted for " +
              s"correlationId=${record.correlationId}; sending to DLQ. last=${t.getMessage}"
          )) *> writeDeadLetter(record, config)
        else
          val backoff = nextBackoff(attempt, config)
          IO(logger.info(
            s"audit kafka: retryable failure (${t.getClass.getSimpleName}: ${t.getMessage}) for " +
              s"correlationId=${record.correlationId}, attempt=${attempt + 1}/${config.maxRetries}, " +
              s"sleeping ${backoff.toMillis}ms"
          )) *> IO.sleep(backoff) *> attemptWithRetry(record, producer, config, attempt + 1)
    }

  private def publish(
      record: AuditRecord,
      producer: SendProducer[String, Array[Byte]],
      config: Config
  ): IO[Unit] =
    val body = record.asJson.noSpaces.getBytes(StandardCharsets.UTF_8)
    val msg  = new ProducerRecord[String, Array[Byte]](config.topic, record.correlationId, body)
    IO.fromFuture(IO(producer.send(msg))).void

  private def nextBackoff(attempt: Int, config: Config): FiniteDuration =
    val raw = config.initialBackoff * Math.pow(2.0, attempt.toDouble).toLong
    if raw > config.maxBackoff then config.maxBackoff else raw

  // ── Dead-letter ───────────────────────────────────────────────────────────

  private def writeDeadLetter(record: AuditRecord, config: Config): IO[Unit] =
    IO.blocking {
      val line = record.asJson.noSpaces + "\n"
      Option(config.deadLetterFile.getParent).foreach(Files.createDirectories(_))
      Files.write(
        config.deadLetterFile,
        line.getBytes(StandardCharsets.UTF_8),
        StandardOpenOption.CREATE,
        StandardOpenOption.APPEND
      )
      ()
    }.handleErrorWith { t =>
      IO(logger.error(
        s"audit kafka: DLQ write to ${config.deadLetterFile} failed for " +
          s"correlationId=${record.correlationId}: ${t.getMessage}",
        t
      ))
    }
