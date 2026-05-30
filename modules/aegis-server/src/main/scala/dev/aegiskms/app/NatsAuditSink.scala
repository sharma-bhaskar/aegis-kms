package dev.aegiskms.app

import cats.effect.std.Queue
import cats.effect.{IO, Resource}
import dev.aegiskms.audit.AuditRecordJson.given
import dev.aegiskms.audit.{AuditRecord, AuditSink}
import io.circe.syntax.*
import io.nats.client.api.{RetentionPolicy, StorageType, StreamConfiguration}
import io.nats.client.{Connection, JetStream, Nats, Options}
import org.slf4j.LoggerFactory

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, StandardOpenOption}
import scala.concurrent.duration.*

/** NATS JetStream audit fan-out sink (#23). Records are enqueued by `write` and drained by a single
  * background fiber that publishes them — one record per JetStream message — to the configured subject.
  * Closes ROADMAP audit fan-out track for the NATS shop.
  *
  * Why JetStream specifically (vs core NATS pub/sub): JetStream is the persistent / at-least-once variant.
  * `publishAsync` returns a `CompletableFuture<PubAck>` that completes only after the broker has durably
  * accepted the message into the stream. Core NATS pub/sub is fire-and-forget and would lose records on
  * broker restart — unacceptable for an audit pipeline.
  *
  * Stream provisioning: when `autoCreateStream=true`, the sink creates the configured stream on boot if it
  * doesn't already exist (idempotent — existing streams are left untouched). The stream is configured with
  * `StorageType.File` retention so messages survive restart. Operators with their own provisioning flow
  * should set `autoCreateStream=false` and pre-create the stream via NATS CLI / Terraform / etc.
  *
  * Dead-letter: one JSON object per line appended to `deadLetterFile` after `maxRetries` consecutive
  * transport failures. Format identical to [[WebhookAuditSink]] / [[KafkaAuditSink]] for operator parity.
  */
final class NatsAuditSink private (
    queue: Queue[IO, AuditRecord]
) extends AuditSink[IO]:
  def write(record: AuditRecord): IO[Unit] = queue.offer(record)

object NatsAuditSink:

  final case class Config(
      servers: String,
      stream: String,
      subject: String,
      autoCreateStream: Boolean,
      credentialsFile: Option[Path],
      maxRetries: Int,
      initialBackoff: FiniteDuration,
      maxBackoff: FiniteDuration,
      deadLetterFile: Path,
      queueCapacity: Int
  ):
    require(servers.nonEmpty, "servers must be non-empty")
    require(stream.nonEmpty, "stream must be non-empty")
    require(subject.nonEmpty, "subject must be non-empty")
    require(maxRetries >= 0, s"maxRetries must be >= 0, was $maxRetries")
    require(queueCapacity > 0, s"queueCapacity must be > 0, was $queueCapacity")

  private val logger = LoggerFactory.getLogger(classOf[NatsAuditSink])

  /** Build the sink. Acquires NATS connection + JetStream context + queue + drain fiber; release cancels the
    * fiber, drains the JetStream context, and closes the connection.
    */
  def make(config: Config): Resource[IO, AuditSink[IO]] =
    for
      connection <- connectionResource(config)
      jetStream  <- Resource.eval(IO(connection.jetStream()))
      _          <- Resource.eval(maybeCreateStream(connection, config))
      q          <- Resource.eval(Queue.bounded[IO, AuditRecord](config.queueCapacity))
      _ <- Resource.eval(IO {
        logger.info(
          s"audit nats: servers=${config.servers}, stream=${config.stream}, " +
            s"subject=${config.subject}, max-retries=${config.maxRetries}, " +
            s"queue-capacity=${config.queueCapacity}, dead-letter=${config.deadLetterFile}"
        )
      })
      _ <- Resource.make(drainLoop(q, jetStream, config).start)(f => f.cancel)
    yield new NatsAuditSink(q)

  // ── Connection Resource ───────────────────────────────────────────────────

  private def connectionResource(config: Config): Resource[IO, Connection] =
    Resource.make(IO {
      val builder = new Options.Builder()
        .server(config.servers)
        .connectionTimeout(java.time.Duration.ofSeconds(5))
        .reconnectWait(java.time.Duration.ofSeconds(2))
        .maxReconnects(-1)
      config.credentialsFile.foreach(p => builder.authHandler(Nats.credentials(p.toString)))
      Nats.connect(builder.build())
    }) { conn =>
      IO(conn.close()).handleErrorWith(t =>
        IO(logger.warn(s"audit nats: connection close reported error: ${t.getMessage}", t))
      )
    }

  /** Idempotent stream provisioning. JetStream's `addStream` errors with `JetStreamApiException` when the
    * stream already exists; we treat that as a no-op so the boot path is safe to re-run.
    */
  private def maybeCreateStream(connection: Connection, config: Config): IO[Unit] =
    if !config.autoCreateStream then IO.unit
    else
      IO {
        val jsm = connection.jetStreamManagement()
        val existing =
          try
            val info = jsm.getStreamInfo(config.stream)
            Option(info)
          catch case _: io.nats.client.JetStreamApiException => None
        if existing.isEmpty then
          val cfg = StreamConfiguration.builder()
            .name(config.stream)
            .subjects(config.subject)
            .storageType(StorageType.File)
            .retentionPolicy(RetentionPolicy.Limits)
            .build()
          jsm.addStream(cfg)
          logger.info(s"audit nats: created JetStream stream '${config.stream}'")
      }

  // ── Drain loop ────────────────────────────────────────────────────────────

  private def drainLoop(
      queue: Queue[IO, AuditRecord],
      jetStream: JetStream,
      config: Config
  ): IO[Unit] =
    val tick: IO[Unit] =
      for
        record <- queue.take
        _ <- attemptWithRetry(record, jetStream, config, attempt = 0).handleErrorWith { t =>
          IO(logger.error(
            "audit nats: unhandled error draining record " +
              s"(correlationId=${record.correlationId}): ${t.getMessage}",
            t
          )) *> writeDeadLetter(record, config)
        }
      yield ()
    tick.foreverM

  private def attemptWithRetry(
      record: AuditRecord,
      jetStream: JetStream,
      config: Config,
      attempt: Int
  ): IO[Unit] =
    publish(record, jetStream, config).attempt.flatMap {
      case Right(_) =>
        IO.unit
      case Left(t) =>
        if attempt >= config.maxRetries then
          IO(logger.warn(
            s"audit nats: max retries (${config.maxRetries}) exhausted for " +
              s"correlationId=${record.correlationId}; sending to DLQ. last=${t.getMessage}"
          )) *> writeDeadLetter(record, config)
        else
          val backoff = nextBackoff(attempt, config)
          IO(logger.info(
            s"audit nats: retryable failure (${t.getClass.getSimpleName}: ${t.getMessage}) for " +
              s"correlationId=${record.correlationId}, attempt=${attempt + 1}/${config.maxRetries}, " +
              s"sleeping ${backoff.toMillis}ms"
          )) *> IO.sleep(backoff) *> attemptWithRetry(record, jetStream, config, attempt + 1)
    }

  private def publish(record: AuditRecord, jetStream: JetStream, config: Config): IO[Unit] =
    val body = record.asJson.noSpaces.getBytes(StandardCharsets.UTF_8)
    IO.blocking {
      // publishAsync returns a CompletableFuture<PubAck>; we await it inside IO.blocking so
      // failure to durably accept the message surfaces as an exception caught by .attempt.
      val ack = jetStream.publishAsync(config.subject, body).get(10, java.util.concurrent.TimeUnit.SECONDS)
      if ack.hasError then
        throw new RuntimeException(s"NATS JetStream PubAck reported error: ${ack.getError}")
      ()
    }

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
        s"audit nats: DLQ write to ${config.deadLetterFile} failed for " +
          s"correlationId=${record.correlationId}: ${t.getMessage}",
        t
      ))
    }
