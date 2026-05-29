package dev.aegiskms.app

import cats.effect.std.Queue
import cats.effect.{IO, Resource}
import dev.aegiskms.audit.AuditRecordJson.given
import dev.aegiskms.audit.{AuditRecord, AuditSink}
import io.circe.syntax.*
import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.model.headers.RawHeader
import org.apache.pekko.stream.Materializer
import org.slf4j.LoggerFactory

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, StandardOpenOption}
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.concurrent.duration.*

/** Pluggable SIEM webhook sink (#21). Records are enqueued by `write` and drained by a single background
  * fiber that POSTs them — one record per request — to the configured `url`. Closes ROADMAP 2.0.i.
  *
  * Why a queue instead of writing inline: webhook delivery is best-effort and the SIEM may be slow,
  * congested, or briefly down. Inline writes would couple every KMS operation's latency to the SIEM's health;
  * the queue decouples them. The queue is **bounded** (`queueCapacity`) so a sustained outage eventually
  * backpressures the caller rather than silently growing the heap — when full, `write` blocks on
  * `Queue.offer`, which back-propagates through `AuditingKeyService.sink.write` to the `KeyService` call site
  * (acceptable: when the audit pipeline can't keep up, you don't want to silently lose records).
  *
  * Retry semantics: each record gets up to `maxRetries` attempts with exponential backoff capped at
  * `maxBackoff`. Failures fall into three buckets:
  *   - **2xx response** → success, ack the record.
  *   - **4xx response** (client error: malformed body, auth rejected, etc.) → DLQ immediately. Retrying a
  *     401/422 is pointless and would just amplify the problem.
  *   - **5xx response or transport error** (timeout, connection refused) → retry with backoff. After
  *     `maxRetries` consecutive failures the record is DLQ'd.
  *
  * Dead-letter: one JSON object per line, appended to `deadLetterFile`. The format matches `AuditRecordJson`
  * exactly so operators can `cat dlq | curl ...` to re-deliver after fixing the SIEM.
  *
  * HMAC signing: every body is signed with HMAC-SHA256 using `secret` and sent in `X-Aegis-Signature:
  * sha256=<hex>` — same convention as GitHub webhooks. SIEMs verify by recomputing over the raw body. The
  * header name uses `X-Aegis-Signature` so a fronting WAF can match on it.
  *
  * Construction is `Resource`-managed: acquiring builds the queue and starts the drain fiber; release cancels
  * the fiber. The pekko `Http` extension is taken from the implicit `ActorSystem`, so the same one the HTTP
  * server uses serves the webhook POSTs — no extra connection pool.
  */
final class WebhookAuditSink private (
    queue: Queue[IO, AuditRecord]
) extends AuditSink[IO]:
  def write(record: AuditRecord): IO[Unit] = queue.offer(record)

object WebhookAuditSink:

  final case class Config(
      url: Uri,
      secret: String,
      maxRetries: Int,
      initialBackoff: FiniteDuration,
      maxBackoff: FiniteDuration,
      deadLetterFile: Path,
      queueCapacity: Int
  ):
    require(maxRetries >= 0, s"maxRetries must be >= 0, was $maxRetries")
    require(queueCapacity > 0, s"queueCapacity must be > 0, was $queueCapacity")
    require(secret.nonEmpty, "secret must be non-empty (HMAC signing requires a key)")

  private val logger = LoggerFactory.getLogger(classOf[WebhookAuditSink])

  /** Build the sink. Acquires the queue + drain fiber; release cancels the fiber so any records still pending
    * on shutdown are LOST (a deliberate trade-off — alternative is a synchronous flush which would couple
    * server shutdown latency to the SIEM's health). Operators worried about the boundary should run the SIEM
    * colocated; the queue capacity provides a buffer for transient blips.
    */
  def make(config: Config)(using system: ActorSystem[?]): Resource[IO, AuditSink[IO]] =
    for
      q <- Resource.eval(Queue.bounded[IO, AuditRecord](config.queueCapacity))
      _ <- Resource.eval(IO {
        logger.info(
          s"audit webhook: ${config.url} (max-retries=${config.maxRetries}, " +
            s"initial-backoff=${config.initialBackoff.toMillis}ms, " +
            s"max-backoff=${config.maxBackoff.toMillis}ms, " +
            s"queue-capacity=${config.queueCapacity}, " +
            s"dead-letter=${config.deadLetterFile})"
        )
      })
      _ <- Resource.make(drainLoop(q, config).start)(_.cancel)
    yield new WebhookAuditSink(q)

  // ── Drain loop ────────────────────────────────────────────────────────────

  /** Forever: pull a record, attempt delivery with retry, DLQ on terminal failure, loop. Any unexpected
    * throwable inside the delivery path is caught and logged so the loop can never silently die.
    */
  private def drainLoop(queue: Queue[IO, AuditRecord], config: Config)(using
      ActorSystem[?]
  ): IO[Unit] =
    val tick: IO[Unit] =
      for
        record <- queue.take
        _ <- attemptWithRetry(record, config, attempt = 0).handleErrorWith { t =>
          IO(logger.error(
            "audit webhook: unhandled error draining record " +
              s"(correlationId=${record.correlationId}): ${t.getMessage}",
            t
          )) *> writeDeadLetter(record, config)
        }
      yield ()
    tick.foreverM

  /** Single delivery attempt. On success → ack; on retryable failure → backoff + recurse with `attempt+1`; on
    * max-retries → DLQ.
    */
  private def attemptWithRetry(
      record: AuditRecord,
      config: Config,
      attempt: Int
  )(using ActorSystem[?]): IO[Unit] =
    deliver(record, config).flatMap {
      case Outcome.Success =>
        IO.unit
      case Outcome.ClientError(status, body) =>
        // 4xx — no retry. DLQ so operator can inspect; the SIEM rejected the shape or auth and
        // backing off won't help.
        IO(logger.warn(
          s"audit webhook: 4xx ($status) from ${config.url} for " +
            s"correlationId=${record.correlationId}; sending to DLQ. body=${truncate(body, 200)}"
        )) *> writeDeadLetter(record, config)
      case Outcome.Retryable(reason) =>
        if attempt >= config.maxRetries then
          IO(logger.warn(
            s"audit webhook: max retries (${config.maxRetries}) exhausted for " +
              s"correlationId=${record.correlationId}; sending to DLQ. last=$reason"
          )) *> writeDeadLetter(record, config)
        else
          val backoff = nextBackoff(attempt, config)
          IO(logger.info(
            s"audit webhook: retryable failure ($reason) for correlationId=${record.correlationId}, " +
              s"attempt=${attempt + 1}/${config.maxRetries}, sleeping ${backoff.toMillis}ms"
          )) *> IO.sleep(backoff) *> attemptWithRetry(record, config, attempt + 1)
    }

  /** Compute the backoff for `attempt` (zero-indexed). Exponential, capped at `maxBackoff`. */
  private def nextBackoff(attempt: Int, config: Config): FiniteDuration =
    val raw = config.initialBackoff * Math.pow(2.0, attempt.toDouble).toLong
    if raw > config.maxBackoff then config.maxBackoff else raw

  // ── HTTP delivery ─────────────────────────────────────────────────────────

  sealed private trait Outcome
  private object Outcome:
    case object Success                                     extends Outcome
    final case class ClientError(status: Int, body: String) extends Outcome
    final case class Retryable(reason: String)              extends Outcome

  /** POST the record. Translates the HTTP response (or transport failure) into an `Outcome`. */
  private def deliver(record: AuditRecord, config: Config)(using
      system: ActorSystem[?]
  ): IO[Outcome] =
    val bodyBytes = record.asJson.noSpaces.getBytes(StandardCharsets.UTF_8)
    val signature = signBody(config.secret, bodyBytes)
    val request = HttpRequest(
      method = HttpMethods.POST,
      uri = config.url,
      headers = scala.collection.immutable.Seq(
        RawHeader("X-Aegis-Signature", s"sha256=$signature"),
        RawHeader("User-Agent", "aegis-kms-webhook/1")
      ),
      entity = HttpEntity(ContentTypes.`application/json`, bodyBytes)
    )
    val classicSystem  = system.classicSystem
    given Materializer = Materializer.matFromSystem(classicSystem)
    IO.fromFuture(IO(Http()(classicSystem).singleRequest(request)))
      .flatMap { response =>
        // Always drain the entity to release the connection back to the pool. Body is only kept on
        // 4xx so the warn log can include it.
        val statusCode = response.status.intValue
        if statusCode >= 200 && statusCode < 300 then
          IO.fromFuture(IO(response.discardEntityBytes().future()))
            .as(Outcome.Success)
        else if statusCode >= 400 && statusCode < 500 then
          IO.fromFuture(IO(response.entity.toStrict(2.seconds)))
            .map(strict => Outcome.ClientError(statusCode, strict.data.utf8String))
        else
          IO.fromFuture(IO(response.discardEntityBytes().future()))
            .as(Outcome.Retryable(s"http $statusCode"))
      }
      .handleError(t => Outcome.Retryable(s"transport: ${t.getMessage}"))

  /** HMAC-SHA256 hex. Matches what a SIEM receiver would compute with `openssl dgst -sha256 -hmac <secret>`
    * over the raw body.
    */
  private[app] def signBody(secret: String, body: Array[Byte]): String =
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"))
    mac.doFinal(body).map(b => f"$b%02x").mkString

  // ── Dead-letter ───────────────────────────────────────────────────────────

  /** Append one JSON line to the dead-letter file. Best-effort: if even the DLQ write fails (disk full,
    * permission denied) we log at ERROR and drop the record — at that point the operator has bigger problems
    * than this one missing audit row.
    */
  private def writeDeadLetter(record: AuditRecord, config: Config): IO[Unit] =
    IO.blocking {
      val line = record.asJson.noSpaces + "\n"
      // Ensure the parent dir exists so the first DLQ write doesn't fail on a fresh deployment that
      // never created /var/lib/aegis. createDirectories is a no-op when the dir already exists.
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
        s"audit webhook: DLQ write to ${config.deadLetterFile} failed for " +
          s"correlationId=${record.correlationId}: ${t.getMessage}",
        t
      ))
    }

  private def truncate(s: String, max: Int): String =
    if s.length <= max then s else s.take(max) + "…(truncated)"
