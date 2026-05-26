package dev.aegiskms.app

import cats.effect.unsafe.IORuntime
import cats.effect.{IO, Ref}
import dev.aegiskms.audit.AuditRecord
import dev.aegiskms.core.{Operation, Principal}
import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.actor.typed.scaladsl.Behaviors
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.Http.ServerBinding
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.server.Directives.*
import org.apache.pekko.http.scaladsl.server.Route
import org.scalatest.BeforeAndAfterAll
import org.scalatest.OptionValues.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import scala.concurrent.duration.*

/** Integration tests for `WebhookAuditSink` (#21). Spins up a real pekko-http server on `127.0.0.1:0` per
  * test, points the sink at it, exercises the sink, then unbinds. This is the only way to validate end-to-end
  * that:
  *   - the HMAC signature header is well-formed and matches what a SIEM receiver would recompute,
  *   - 2xx responses ack the record (no DLQ entry),
  *   - 4xx responses skip retry and DLQ immediately,
  *   - 5xx responses retry up to `maxRetries` then DLQ,
  *   - the dead-letter file is created and contains JSONL.
  *
  * No external dependencies — pekko-http and JDK file APIs are sufficient.
  */
final class WebhookAuditSinkSpec extends AnyFunSuite with Matchers with BeforeAndAfterAll:

  private given IORuntime = IORuntime.global

  // One ActorSystem for all tests in this suite. Behaviors.empty is the standard "do-nothing"
  // user guardian for tests that only need the system as a Materializer + Http() extension.
  implicit private lazy val system: ActorSystem[Nothing] =
    ActorSystem(Behaviors.empty[Nothing], "WebhookAuditSinkSpec")

  override def afterAll(): Unit =
    system.terminate()
    super.afterAll()

  // ── Helpers ────────────────────────────────────────────────────────────────

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def sampleRecord(corr: String = "c-1"): AuditRecord =
    AuditRecord(
      at = Instant.parse("2026-05-26T10:14:53Z"),
      principal = alice,
      operation = Operation.Sign,
      resource = "key:invoice-2026",
      outcome = "Success",
      correlationId = corr,
      context = Map("source.ip" -> "203.0.113.42")
    )

  /** What the receiver captured for one POST attempt. */
  final private case class Captured(body: String, signatureHeader: Option[String])

  /** Bind a one-shot test server with the given Route to a random port; returns the URL and the binding (so
    * the test can unbind on cleanup).
    */
  private def bindServer(route: Route): IO[(String, ServerBinding)] =
    IO.fromFuture(IO(Http().newServerAt("127.0.0.1", 0).bind(route))).map { binding =>
      val port = binding.localAddress.getPort
      (s"http://127.0.0.1:$port/sink", binding)
    }

  private def unbind(binding: ServerBinding): IO[Unit] =
    IO.fromFuture(IO(binding.terminate(hardDeadline = 1.second))).void

  /** A test route that always responds with `statusCode`, capturing every body + signature header into the
    * supplied `Ref` for assertions.
    */
  private def alwaysRoute(statusCode: Int, captured: Ref[IO, List[Captured]]): Route =
    extractRequest { req =>
      val sigHeader = req.headers.find(_.name == "X-Aegis-Signature").map(_.value)
      entity(as[String]) { body =>
        // The Ref update has to run on the cats-effect runtime; we do it synchronously here so
        // the order matches the request order.
        captured.update(_ :+ Captured(body, sigHeader)).unsafeRunSync()
        complete(StatusCodes.custom(statusCode, ""))
      }
    }

  private def baseConfig(url: String, dlq: Path): WebhookAuditSink.Config =
    WebhookAuditSink.Config(
      url = Uri(url),
      secret = "test-shared-secret-32-bytes-long!!",
      maxRetries = 2,
      initialBackoff = 50.millis,
      maxBackoff = 200.millis,
      deadLetterFile = dlq,
      queueCapacity = 16
    )

  private def freshDlqPath(): Path =
    val f = Files.createTempFile("aegis-webhook-dlq-", ".jsonl")
    Files.delete(f) // delete; the sink will recreate
    f

  /** Wait until `predicate` is true (polling every 25ms), or fail after `total`. Keeps the tests fast without
    * leaning on arbitrary `Thread.sleep`.
    */
  private def waitUntil(total: FiniteDuration)(predicate: => Boolean): Unit =
    val deadline = System.currentTimeMillis() + total.toMillis
    while !predicate && System.currentTimeMillis() < deadline do Thread.sleep(25)
    if !predicate then fail(s"condition not met within $total")

  // ── Tests ──────────────────────────────────────────────────────────────────

  test("happy path: 2xx response acks the record (no DLQ entry)") {
    val captured = Ref.unsafe[IO, List[Captured]](Nil)
    val dlq      = freshDlqPath()
    val program: IO[Unit] =
      bindServer(alwaysRoute(200, captured)).bracket { case (url, _) =>
        WebhookAuditSink.make(baseConfig(url, dlq)).use { sink =>
          sink.write(sampleRecord("c-200")) *> IO {
            waitUntil(2.seconds)(captured.get.unsafeRunSync().nonEmpty)
          }
        }
      } { case (_, binding) => unbind(binding) }
    program.unsafeRunSync()

    val all = captured.get.unsafeRunSync()
    all.size shouldBe 1
    all.head.body should include(""""correlationId":"c-200"""")
    all.head.signatureHeader.value should startWith("sha256=")
    // Hex is 64 chars for SHA-256 (32 bytes × 2). Plus "sha256=" prefix = 71.
    all.head.signatureHeader.value.length shouldBe 71
    // No DLQ entry — the sink succeeded.
    Files.exists(dlq) shouldBe false
  }

  test("HMAC signature matches what an independent verifier would compute") {
    val captured = Ref.unsafe[IO, List[Captured]](Nil)
    val dlq      = freshDlqPath()
    val config   = baseConfig("http://placeholder", dlq) // url overridden below

    val program: IO[Captured] =
      bindServer(alwaysRoute(200, captured)).bracket { case (url, _) =>
        val realConfig = config.copy(url = Uri(url))
        WebhookAuditSink.make(realConfig).use { sink =>
          sink.write(sampleRecord("c-sig")) *> IO {
            waitUntil(2.seconds)(captured.get.unsafeRunSync().nonEmpty)
            captured.get.unsafeRunSync().head
          }
        }
      } { case (_, binding) => unbind(binding) }
    val cap = program.unsafeRunSync()

    val expectedHex = WebhookAuditSink.signBody(config.secret, cap.body.getBytes(StandardCharsets.UTF_8))
    cap.signatureHeader.value shouldBe s"sha256=$expectedHex"
  }

  test("4xx response → no retry, dead-letter immediately (auth/malformed are not transient)") {
    val captured = Ref.unsafe[IO, List[Captured]](Nil)
    val dlq      = freshDlqPath()
    val program: IO[Unit] =
      bindServer(alwaysRoute(401, captured)).bracket { case (url, _) =>
        WebhookAuditSink.make(baseConfig(url, dlq)).use { sink =>
          sink.write(sampleRecord("c-401")) *> IO {
            waitUntil(2.seconds)(Files.exists(dlq))
          }
        }
      } { case (_, binding) => unbind(binding) }
    program.unsafeRunSync()

    // Receiver was called exactly once — no retry on 4xx.
    captured.get.unsafeRunSync().size shouldBe 1
    val dlqLines = Files.readAllLines(dlq)
    dlqLines.size shouldBe 1
    dlqLines.get(0) should include(""""correlationId":"c-401"""")
  }

  test("5xx response → retries up to maxRetries+1 attempts, then dead-letter") {
    val attempts = new AtomicInteger(0)
    val dlq      = freshDlqPath()
    val route: Route = extractRequest { _ =>
      entity(as[String]) { _ =>
        attempts.incrementAndGet()
        complete(StatusCodes.custom(503, ""))
      }
    }

    val program: IO[Unit] =
      bindServer(route).bracket { case (url, _) =>
        // maxRetries=2 means: attempt 0 + retry 1 + retry 2 = 3 total attempts before DLQ.
        WebhookAuditSink.make(baseConfig(url, dlq)).use { sink =>
          sink.write(sampleRecord("c-503")) *> IO {
            waitUntil(5.seconds)(Files.exists(dlq))
          }
        }
      } { case (_, binding) => unbind(binding) }
    program.unsafeRunSync()

    attempts.get shouldBe 3
    val dlqLines = Files.readAllLines(dlq)
    dlqLines.size shouldBe 1
    dlqLines.get(0) should include(""""correlationId":"c-503"""")
  }

  test("transport failure (connection refused) is retried like a 5xx") {
    val dlq = freshDlqPath()
    // Bind, then immediately unbind so the port is closed by the time the sink tries to POST.
    val (deadUrl, binding) = bindServer(alwaysRoute(200, Ref.unsafe[IO, List[Captured]](Nil)))
      .unsafeRunSync()
    unbind(binding).unsafeRunSync()
    // Brief pause to let the OS reclaim the listening socket. We don't care if anything is
    // bound at the new connection time — refused / RST counts as transport failure.
    Thread.sleep(100)

    val program = WebhookAuditSink.make(baseConfig(deadUrl, dlq)).use { sink =>
      sink.write(sampleRecord("c-refused")) *> IO {
        waitUntil(5.seconds)(Files.exists(dlq))
      }
    }
    program.unsafeRunSync()

    val dlqLines = Files.readAllLines(dlq)
    dlqLines.size shouldBe 1
    dlqLines.get(0) should include(""""correlationId":"c-refused"""")
  }

  test("dead-letter file is JSONL — one record per line, parseable") {
    import io.circe.parser
    val dlq = freshDlqPath()
    val program: IO[Unit] =
      bindServer(alwaysRoute(401, Ref.unsafe[IO, List[Captured]](Nil))).bracket {
        case (url, _) =>
          WebhookAuditSink.make(baseConfig(url, dlq)).use { sink =>
            sink.write(sampleRecord("c-a")) *>
              sink.write(sampleRecord("c-b")) *>
              sink.write(sampleRecord("c-c")) *> IO {
                // Gate the line-count check behind exists() so the first poll doesn't blow up
                // with NoSuchFileException before the drain fiber has had a chance to write.
                waitUntil(3.seconds)(
                  Files.exists(dlq) && Files.readAllLines(dlq).size == 3
                )
              }
          }
      } { case (_, binding) => unbind(binding) }
    program.unsafeRunSync()

    val lines = Files.readAllLines(dlq)
    lines.size shouldBe 3
    lines.forEach { line =>
      val json = parser.parse(line).fold(throw _, identity)
      json.hcursor.downField("correlationId").as[String].fold(throw _, identity) should
        (be("c-a") or be("c-b") or be("c-c"))
    }
  }
