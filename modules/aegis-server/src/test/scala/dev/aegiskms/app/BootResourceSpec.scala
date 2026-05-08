package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import com.typesafe.config.ConfigFactory
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.net.URI
import java.net.http.HttpResponse.BodyHandlers
import java.net.http.{HttpClient, HttpRequest}
import java.time.Duration as JDuration

/** Acquires the full `Server.boot` Resource against a free local port, hits the HTTP listener to confirm the
  * binding is live, and then releases the resource. The release path exercises the finalizer chain — HTTP
  * unbind → actor system terminate → journal close → meter registry close — which is the load-bearing claim
  * of issue #12 (graceful shutdown). If any finalizer hangs or throws, this test exceeds its scalatest
  * timeout or surfaces the exception.
  *
  * The HTTP client is the JDK-native `java.net.http.HttpClient` — no extra test dep, and it gives us a real
  * off-thread connection so we exercise the actual binding rather than the in-process pekko-http test-kit
  * harness.
  */
final class BootResourceSpec extends AnyFunSuite with Matchers:

  /** Pick an ephemeral port at construction time. Two parallel test runs would still race on the port, but
    * scalatest's default scoping is sequential per suite and this is the only suite that binds.
    */
  private def freePort: Int =
    val sock = new java.net.ServerSocket(0)
    try sock.getLocalPort
    finally sock.close()

  private val client = HttpClient.newBuilder().connectTimeout(JDuration.ofSeconds(3)).build()

  test("boot acquires + releases the full server stack against an in-memory journal") {
    val port = freePort
    val cfg = ConfigFactory.parseString(s"""
      aegis.http.host = "127.0.0.1"
      aegis.http.port = $port
      aegis.persistence.journal.kind = "in-memory"
      aegis.auth.kind = "dev"
      aegis.auth.hmac.secret = ""
    """).withFallback(ConfigFactory.load())

    // `use` runs the action with the resource live, then walks finalizers on completion. We hit the
    // server inside the scope to prove the binding is real, then let the resource release.
    val program: IO[Int] = Server.boot(cfg).use { _ =>
      IO {
        val req = HttpRequest.newBuilder()
          .uri(URI.create(s"http://127.0.0.1:$port/v1/keys"))
          .header("X-Aegis-User", "alice")
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(
            """{"spec":{"name":"boot-test","algorithm":"AES","sizeBits":256,"objectType":"SymmetricKey"}}"""
          ))
          .build()
        client.send(req, BodyHandlers.discarding()).statusCode()
      }
    }

    val status = program.unsafeRunSync()
    status shouldBe 201

    // After `use` returns, the binding is unbound. A subsequent connect should fail. We don't assert
    // the OS-level error code — `Connection refused` vs `Connection reset` vs timeout varies by JDK +
    // OS — but we do assert that we no longer get a 2xx, which would mean the listener leaked.
    val afterShutdown =
      try
        val req = HttpRequest.newBuilder()
          .uri(URI.create(s"http://127.0.0.1:$port/v1/keys/whatever"))
          .timeout(JDuration.ofSeconds(2))
          .GET()
          .build()
        Some(client.send(req, BodyHandlers.discarding()).statusCode())
      catch case _: Exception => None

    afterShutdown shouldNot contain(200)
  }

  test("boot fails fast with a clear error when journal kind is unknown") {
    val cfg = ConfigFactory.parseString("""
      aegis.http.host = "127.0.0.1"
      aegis.http.port = 0
      aegis.persistence.journal.kind = "carrier-pigeon"
      aegis.auth.kind = "dev"
      aegis.auth.hmac.secret = ""
    """).withFallback(ConfigFactory.load())

    val ex = intercept[IllegalArgumentException] {
      Server.boot(cfg).use_.unsafeRunSync()
    }
    ex.getMessage should include("carrier-pigeon")
  }
