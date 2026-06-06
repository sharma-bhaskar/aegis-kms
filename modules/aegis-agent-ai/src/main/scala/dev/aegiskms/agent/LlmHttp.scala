package dev.aegiskms.agent

import cats.effect.IO

import java.net.URI
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.time.Duration

/** Minimal HTTP seam for the LLM provider adapters.
  *
  * Mirrors the CLI's `HttpPort`: a one-method port so adapters can be unit-tested with a hand-rolled stub —
  * asserting the request shape and returning canned JSON — with no live network and no real API key. The
  * advisor only ever issues a single bounded request/response completion, so streaming is out of scope; the
  * JDK-backed default is sufficient and drags in no new dependency.
  */
trait LlmHttp:
  def post(url: String, headers: Map[String, String], body: String): IO[LlmHttp.Response]

object LlmHttp:

  final case class Response(status: Int, body: String)

  /** JDK `HttpClient`-backed implementation. The blocking `send` is wrapped in `IO.blocking` so it runs on
    * the blocking pool rather than starving a compute thread on a slow model.
    */
  def jdk(timeout: Duration = Duration.ofSeconds(30)): LlmHttp = new LlmHttp:
    private val client = HttpClient.newHttpClient()

    def post(url: String, headers: Map[String, String], body: String): IO[Response] =
      IO.blocking {
        val builder = HttpRequest.newBuilder().uri(URI.create(url)).timeout(timeout)
        headers.foreach { case (k, v) => builder.header(k, v) }
        builder.POST(HttpRequest.BodyPublishers.ofString(body))
        val res = client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        Response(res.statusCode(), Option(res.body()).getOrElse(""))
      }
