package dev.aegiskms.cli

import java.net.URI
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.time.Duration

/** A tiny HTTP seam used by the CLI. Two reasons it exists:
  *   - JDK's `HttpClient` works fine for the CLI's needs but is awkward to mock; this port lets tests inject
  *     a hand-rolled stub that records calls and returns canned responses, with no network boot.
  *   - It pins the exact wire shape (method/url/headers/body) we depend on, so we can route requests through
  *     a different backend later (for example, an in-process route interpreter for testing).
  */
trait HttpPort:
  def execute(req: HttpPort.Request): HttpPort.Response

object HttpPort:

  final case class Request(
      method: String,
      url: String,
      headers: Map[String, String] = Map.empty,
      body: Option[String] = None
  )

  final case class Response(status: Int, body: String)

  /** Default JDK-backed implementation. Uses `HttpClient.newHttpClient()` with a per-request timeout so a
    * misconfigured server URL doesn't hang the CLI indefinitely.
    */
  def jdk(timeout: Duration = Duration.ofSeconds(15)): HttpPort = new HttpPort:
    private val client = HttpClient.newHttpClient()

    def execute(req: Request): Response =
      val builder = HttpRequest.newBuilder().uri(URI.create(req.url)).timeout(timeout)
      req.headers.foreach { case (k, v) => builder.header(k, v) }
      val publisher = req.body match
        case Some(b) =>
          builder.header("Content-Type", "application/json")
          HttpRequest.BodyPublishers.ofString(b)
        case None => HttpRequest.BodyPublishers.noBody()
      builder.method(req.method, publisher)
      val res = client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
      Response(res.statusCode(), Option(res.body()).getOrElse(""))
