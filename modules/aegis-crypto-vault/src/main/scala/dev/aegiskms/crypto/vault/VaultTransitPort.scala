package dev.aegiskms.crypto.vault

import io.circe.Json
import io.circe.parser.parse

import java.net.URI
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.time.Duration

/** HTTP seam for Vault's Transit secrets engine.
  *
  * Unlike the AWS, GCP, and Azure adapters, this one takes **no third-party dependency at all**. Transit is a
  * handful of JSON endpoints, so the port is built on the JDK's own `HttpClient` and the circe already
  * present via `aegis-core` — the same approach `aegis-agent-ai`'s `LlmHttp` takes for LLM providers. A Vault
  * driver would add transitive weight for an API surface we would still have to wrap in a seam to test
  * against.
  *
  * The port speaks in already-decoded JSON so the adapter never touches HTTP, and tests never touch a socket:
  * [[VaultTransitPort.fromConfig]] for production, a hand-rolled stub in tests.
  */
trait VaultTransitPort:
  /** POST to a Transit path (e.g. `transit/encrypt/invoice-kek`) and return the response's `data` object. */
  def post(path: String, body: Json): Json

  /** GET a Transit path and return the response's `data` object. */
  def get(path: String): Json

object VaultTransitPort:

  /** Raised for any non-2xx response. Carries the status so the adapter can distinguish a bad request from an
    * outage without parsing prose.
    */
  final case class VaultHttpError(status: Int, body: String)
      extends RuntimeException(s"Vault returned $status: $body")

  /** Production implementation.
    *
    * @param address
    *   Vault base URL, e.g. `https://vault.internal:8200`.
    * @param token
    *   Vault token, sent as `X-Vault-Token`. Renewal is the operator's concern (Vault Agent, or a Kubernetes
    *   auth sidecar) — this adapter does not implement a login flow, which would be a much larger surface
    *   than the crypto it exists to perform.
    * @param namespace
    *   Vault Enterprise namespace, sent as `X-Vault-Namespace` when set.
    */
  def fromConfig(
      address: String,
      token: String,
      namespace: Option[String] = None,
      timeout: Duration = Duration.ofSeconds(10)
  ): VaultTransitPort =
    val client = HttpClient.newBuilder().connectTimeout(timeout).build()

    def send(path: String, body: Option[Json]): Json =
      val base = HttpRequest
        .newBuilder()
        .uri(URI.create(s"${address.stripSuffix("/")}/v1/$path"))
        .timeout(timeout)
        .header("X-Vault-Token", token)
        .header("Content-Type", "application/json")
      namespace.foreach(ns => base.header("X-Vault-Namespace", ns))
      val req = body match
        case Some(j) => base.POST(HttpRequest.BodyPublishers.ofString(j.noSpaces)).build()
        case None    => base.GET().build()

      val res = client.send(req, HttpResponse.BodyHandlers.ofString())
      if res.statusCode() < 200 || res.statusCode() >= 300 then
        throw VaultHttpError(res.statusCode(), res.body())
      // Every Transit response wraps its payload in a top-level `data` object. Returning that directly
      // keeps the envelope out of the adapter.
      parse(res.body())
        .toOption
        .flatMap(_.hcursor.downField("data").focus)
        .getOrElse(Json.obj())

    new VaultTransitPort:
      def post(path: String, body: Json): Json = send(path, Some(body))
      def get(path: String): Json              = send(path, None)
