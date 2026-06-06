package dev.aegiskms.agent

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import io.circe.parser.parse
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Tests for the pluggable LLM providers (#30).
  *
  * The adapters are exercised through a stub [[LlmHttp]] that captures the outbound request (so we can assert
  * the exact wire shape each provider sends) and returns a canned body — no network, no API key. This pins
  * the request contract and the response-parsing for Anthropic + Ollama, plus the `fromConfig` selection.
  */
final class LlmClientSpec extends AnyFunSuite with Matchers:

  /** A stub transport that records the last request and replays a fixed response. */
  final private class CapturingHttp(status: Int, body: String) extends LlmHttp:
    var lastUrl: String                  = ""
    var lastHeaders: Map[String, String] = Map.empty
    var lastBody: String                 = ""
    def post(url: String, headers: Map[String, String], reqBody: String): IO[LlmHttp.Response] =
      IO {
        lastUrl = url; lastHeaders = headers; lastBody = reqBody
        LlmHttp.Response(status, body)
      }

  // ── Anthropic ──────────────────────────────────────────────────────────────

  test("Anthropic adapter posts to /v1/messages with x-api-key + version and parses the text block") {
    val http = new CapturingHttp(200, """{"content":[{"type":"text","text":"all quiet"}]}""")
    val client = new AnthropicLlmClient(
      LlmClient.Config(provider = "anthropic", apiKey = Some("sk-test"), model = Some("claude-sonnet-4-6")),
      http
    )
    val out = client.plan("be terse", "agent-7a3 did 3 things").unsafeRunSync()
    out shouldBe "all quiet"
    http.lastUrl shouldBe "https://api.anthropic.com/v1/messages"
    http.lastHeaders("x-api-key") shouldBe "sk-test"
    http.lastHeaders("anthropic-version") shouldBe "2023-06-01"
    val json = parse(http.lastBody).toOption.get.hcursor
    json.get[String]("model").toOption shouldBe Some("claude-sonnet-4-6")
    json.get[String]("system").toOption shouldBe Some("be terse")
    json.downField("messages").downArray.get[String]("content").toOption shouldBe Some(
      "agent-7a3 did 3 things"
    )
  }

  test("Anthropic adapter without an API key fails with a clear LlmError") {
    val client =
      new AnthropicLlmClient(LlmClient.Config(provider = "anthropic"), new CapturingHttp(200, "{}"))
    val err = client.plan("x", "y").attempt.unsafeRunSync()
    err.left.toOption.get shouldBe a[LlmError]
    err.left.toOption.get.getMessage should include("requires an API key")
  }

  test("Anthropic adapter surfaces a non-200 as an LlmError carrying the status") {
    val http   = new CapturingHttp(429, """{"error":"overloaded"}""")
    val client = new AnthropicLlmClient(LlmClient.Config(provider = "anthropic", apiKey = Some("k")), http)
    val err    = client.plan("x", "y").attempt.unsafeRunSync()
    err.left.toOption.get.getMessage should include("429")
  }

  test("Anthropic adapter honours a baseUrl override (gateway / stub)") {
    val http = new CapturingHttp(200, """{"content":[{"type":"text","text":"ok"}]}""")
    val client = new AnthropicLlmClient(
      LlmClient.Config(provider = "anthropic", apiKey = Some("k"), baseUrl = Some("https://gw.internal/")),
      http
    )
    client.plan("p", "c").unsafeRunSync()
    http.lastUrl shouldBe "https://gw.internal/v1/messages"
  }

  // ── OpenAI ─────────────────────────────────────────────────────────────────

  test(
    "OpenAI adapter posts to /v1/chat/completions with bearer auth and parses choices[0].message.content"
  ) {
    val http = new CapturingHttp(200, """{"choices":[{"message":{"role":"assistant","content":"steady"}}]}""")
    val client = new OpenAiLlmClient(
      LlmClient.Config(provider = "openai", apiKey = Some("sk-oai"), model = Some("gpt-4o-mini")),
      http
    )
    val out = client.plan("be brief", "agent-7a3 timeline").unsafeRunSync()
    out shouldBe "steady"
    http.lastUrl shouldBe "https://api.openai.com/v1/chat/completions"
    http.lastHeaders("authorization") shouldBe "Bearer sk-oai"
    val json = parse(http.lastBody).toOption.get.hcursor
    json.get[String]("model").toOption shouldBe Some("gpt-4o-mini")
    val messages = json.downField("messages")
    messages.downN(0).get[String]("role").toOption shouldBe Some("system")
    messages.downN(0).get[String]("content").toOption shouldBe Some("be brief")
    messages.downN(1).get[String]("role").toOption shouldBe Some("user")
    messages.downN(1).get[String]("content").toOption shouldBe Some("agent-7a3 timeline")
  }

  test("OpenAI adapter without an API key fails with a clear LlmError") {
    val client = new OpenAiLlmClient(LlmClient.Config(provider = "openai"), new CapturingHttp(200, "{}"))
    val err    = client.plan("x", "y").attempt.unsafeRunSync()
    err.left.toOption.get.getMessage should include("requires an API key")
  }

  // ── Ollama ─────────────────────────────────────────────────────────────────

  test("Ollama adapter posts to /api/generate with stream=false and parses the response field") {
    val http   = new CapturingHttp(200, """{"response":"local answer","done":true}""")
    val client = new OllamaLlmClient(LlmClient.Config(provider = "ollama", model = Some("llama3")), http)
    val out    = client.plan("summarize", "events here").unsafeRunSync()
    out shouldBe "local answer"
    http.lastUrl shouldBe "http://localhost:11434/api/generate"
    val json = parse(http.lastBody).toOption.get.hcursor
    json.get[Boolean]("stream").toOption shouldBe Some(false)
    json.get[String]("prompt").toOption.get should include("summarize")
    json.get[String]("prompt").toOption.get should include("events here")
  }

  // ── fromConfig selection ─────────────────────────────────────────────────────

  test("fromConfig returns None when the provider is none/empty/disabled") {
    val http = new CapturingHttp(200, "{}")
    LlmClient.fromConfig(LlmClient.Config(provider = "none"), http) shouldBe None
    LlmClient.fromConfig(LlmClient.Config(provider = ""), http) shouldBe None
    LlmClient.fromConfig(LlmClient.Config(provider = "DISABLED"), http) shouldBe None
  }

  test("fromConfig selects the named provider (case-insensitive) and throws on an unknown name") {
    val http = new CapturingHttp(200, "{}")
    LlmClient.fromConfig(LlmClient.Config(provider = "Anthropic", apiKey = Some("k")), http).get shouldBe a[
      AnthropicLlmClient
    ]
    LlmClient.fromConfig(LlmClient.Config(provider = "OpenAI", apiKey = Some("k")), http).get shouldBe a[
      OpenAiLlmClient
    ]
    LlmClient.fromConfig(LlmClient.Config(provider = "ollama"), http).get shouldBe a[OllamaLlmClient]
    val ex = intercept[LlmError](LlmClient.fromConfig(LlmClient.Config(provider = "bedrock"), http))
    ex.getMessage should include("unknown LLM provider 'bedrock'")
  }
