package dev.aegiskms.agent

import cats.effect.IO
import io.circe.Json
import io.circe.parser.parse
import io.circe.syntax.*

/** Anthropic Messages API adapter (`POST {baseUrl}/v1/messages`).
  *
  * Cloud provider for the "pair Aegis with your existing AI vendor" pitch. Auth is the `x-api-key` header
  * (NOT a bearer token); the `anthropic-version` header is required by the API. The system instruction maps
  * to the request's top-level `system` field and the audit context to a single user message — the advisor
  * never needs multi-turn. The reply text is the first `text` block of the `content` array.
  *
  * Defaults to the `claude-sonnet-4-6` model (a balanced choice for narration); override via `config.model`.
  */
final class AnthropicLlmClient(config: LlmClient.Config, http: LlmHttp) extends LlmClient[IO]:

  private val baseUrl = config.baseUrl.getOrElse("https://api.anthropic.com").stripSuffix("/")
  private val model   = config.model.getOrElse("claude-sonnet-4-6")

  def plan(prompt: String, context: String): IO[String] =
    config.apiKey match
      case None =>
        IO.raiseError(
          LlmError(
            "anthropic provider requires an API key (set aegis.advisor.llm.api-key / AEGIS_ADVISOR_LLM_API_KEY)"
          )
        )
      case Some(apiKey) =>
        val body = Json
          .obj(
            "model"      -> model.asJson,
            "max_tokens" -> config.maxTokens.asJson,
            "system"     -> prompt.asJson,
            "messages"   -> Json.arr(Json.obj("role" -> "user".asJson, "content" -> context.asJson))
          )
          .noSpaces
        val headers = Map(
          "x-api-key"         -> apiKey,
          "anthropic-version" -> "2023-06-01",
          "content-type"      -> "application/json"
        )
        http.post(s"$baseUrl/v1/messages", headers, body).flatMap(parseReply)

  private def parseReply(res: LlmHttp.Response): IO[String] =
    if res.status != 200 then
      IO.raiseError(LlmError(s"anthropic returned ${res.status}: ${res.body.take(300)}"))
    else
      IO.fromEither(
        parse(res.body)
          .flatMap(_.hcursor.downField("content").downArray.downField("text").as[String])
          .left
          .map(e =>
            LlmError(s"could not parse anthropic response: ${e.getMessage}; body: ${res.body.take(300)}")
          )
      )
