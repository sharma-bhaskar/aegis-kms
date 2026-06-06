package dev.aegiskms.agent

import cats.effect.IO
import io.circe.Json
import io.circe.parser.parse
import io.circe.syntax.*

/** OpenAI Chat Completions API adapter (`POST {baseUrl}/v1/chat/completions`).
  *
  * Cloud provider, bearer-token auth (`Authorization: Bearer <key>`). The system instruction and audit
  * context map to a two-message `messages` array (`system` + `user`); the advisor never needs multi-turn. The
  * reply text is `choices[0].message.content`. The `baseUrl` override also targets OpenAI-compatible gateways
  * (Azure OpenAI proxies, LiteLLM, vLLM's OpenAI server, etc.).
  *
  * Defaults to the `gpt-4o-mini` model (cheap + capable enough for narration); override via `config.model`.
  */
final class OpenAiLlmClient(config: LlmClient.Config, http: LlmHttp) extends LlmClient[IO]:

  private val baseUrl = config.baseUrl.getOrElse("https://api.openai.com").stripSuffix("/")
  private val model   = config.model.getOrElse("gpt-4o-mini")

  def plan(prompt: String, context: String): IO[String] =
    config.apiKey match
      case None =>
        IO.raiseError(
          LlmError(
            "openai provider requires an API key (set aegis.advisor.llm.api-key / AEGIS_ADVISOR_LLM_API_KEY)"
          )
        )
      case Some(apiKey) =>
        val body = Json
          .obj(
            "model"      -> model.asJson,
            "max_tokens" -> config.maxTokens.asJson,
            "messages" -> Json.arr(
              Json.obj("role" -> "system".asJson, "content" -> prompt.asJson),
              Json.obj("role" -> "user".asJson, "content"   -> context.asJson)
            )
          )
          .noSpaces
        val headers = Map(
          "authorization" -> s"Bearer $apiKey",
          "content-type"  -> "application/json"
        )
        http.post(s"$baseUrl/v1/chat/completions", headers, body).flatMap(parseReply)

  private def parseReply(res: LlmHttp.Response): IO[String] =
    if res.status != 200 then
      IO.raiseError(LlmError(s"openai returned ${res.status}: ${res.body.take(300)}"))
    else
      IO.fromEither(
        parse(res.body)
          .flatMap(
            _.hcursor.downField("choices").downArray.downField("message").downField("content").as[String]
          )
          .left
          .map(e =>
            LlmError(s"could not parse openai response: ${e.getMessage}; body: ${res.body.take(300)}")
          )
      )
