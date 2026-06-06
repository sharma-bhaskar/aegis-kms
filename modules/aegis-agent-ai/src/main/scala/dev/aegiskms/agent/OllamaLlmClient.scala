package dev.aegiskms.agent

import cats.effect.IO
import io.circe.Json
import io.circe.parser.parse
import io.circe.syntax.*

/** Ollama adapter (`POST {baseUrl}/api/generate`).
  *
  * Local provider for privacy-conscious shops: the model runs on the operator's own host (default
  * `http://localhost:11434`) so audit data never leaves the network. No API key. The system instruction and
  * the audit context are concatenated into the single `prompt` field, and `stream` is forced to `false` so
  * the whole completion arrives in one JSON body (the advisor wants the full answer, not a token stream). The
  * reply text is the `response` field.
  *
  * Defaults to the `llama3` model; override via `config.model`.
  */
final class OllamaLlmClient(config: LlmClient.Config, http: LlmHttp) extends LlmClient[IO]:

  private val baseUrl = config.baseUrl.getOrElse("http://localhost:11434").stripSuffix("/")
  private val model   = config.model.getOrElse("llama3")

  def plan(prompt: String, context: String): IO[String] =
    val body = Json
      .obj(
        "model"  -> model.asJson,
        "prompt" -> s"$prompt\n\n$context".asJson,
        "stream" -> false.asJson
      )
      .noSpaces
    http
      .post(s"$baseUrl/api/generate", Map("content-type" -> "application/json"), body)
      .flatMap(parseReply)

  private def parseReply(res: LlmHttp.Response): IO[String] =
    if res.status != 200 then
      IO.raiseError(LlmError(s"ollama returned ${res.status}: ${res.body.take(300)}"))
    else
      IO.fromEither(
        parse(res.body)
          .flatMap(_.hcursor.downField("response").as[String])
          .left
          .map(e =>
            LlmError(s"could not parse ollama response: ${e.getMessage}; body: ${res.body.take(300)}")
          )
      )
