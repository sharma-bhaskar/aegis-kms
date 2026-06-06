package dev.aegiskms.agent

import cats.effect.IO

/** SPI for pluggable LLM providers (#30, ROADMAP 2.1.c).
  *
  * The advisor's natural-language features (`advisor explain`, #29) call `plan` to turn a structured
  * instruction plus a block of audit context into a human-readable answer. The contract is deliberately
  * narrow and **read-only**: Aegis-KMS only ever asks the model to *describe* or *recommend* — it never lets
  * the model execute a cryptographic operation. That guarantee lives in the calling code, not the model.
  *
  * Bundled adapters: [[AnthropicLlmClient]] + [[OpenAiLlmClient]] (cloud — "pair with your existing AI
  * vendor") and [[OllamaLlmClient]] (local — privacy-preserving, no data leaves the host). Providers are
  * selected at boot via [[LlmClient.fromConfig]]; `provider = none` yields no client and callers skip
  * narration entirely.
  */
trait LlmClient[F[_]]:
  /** Produce a completion. `prompt` is the system instruction (what to do); `context` is the data to reason
    * over (e.g. an agent's audit timeline). Returns the model's text answer.
    */
  def plan(prompt: String, context: String): F[String]

object LlmClient:

  /** Selection + connection settings for the bundled providers. Parsed from HOCON / env by `Server.boot` (it
    * owns the Typesafe Config dependency) and handed to [[fromConfig]]; keeping it a plain case class lets
    * the adapters and factory stay testable without a config library.
    *
    *   - `provider` — `none` | `anthropic` | `openai` | `ollama` (case-insensitive). Unknown values fail
    *     fast.
    *   - `apiKey` — required by cloud providers (Anthropic, OpenAI); ignored by Ollama.
    *   - `baseUrl` — overrides the provider default (Anthropic `https://api.anthropic.com`, OpenAI
    *     `https://api.openai.com`, Ollama `http://localhost:11434`). Useful for proxies, gateways, stubbing.
    *   - `model` — provider default applies when absent.
    *   - `maxTokens` — completion cap for cloud providers (Ollama manages its own).
    */
  final case class Config(
      provider: String,
      apiKey: Option[String] = None,
      baseUrl: Option[String] = None,
      model: Option[String] = None,
      maxTokens: Int = 1024
  )

  /** Build the configured provider, or `None` when LLM features are disabled (`provider = none`/empty).
    * Throws [[LlmError]] on an unrecognised provider name so a typo in config fails the boot rather than
    * silently disabling narration.
    */
  def fromConfig(config: Config, http: LlmHttp): Option[LlmClient[IO]] =
    config.provider.trim.toLowerCase match
      case "" | "none" | "disabled" => None
      case "anthropic"              => Some(new AnthropicLlmClient(config, http))
      case "openai"                 => Some(new OpenAiLlmClient(config, http))
      case "ollama"                 => Some(new OllamaLlmClient(config, http))
      case other =>
        throw LlmError(s"unknown LLM provider '$other' (expected one of: none, anthropic, openai, ollama)")

/** Failure raised by an LLM adapter — a missing credential, a non-2xx provider response, or an unparseable
  * body. Carried through `IO.raiseError` so callers can fall back (e.g. `advisor explain` degrades to the
  * deterministic timeline when narration fails).
  */
final case class LlmError(message: String) extends RuntimeException(message)

/** Advisory recommendation produced by the AI module. */
final case class PolicyRecommendation(
    severity: Severity,
    summary: String,
    rationale: String,
    suggestedActions: List[String]
)

enum Severity:
  case Informational, Low, Medium, High, Critical
