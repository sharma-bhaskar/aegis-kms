package dev.aegiskms.agent

/** SPI for LLM providers used by the AI policy and natural-language admin features. Bundled backends:
  * Anthropic, OpenAI, Ollama.
  *
  * The contract is deliberately narrow: Aegis-KMS only ever asks the LLM to produce a structured plan of
  * domain commands. The LLM never signs a cryptographic operation itself.
  */
trait LlmClient[F[_]]:
  def plan(prompt: String, context: String): F[String]

/** Advisory recommendation produced by the AI module. */
final case class PolicyRecommendation(
    severity: Severity,
    summary: String,
    rationale: String,
    suggestedActions: List[String]
)

enum Severity:
  case Informational, Low, Medium, High, Critical
