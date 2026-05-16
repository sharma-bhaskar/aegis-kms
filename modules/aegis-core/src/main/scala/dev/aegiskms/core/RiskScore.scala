package dev.aegiskms.core

/** A per-request risk score in `[0.0, 1.0]`, with structured reasoning.
  *
  * The numeric value is a single roll-up — useful for thresholding (e.g. `score >= 0.7 → deny`, `score >= 0.4
  * → step-up`) and for dashboards. The `factors` list is the *evidence*: which inputs fired, what weight each
  * contributed, and an evidence string a human operator can read after the fact.
  *
  * Recorded on the `AuditRecord.context` map as:
  *
  *   - `risk.score` → `"0.62"` (the value, fixed to 2 decimal places)
  *   - `risk.factors` → `"ScopeBaseline:0.50;TimeOfDayBaseline:0.20"` (semicolon-separated `name:weight`
  *     pairs)
  *
  * The wire/log format is a string because `AuditRecord.context` is a `Map[String, String]`. SIEM consumers
  * parse the score string; dashboards render it directly.
  */
final case class RiskScore(value: Double, factors: List[RiskFactor]):
  /** Compact wire representation of the factor list, suitable for an `AuditRecord.context` value. */
  def renderedFactors: String = factors.map(f => s"${f.name}:${f.weight}").mkString(";")

  /** Fixed-two-decimal-places rendering of the score. Avoids `0.6200000000000001` floating-point noise in
    * audit rows.
    */
  def renderedScore: String = f"$value%.2f"

object RiskScore:

  /** The "no risk signals at all" score. Returned when an actor has no baseline and the request carries no
    * elevated contextual signals. Useful as a starting point in reductions.
    */
  val Zero: RiskScore = RiskScore(0.0, Nil)

  /** Build a score by summing factor weights and clamping to `[0.0, 1.0]`. The reduction lives on the
    * companion so call sites can't accidentally produce a score outside the contract range.
    */
  def fromFactors(factors: List[RiskFactor]): RiskScore =
    val raw     = factors.map(_.weight).sum
    val clamped = math.max(0.0, math.min(1.0, raw))
    RiskScore(clamped, factors)

/** A single contributing factor to a risk score. `name` identifies the producer (e.g. `"ScopeBaseline"`,
  * `"AgentPrincipal"`, `"BroadScope"`), `weight` is the per-factor contribution in `[0.0, 1.0]` (which the
  * scorer sums + clamps), and `evidence` is a short human-readable string explaining *why* this factor fired
  * — surfaced in audit rows and (eventually) in the `aegis advisor explain` CLI output.
  */
final case class RiskFactor(name: String, weight: Double, evidence: String)
