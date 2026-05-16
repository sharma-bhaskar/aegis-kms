package dev.aegiskms.core

/** SPI: compute a per-request `RiskScore` from the request shape.
  *
  * Implementations live outside `aegis-core` because they need state (the `BaselineDetector` in
  * `aegis-agent-ai`) or external signals (a future ML scorer, a future Bedrock-backed advisor). The trait
  * itself stays here so the audit decorator can take it as a constructor argument without dragging Pekko or
  * any specific backend into the library-safe tier.
  *
  * The scorer is called BEFORE the inner `KeyService` runs, on every request — including ones that will be
  * denied by policy. That's deliberate: we want the audit row for the denied call to also carry its risk
  * score, so post-incident review can answer "was this denied because policy already knew it was risky?"
  *
  * Contract:
  *   - Pure I/O — the scorer must not mutate any state visible outside its own (BaselineDetector reads are
  *     fine; writes happen separately after the request completes).
  *   - Must always produce a value, even on missing baseline. Use `RiskScore.Zero` for a cold-start actor.
  *   - Total — never throws. Internal failures collapse to `RiskScore.Zero` plus a `RiskFactor` with evidence
  *     `"scorer error: <message>"` so the audit row records that scoring failed without crashing the request
  *     path.
  */
trait RiskScorer[F[_]]:
  def score(request: RiskScorer.Request): F[RiskScore]

object RiskScorer:

  /** Everything a scorer needs about the current request. Constructed by the audit decorator from the
    * `KeyService` method arguments — same shape regardless of which op (sign / encrypt / rotate / …) the
    * caller invoked. The scorer reads the fields it cares about; future scorers can ignore the rest.
    */
  final case class Request(
      principal: Principal,
      operation: Operation,
      keyId: Option[KeyId],
      at: java.time.Instant,
      context: Map[String, String] = Map.empty
  )
