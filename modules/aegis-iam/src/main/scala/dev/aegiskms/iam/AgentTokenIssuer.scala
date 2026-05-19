package dev.aegiskms.iam

import cats.effect.IO
import dev.aegiskms.core.*

import java.time.{Duration, Instant}
import java.util.UUID
import scala.concurrent.duration.{DurationInt, FiniteDuration, HOURS}

/** Domain-level service that turns an "issue an agent for this human" request into a signed JWT the agent can
  * present on subsequent requests.
  *
  * Encapsulates four things the raw `JwtIssuer` doesn't:
  *
  *   1. **Authorization.** Only `Principal.Human` callers can issue agents. `Service` callers (the
  *      `aegis-system` auto-responder included) and `Agent` callers are refused with `AccessDenied`. This is
  *      the "agents cannot issue agents" rule from issue #18. 2. **Validation.** Scopes must parse as
  *      `Operation` values; TTL must be positive and ≤ `maxTtl` (default 24 h — agent credentials are meant
  *      to be short-lived). Empty `label` and empty scope set are rejected as `InvalidField`. 3. **Identity
  *      generation.** The agent's subject (the `sub` JWT claim and the `Principal.Agent.subject` it'll carry
  *      on every request) is a fresh `agent-<uuid>`. The `jti` is a separate UUID for revocation (#24). 4.
  *      **JWT construction.** Builds the `JwtClaims.Agent` and signs it via the wrapped `JwtIssuer`. Returns
  *      the agent id, the signed token, the jti, and the expiry instant in a single `AgentToken`.
  *
  * The issuer is stateless aside from the wrapped `JwtIssuer`'s key material; a singleton lives in
  * `Server.boot` and is shared by every `POST /v1/agents/issue` request.
  */
final class AgentTokenIssuer(
    issuer: JwtIssuer,
    issuerName: Option[String] = None,
    maxTtl: FiniteDuration = AgentTokenIssuer.DefaultMaxTtl,
    now: IO[Instant] = IO.realTimeInstant
):

  import AgentTokenIssuer.*

  def issue(
      caller: Principal,
      request: IssueAgentRequest
  ): IO[Either[KmsError, AgentToken]] =
    authorize(caller) match
      case Left(err) => IO.pure(Left(err))
      case Right(human) =>
        validate(request) match
          case Left(err) => IO.pure(Left(err))
          case Right(req) =>
            now.map { issuedAt =>
              val expiresAt = issuedAt.plus(Duration.ofSeconds(req.ttl.toSeconds))
              val agentId   = s"agent-${UUID.randomUUID()}"
              val jti       = UUID.randomUUID().toString
              val claims = JwtClaims.Agent(
                subject = agentId,
                issuer = issuerName,
                issuedAt = issuedAt,
                expiresAt = expiresAt,
                parentSubject = human.subject,
                purpose = req.label,
                allowedOps = req.scopes.map(_.toString),
                jti = jti
              )
              val jwt = issuer.issue(claims)
              Right(AgentToken(agentId, jwt, jti, expiresAt))
            }

  private def authorize(caller: Principal): Either[KmsError, Principal.Human] =
    caller match
      case h: Principal.Human => Right(h)
      case _: Principal.Service =>
        Left(KmsError(ErrorCode.PermissionDenied, "service principals cannot issue agent tokens"))
      case _: Principal.Agent =>
        Left(KmsError(ErrorCode.PermissionDenied, "agents cannot issue agents"))

  private def validate(req: IssueAgentRequest): Either[KmsError, ValidatedRequest] =
    if req.label.trim.isEmpty then
      Left(KmsError(ErrorCode.InvalidField, "label must be non-empty"))
    else if req.scopes.isEmpty then
      Left(KmsError(ErrorCode.InvalidField, "scopes must include at least one operation"))
    else if req.ttl <= 0.nanos then
      Left(KmsError(ErrorCode.InvalidField, "ttl must be positive"))
    else if req.ttl > maxTtl then
      Left(KmsError(
        ErrorCode.InvalidField,
        s"ttl ${req.ttl.toSeconds}s exceeds maximum ${maxTtl.toSeconds}s"
      ))
    else if req.parent.exists(_ != callerSubjectExpected(req)) && req.parent.nonEmpty then
      // Caller specified a parent subject in the body; v0.2.0 requires it to match the caller.
      // Cross-principal issuance (one human issues for another) lands when delegation is designed.
      Left(KmsError(
        ErrorCode.InvalidField,
        "parent in the request body must match the authenticated caller (cross-principal issuance is not supported)"
      ))
    else
      // Parse scopes into Operation values. Reject the request if any name doesn't resolve — better
      // to fail loudly than silently mint a token with a typo'd op the verifier would later reject.
      val parsedOps = req.scopes.foldLeft[Either[KmsError, List[Operation]]](Right(Nil)) {
        case (acc @ Left(_), _) => acc
        case (Right(ops), name) =>
          Operation.values
            .find(_.toString == name)
            .toRight(KmsError(ErrorCode.InvalidField, s"unknown operation in scopes: '$name'"))
            .map(op => ops :+ op)
      }
      parsedOps.map(ops => ValidatedRequest(req.label.trim, ops.toSet, req.ttl))

  /** Caller-subject check helper. Used inside `validate` so the body-parent / caller-parent invariant stays a
    * single readable expression. Returns the *expected* subject string — the actual value is compared against
    * `req.parent`.
    */
  private def callerSubjectExpected(req: IssueAgentRequest): String =
    req.callerSubject.getOrElse("")

object AgentTokenIssuer:

  /** Aegis-side cap on agent token lifetime. 24 hours by default — agent credentials should be short-lived
    * because the JTI blacklist (#24) is the only revocation mechanism, and a 1-week agent token can do damage
    * well beyond the operator's incident response window.
    */
  val DefaultMaxTtl: FiniteDuration = FiniteDuration(24L, HOURS)

  /** Validated, parsed view of the request after `validate()` passes. */
  final private case class ValidatedRequest(
      label: String,
      scopes: Set[Operation],
      ttl: FiniteDuration
  )

/** Domain request for `AgentTokenIssuer.issue`. Independent of the HTTP DTO so non-HTTP planes (the CLI's
  * `aegis agent issue`, the SDK, future MCP / KMIP plumbing) can call the issuer directly. The HTTP layer
  * maps its wire body into this.
  *
  * `parent` is optional and, when set, must equal the authenticated caller's subject — the field exists so
  * callers can be explicit about who they're issuing on behalf of, but cross-principal issuance (alice
  * issuing an agent on behalf of bob) is rejected in v0.2.0 (a delegation model is roadmapped for a later
  * release).
  *
  * `callerSubject` is internal-only — the issuer reads it inside `validate` to compare against `parent`. The
  * HTTP layer fills it from the resolved principal before calling `issue()`. Field is package-private only by
  * convention; refactor to a sealed factory later if needed.
  */
final case class IssueAgentRequest(
    label: String,
    scopes: List[String],
    ttl: FiniteDuration,
    parent: Option[String] = None,
    callerSubject: Option[String] = None
)

/** Output of `AgentTokenIssuer.issue` — exactly the shape returned over the wire by `POST /v1/agents/issue`,
  * but as a domain type so non-HTTP callers can use it directly.
  */
final case class AgentToken(
    agentId: String,
    jwt: String,
    jti: String,
    expiresAt: Instant
)
