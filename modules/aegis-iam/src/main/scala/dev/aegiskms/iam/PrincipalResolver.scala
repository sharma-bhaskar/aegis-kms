package dev.aegiskms.iam

import dev.aegiskms.core.*

import java.time.Duration as JDuration
import scala.concurrent.duration.Duration

/** Resolves request-level credentials into a `Principal`.
  *
  * The HTTP layer reads two headers per request: `Authorization` (Bearer JWT) and `X-Aegis-User` (dev-mode
  * subject). It hands both to a `PrincipalResolver` chosen at boot time; the resolver decides which to honour
  * and how to interpret the result.
  *
  * Two implementations ship in v0.1.0:
  *   - [[PrincipalResolver.dev]] — accepts only `X-Aegis-User`. Boot-time warning logged; intended for the
  *     local-development quickstart and the in-tree integration tests.
  *   - [[PrincipalResolver.jwt]] — accepts only `Authorization: Bearer <jwt>`. The dev header is silently
  *     ignored so a forgotten configuration cannot accidentally fall back to permissive auth.
  *
  * No "either" mode is provided on purpose: prod deployments must pick one and mean it. Falling back from JWT
  * to dev-header is a security footgun.
  */
trait PrincipalResolver:
  def resolve(authHeader: Option[String], devUserHeader: Option[String]): Either[KmsError, Principal]

object PrincipalResolver:

  /** Dev-mode resolver. Returns `Principal.Human(subject, Set("admins"))` from the `X-Aegis-User` header so
    * the dev policy engine can grant access. If the header is missing, returns an `anonymous` Human — also
    * permitted by `DevPolicyEngine`. Production deployments must NOT use this resolver.
    */
  def dev: PrincipalResolver =
    (_, devHeader) =>
      val subject = devHeader.getOrElse("anonymous")
      Right(Principal.Human(subject, Set("admins")))

  /** JWT-bearer resolver. Verifies the `Authorization: Bearer <jwt>` header against the supplied verifier and
    * translates the decoded [[JwtClaims]] into the matching `Principal` variant.
    *
    * Behaviour:
    *   - Missing `Authorization` header → `AuthenticationNotSuccessful` ("missing bearer token").
    *   - Malformed bearer prefix (e.g. `Bearer ` with empty token, or non-Bearer scheme) → same.
    *   - `JwtVerifier` returns an error → `AuthenticationNotSuccessful` with the underlying reason.
    *   - Successful verification → `Principal.Human` or `Principal.Agent` per the `aegis_kind` claim.
    */
  def jwt(verifier: JwtVerifier): PrincipalResolver =
    (authHeader, _) =>
      authHeader.flatMap(parseBearer) match
        case None =>
          Left(KmsError(ErrorCode.AuthenticationNotSuccessful, "missing or malformed bearer token"))
        case Some(token) =>
          verifier.verify(token) match
            case Left(err)     => Left(KmsError(ErrorCode.AuthenticationNotSuccessful, renderError(err)))
            case Right(claims) => Right(toPrincipal(claims))

  /** Map decoded [[JwtClaims]] → `Principal`. Public so callers building agents from non-HTTP entry points
    * (CLI, embedded SDK) can re-use the same translation rules.
    */
  def toPrincipal(claims: JwtClaims): Principal = claims match
    case h: JwtClaims.Human =>
      Principal.Human(h.subject, h.groups)
    case a: JwtClaims.Agent =>
      // The parent's groups aren't carried in the agent JWT (the IDP issues two distinct tokens with
      // separate claim sets). Synthesize the parent with empty groups; the policy engine looks the parent's
      // bindings up by subject anyway, so groups here are irrelevant for the recursive permit check.
      val parent = Principal.Human(a.parentSubject, Set.empty)
      val ttl    = Duration.fromNanos(JDuration.between(a.issuedAt, a.expiresAt).toNanos)
      Principal.Agent(
        subject = a.subject,
        operator = parent,
        purpose = a.purpose,
        issuedAt = a.issuedAt,
        ttl = ttl,
        allowedOps = a.allowedOps.flatMap(parseOp),
        parent = None
      )

  // ── Helpers ──────────────────────────────────────────────────────────────────

  private val BearerPrefix = "Bearer "

  private def parseBearer(header: String): Option[String] =
    if header.startsWith(BearerPrefix) then
      val tok = header.drop(BearerPrefix.length).trim
      if tok.isEmpty then None else Some(tok)
    else None

  private def parseOp(name: String): Option[Operation] =
    Operation.values.find(_.toString == name)

  private def renderError(err: JwtError): String = err match
    case JwtError.Malformed(msg)        => s"malformed JWT: $msg"
    case JwtError.SignatureInvalid      => "JWT signature invalid"
    case JwtError.Expired               => "JWT expired"
    case JwtError.InvalidClaims(reason) => s"invalid JWT claims: $reason"
