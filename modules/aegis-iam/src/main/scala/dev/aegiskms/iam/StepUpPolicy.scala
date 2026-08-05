package dev.aegiskms.iam

import dev.aegiskms.core.{ErrorCode, KmsError, Principal}

import java.time.{Duration, Instant}

/** The `WWW-Authenticate` challenge Aegis sends when an operation needs a stronger credential than the one
  * presented.
  *
  * Rendered as an RFC 7235 auth-scheme with parameters:
  * {{{
  *   WWW-Authenticate: aegis-stepup realm="aegis", reason="...", acr="mfa", max_age=300
  * }}}
  *
  * A client that gets this should re-authenticate the human — genuinely, not by refreshing the token it
  * already holds — and retry with a credential whose `amr` includes one of the required methods and whose
  * `auth_time` is inside `max_age`.
  */
final case class StepUpChallenge(
    reason: String,
    requiredMethods: Set[String],
    maxAge: Duration
):
  /** The header value. Parameter values are quoted and any embedded quote or backslash is escaped, so a
    * reason string containing a `"` cannot break out and inject extra auth-params.
    */
  def headerValue: String =
    val acr = requiredMethods.toList.sorted.mkString(" ")
    s"""${StepUpChallenge.Scheme} realm="aegis", reason="${StepUpChallenge.escape(reason)}", """ +
      s"""acr="${StepUpChallenge.escape(acr)}", max_age=${maxAge.toSeconds}"""

  def asError: KmsError = KmsError(ErrorCode.StepUpRequired, reason)

object StepUpChallenge:
  val Scheme = "aegis-stepup"

  private def escape(s: String): String =
    s.flatMap {
      case '"'  => "\\\""
      case '\\' => "\\\\"
      case c    => c.toString
    }

/** Decides whether a caller has authenticated strongly and recently enough for a high-blast-radius operation.
  *
  * Aegis has carried `ErrorCode.StepUpRequired` since the risk engine landed, but nothing could ever *demand*
  * step-up — the code was only ever produced by the risk scorer as advice. This closes that: an endpoint can
  * require step-up, emit a real challenge, and verify the retry.
  *
  * Two conditions, both necessary:
  *
  *   - **Method.** The credential's `amr` must intersect `requiredMethods`. Holding a password-only token is
  *     not enough to wipe out an agent fleet.
  *   - **Freshness.** `authTime` must be within `maxAge`. This is the condition that actually matters: a
  *     long-lived token minted after a legitimate MFA login is exactly what an attacker steals, and without a
  *     freshness bound it would satisfy an `amr`-only check forever.
  *
  * A missing `amr` or `authTime` fails closed. Tokens minted before Aegis understood step-up carry neither,
  * and treating "the issuer didn't say" as "the human did MFA" would make the whole mechanism decorative.
  *
  * Non-human principals are always refused: step-up means *a person re-proved who they are*, and there is no
  * coherent way for a service account or an agent to do that.
  */
final class StepUpPolicy(
    val requiredMethods: Set[String] = StepUpPolicy.DefaultMethods,
    val maxAge: Duration = StepUpPolicy.DefaultMaxAge
):

  def check(caller: Principal, now: Instant): Either[StepUpChallenge, Principal.Human] =
    caller match
      case _: Principal.Service =>
        Left(challenge("service principals cannot satisfy step-up authentication"))
      case _: Principal.Agent =>
        Left(challenge("agents cannot satisfy step-up authentication"))
      case h: Principal.Human =>
        if h.amr.intersect(requiredMethods).isEmpty then
          Left(challenge(
            s"this operation requires re-authentication with one of: ${requiredMethods.toList.sorted.mkString(", ")}"
          ))
        else
          h.authTime match
            case None =>
              Left(challenge("credential carries no auth_time, so its freshness cannot be established"))
            case Some(t) if Duration.between(t, now).compareTo(maxAge) > 0 =>
              Left(challenge(
                s"last authentication was more than ${maxAge.toSeconds}s ago; re-authenticate to continue"
              ))
            // A token whose auth_time is in the future is a clock problem or a forgery; either way it is
            // not evidence of a recent login.
            case Some(t) if t.isAfter(now.plus(StepUpPolicy.ClockSkewTolerance)) =>
              Left(challenge("credential auth_time is in the future"))
            case Some(_) => Right(h)

  private def challenge(reason: String): StepUpChallenge =
    StepUpChallenge(reason, requiredMethods, maxAge)

object StepUpPolicy:

  /** Methods that count as a genuine step-up. `pwd` is deliberately absent — a password re-entry is what the
    * user already did to get the session, so accepting it would make step-up a no-op.
    */
  val DefaultMethods: Set[String] = Set("mfa", "otp", "hwk", "swk", "face", "fpt")

  /** How recently the human must have authenticated. Five minutes is the usual "you just did this" window for
    * a destructive admin action — long enough to complete a retry, short enough that a stolen token is
    * unlikely to still qualify.
    */
  val DefaultMaxAge: Duration = Duration.ofMinutes(5)

  /** Tolerance for issuer/verifier clock drift when rejecting future `auth_time` values. */
  val ClockSkewTolerance: Duration = Duration.ofSeconds(60)
