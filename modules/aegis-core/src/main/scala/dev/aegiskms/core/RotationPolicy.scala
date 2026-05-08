package dev.aegiskms.core

import scala.concurrent.duration.FiniteDuration

/** Why a rotation happened. Recorded on `KeyEvent.Rotated` and the audit row so post-incident review can tell
  * an operator-initiated rotation apart from an automatic one driven by a time/op-count threshold.
  *
  * v0.1.1 carries the value through the algebra and journal; it does not yet drive an auto-rotation scheduler
  * — explicit `aegis keys rotate` calls always pass `Manual`. The TimeBased / OpCountBased variants are
  * populated when the v0.2.0 scheduler lands.
  */
enum RotationPolicy:
  case Manual
  case TimeBased(interval: FiniteDuration)
  case OpCountBased(maxOps: Long)

  /** Stable wire representation. The shape is intentionally human-readable so audit consumers can render the
    * policy without a JSON parser, e.g. `"Manual"`, `"TimeBased:7d"`, `"OpCountBased:10000"`.
    */
  def render: String = this match
    case RotationPolicy.Manual               => "Manual"
    case RotationPolicy.TimeBased(interval)  => s"TimeBased:${interval.toString.replace(" ", "")}"
    case RotationPolicy.OpCountBased(maxOps) => s"OpCountBased:$maxOps"

object RotationPolicy:
  /** Parse a wire-format string. Used by the REST DTOs and CLI. Examples:
    *   - `"Manual"`
    *   - `"TimeBased:7days"` / `"TimeBased:24hours"`
    *   - `"OpCountBased:10000"`
    */
  def fromString(s: String): Either[String, RotationPolicy] =
    s match
      case "Manual" => Right(Manual)
      case raw if raw.startsWith("TimeBased:") =>
        val tail = raw.drop("TimeBased:".length)
        try Right(TimeBased(scala.concurrent.duration.Duration(tail).asInstanceOf[FiniteDuration]))
        catch case e: Throwable => Left(s"invalid TimeBased duration '$tail': ${e.getMessage}")
      case raw if raw.startsWith("OpCountBased:") =>
        val tail = raw.drop("OpCountBased:".length)
        tail.toLongOption
          .map(OpCountBased(_))
          .toRight(s"invalid OpCountBased count '$tail'")
      case other => Left(s"unknown rotation policy: $other")
