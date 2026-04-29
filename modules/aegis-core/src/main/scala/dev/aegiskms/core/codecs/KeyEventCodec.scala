package dev.aegiskms.core.codecs

import dev.aegiskms.core.*
import io.circe.*
import io.circe.generic.semiauto.*

/** Circe codecs for [[KeyEvent]] and the value types embedded in it.
  *
  * These live in `aegis-core` rather than `aegis-persistence` because the type itself does. Any backend that
  * persists or transmits a `KeyEvent` (Postgres journal, Kafka mirror, SIEM webhook, S3 cold-store) wants the
  * same on-the-wire shape.
  *
  * The encoding strategy:
  *   - Each ADT variant is encoded as the case class fields plus a `"type"` discriminator field. The
  *     discriminator is a string matching the variant name (e.g. `"Created"`, `"Activated"`). Decoding reads
  *     the discriminator first and dispatches to the matching variant codec.
  *   - Embedded value types (`KeyId`, `Algorithm`, `KeyObjectType`) are encoded as JSON strings. Opaque types
  *     and Scala 3 enums don't get derivation for free, so we hand-write those.
  *   - `Instant` uses circe-core's built-in ISO-8601 codec (`Encoder.encodeInstant`).
  *
  * Stability note: the JSON shape produced by these codecs is part of the journal's on-disk format. Adding
  * new fields is safe (decoders ignore unknown JSON fields by default in circe). Removing or renaming a field
  * is a breaking change to any persisted journal — handle by writing a migration that re-encodes events on
  * read.
  */
object KeyEventCodec:

  // ── Opaque type & enum codecs ────────────────────────────────────────────────

  given Encoder[KeyId] = Encoder.encodeString.contramap(_.value)
  given Decoder[KeyId] = Decoder.decodeString.emap(KeyId.fromString)

  given Encoder[Algorithm] = Encoder.encodeString.contramap(_.toString)
  given Decoder[Algorithm] = Decoder.decodeString.emap { s =>
    Algorithm.values.find(_.toString == s).toRight(s"Unknown Algorithm: $s")
  }

  given Encoder[KeyObjectType] = Encoder.encodeString.contramap(_.toString)
  given Decoder[KeyObjectType] = Decoder.decodeString.emap { s =>
    KeyObjectType.values.find(_.toString == s).toRight(s"Unknown KeyObjectType: $s")
  }

  // ── Case-class codecs ────────────────────────────────────────────────────────

  given Codec[KeySpec] = deriveCodec

  private given createdCodec: Codec.AsObject[KeyEvent.Created]         = deriveCodec
  private given activatedCodec: Codec.AsObject[KeyEvent.Activated]     = deriveCodec
  private given deactivatedCodec: Codec.AsObject[KeyEvent.Deactivated] = deriveCodec
  private given destroyedCodec: Codec.AsObject[KeyEvent.Destroyed]     = deriveCodec

  // ── ADT codec with `"type"` discriminator ────────────────────────────────────

  given Encoder[KeyEvent] = Encoder.AsObject.instance {
    case e: KeyEvent.Created   => createdCodec.encodeObject(e).add("type", Json.fromString("Created"))
    case e: KeyEvent.Activated => activatedCodec.encodeObject(e).add("type", Json.fromString("Activated"))
    case e: KeyEvent.Deactivated =>
      deactivatedCodec.encodeObject(e).add("type", Json.fromString("Deactivated"))
    case e: KeyEvent.Destroyed => destroyedCodec.encodeObject(e).add("type", Json.fromString("Destroyed"))
  }

  given Decoder[KeyEvent] = Decoder.instance { c =>
    c.get[String]("type").flatMap {
      case "Created"     => createdCodec(c)
      case "Activated"   => activatedCodec(c)
      case "Deactivated" => deactivatedCodec(c)
      case "Destroyed"   => destroyedCodec(c)
      case other =>
        Left(DecodingFailure(s"Unknown KeyEvent type: $other", c.history))
    }
  }
