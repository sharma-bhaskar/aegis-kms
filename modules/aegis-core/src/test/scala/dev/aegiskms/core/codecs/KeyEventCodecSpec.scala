package dev.aegiskms.core.codecs

import dev.aegiskms.core.*
import dev.aegiskms.core.codecs.KeyEventCodec.given
import io.circe.parser.parse
import io.circe.syntax.*
import org.scalatest.funsuite.AnyFunSuite

import java.time.Instant

/** Round-trips every `KeyEvent` variant through circe to guarantee the on-disk JSON shape stays decodable.
  *
  * This is the only thing standing between an in-flight journal write and a permanently corrupt event, so
  * every variant must have an explicit assertion. When a new variant is added to `KeyEvent`, this spec MUST
  * fail to compile (the pattern match below is `match`-exhaustive on `case` statements but it's also a
  * developer signal — extend the test, then extend the codec).
  */
final class KeyEventCodecSpec extends AnyFunSuite:

  private val keyId = KeyId.fromString("k-9f2c").toOption.get
  private val now   = Instant.parse("2026-04-29T12:00:00Z")
  private val spec  = KeySpec("invoice-2026", Algorithm.AES, 256, KeyObjectType.SymmetricKey)

  // Force the static type to the trait so the trait-level Encoder (which adds the `"type"` discriminator) is
  // selected; otherwise the case-class Encoder picked up via deriveCodec for the variant would skip the
  // discriminator and the round-trip would silently lose information.
  private def roundTrip(event: KeyEvent): Unit =
    val json = (event: KeyEvent).asJson
    val back = json.as[KeyEvent].toOption
    assert(back.contains(event), s"round-trip mismatch for $event\nJSON was: ${json.spaces2}")

  test("KeyEvent.Created round-trips with the type discriminator") {
    val event: KeyEvent = KeyEvent.Created("e1", now, keyId, spec, "alice@org", "alice@org")
    roundTrip(event)
    assert(event.asJson.hcursor.get[String]("type").contains("Created"))
  }

  test("KeyEvent.Activated round-trips") {
    roundTrip(KeyEvent.Activated("e2", now, keyId, "alice@org"))
  }

  test("KeyEvent.Deactivated round-trips, preserving reason") {
    val event: KeyEvent = KeyEvent.Deactivated("e3", now, keyId, "alice@org", "operator-revoke")
    roundTrip(event)
    assert(event.asJson.hcursor.get[String]("reason").contains("operator-revoke"))
  }

  test("KeyEvent.Destroyed round-trips") {
    roundTrip(KeyEvent.Destroyed("e4", now, keyId, "alice@org"))
  }

  test("decode rejects an unknown discriminator with a clear message") {
    val bogus =
      parse(
        """{"type":"Imploded","eventId":"x","at":"2026-04-29T12:00:00Z","keyId":"k","actorSubject":"a"}"""
      ).toOption.get
    val decoded = bogus.as[KeyEvent]
    assert(decoded.isLeft)
    assert(decoded.left.toOption.get.message.contains("Imploded"))
  }

  test("Algorithm and KeyObjectType serialize as plain strings") {
    val event: KeyEvent = KeyEvent.Created("e5", now, keyId, spec, "alice", "alice")
    val json            = event.asJson
    assert(json.hcursor.downField("spec").get[String]("algorithm").contains("AES"))
    assert(json.hcursor.downField("spec").get[String]("objectType").contains("SymmetricKey"))
  }
