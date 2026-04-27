package dev.aegiskms.cli

import io.circe.*
import io.circe.generic.semiauto.*

import java.time.Instant

/** Wire DTOs the CLI exchanges with the Aegis server.
  *
  * These mirror the shapes in `aegis-http`'s `JsonCodecs` but are duplicated here on purpose: depending on
  * `aegis-http` would drag Tapir + pekko-http into the CLI, which doubles its packaged size and slows boot.
  * The shapes are small and stable; if they ever drift, the integration tests in `aegis-http` will fail
  * loudly because they exercise the same JSON.
  */
object WireFormats:

  final case class KeySpecDto(name: String, algorithm: String, sizeBits: Int, objectType: String)
  object KeySpecDto:
    given Encoder[KeySpecDto] = deriveEncoder
    given Decoder[KeySpecDto] = deriveDecoder

  final case class CreateKeyRequest(spec: KeySpecDto)
  object CreateKeyRequest:
    given Encoder[CreateKeyRequest] = deriveEncoder
    given Decoder[CreateKeyRequest] = deriveDecoder

  final case class ManagedKeyDto(id: String, spec: KeySpecDto, createdAt: Instant, state: String)
  object ManagedKeyDto:
    given Encoder[ManagedKeyDto] = deriveEncoder
    given Decoder[ManagedKeyDto] = deriveDecoder

  final case class KmsErrorDto(code: String, message: String)
  object KmsErrorDto:
    given Encoder[KmsErrorDto] = deriveEncoder
    given Decoder[KmsErrorDto] = deriveDecoder
