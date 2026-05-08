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

  final case class ManagedKeyDto(
      id: String,
      spec: KeySpecDto,
      createdAt: Instant,
      state: String,
      currentVersion: Int = 1
  )
  object ManagedKeyDto:
    given Encoder[ManagedKeyDto] = deriveEncoder
    given Decoder[ManagedKeyDto] = deriveDecoder

  final case class KmsErrorDto(code: String, message: String)
  object KmsErrorDto:
    given Encoder[KmsErrorDto] = deriveEncoder
    given Decoder[KmsErrorDto] = deriveDecoder

  final case class SignRequest(messageBase64: String, algorithm: String)
  object SignRequest:
    given Encoder[SignRequest] = deriveEncoder
    given Decoder[SignRequest] = deriveDecoder

  final case class SignResponse(signatureBase64: String, algorithm: String)
  object SignResponse:
    given Encoder[SignResponse] = deriveEncoder
    given Decoder[SignResponse] = deriveDecoder

  final case class VerifyRequest(messageBase64: String, signatureBase64: String, algorithm: String)
  object VerifyRequest:
    given Encoder[VerifyRequest] = deriveEncoder
    given Decoder[VerifyRequest] = deriveDecoder

  final case class VerifyResponse(valid: Boolean, algorithm: String)
  object VerifyResponse:
    given Encoder[VerifyResponse] = deriveEncoder
    given Decoder[VerifyResponse] = deriveDecoder

  final case class EncryptRequest(plaintextBase64: String, context: Map[String, String] = Map.empty)
  object EncryptRequest:
    given Encoder[EncryptRequest] = deriveEncoder
    given Decoder[EncryptRequest] = deriveDecoder

  final case class EncryptResponse(ciphertextBase64: String, context: Map[String, String])
  object EncryptResponse:
    given Encoder[EncryptResponse] = deriveEncoder
    given Decoder[EncryptResponse] = deriveDecoder

  final case class DecryptRequest(ciphertextBase64: String, context: Map[String, String] = Map.empty)
  object DecryptRequest:
    given Encoder[DecryptRequest] = deriveEncoder
    given Decoder[DecryptRequest] = deriveDecoder

  final case class DecryptResponse(plaintextBase64: String, context: Map[String, String])
  object DecryptResponse:
    given Encoder[DecryptResponse] = deriveEncoder
    given Decoder[DecryptResponse] = deriveDecoder

  final case class WrapRequest(dekBase64: String)
  object WrapRequest:
    given Encoder[WrapRequest] = deriveEncoder
    given Decoder[WrapRequest] = deriveDecoder

  final case class WrapResponse(wrappedDekBase64: String)
  object WrapResponse:
    given Encoder[WrapResponse] = deriveEncoder
    given Decoder[WrapResponse] = deriveDecoder

  final case class UnwrapRequest(wrappedDekBase64: String)
  object UnwrapRequest:
    given Encoder[UnwrapRequest] = deriveEncoder
    given Decoder[UnwrapRequest] = deriveDecoder

  final case class UnwrapResponse(dekBase64: String)
  object UnwrapResponse:
    given Encoder[UnwrapResponse] = deriveEncoder
    given Decoder[UnwrapResponse] = deriveDecoder

  final case class CompromiseRequest(reason: String)
  object CompromiseRequest:
    given Encoder[CompromiseRequest] = deriveEncoder
    given Decoder[CompromiseRequest] = deriveDecoder

  final case class RotateRequest(policy: String = "Manual")
  object RotateRequest:
    given Encoder[RotateRequest] = deriveEncoder
    given Decoder[RotateRequest] = deriveDecoder
