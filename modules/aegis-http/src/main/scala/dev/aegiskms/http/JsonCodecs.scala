package dev.aegiskms.http

import dev.aegiskms.core.*
import io.circe.*
import io.circe.generic.semiauto.*

import java.time.Instant

/** Wire-format DTOs and circe codecs for the REST surface.
  *
  * Wire types are kept separate from `aegis-core` so the public REST contract can evolve independently of
  * internal model changes. Every DTO has explicit `fromCore` / `toCore` converters so the boundary is obvious
  * and testable.
  */
object JsonCodecs:

  // ── Inputs ──────────────────────────────────────────────────────────────────

  final case class KeySpecDto(
      name: String,
      algorithm: String,
      sizeBits: Int,
      objectType: String
  ):
    def toCore: Either[String, KeySpec] =
      for
        alg <- Algorithm.values
          .find(_.toString == algorithm)
          .toRight(s"unknown algorithm: $algorithm")
        ot <- KeyObjectType.values
          .find(_.toString == objectType)
          .toRight(s"unknown objectType: $objectType")
      yield KeySpec(name, alg, sizeBits, ot)

  object KeySpecDto:
    def fromCore(spec: KeySpec): KeySpecDto =
      KeySpecDto(spec.name, spec.algorithm.toString, spec.sizeBits, spec.objectType.toString)

    given Encoder[KeySpecDto] = deriveEncoder
    given Decoder[KeySpecDto] = deriveDecoder

  final case class CreateKeyRequest(spec: KeySpecDto)
  object CreateKeyRequest:
    given Encoder[CreateKeyRequest] = deriveEncoder
    given Decoder[CreateKeyRequest] = deriveDecoder

  // ── Outputs ─────────────────────────────────────────────────────────────────

  final case class ManagedKeyDto(
      id: String,
      spec: KeySpecDto,
      createdAt: Instant,
      state: String
  )
  object ManagedKeyDto:
    def fromCore(k: ManagedKey): ManagedKeyDto =
      ManagedKeyDto(k.id.value, KeySpecDto.fromCore(k.spec), k.createdAt, k.state.toString)

    given Encoder[ManagedKeyDto] = deriveEncoder
    given Decoder[ManagedKeyDto] = deriveDecoder

  final case class KmsErrorDto(code: String, message: String)
  object KmsErrorDto:
    def fromCore(err: KmsError): KmsErrorDto              = KmsErrorDto(err.code.toString, err.message)
    def of(code: ErrorCode, message: String): KmsErrorDto = KmsErrorDto(code.toString, message)

    given Encoder[KmsErrorDto] = deriveEncoder
    given Decoder[KmsErrorDto] = deriveDecoder
