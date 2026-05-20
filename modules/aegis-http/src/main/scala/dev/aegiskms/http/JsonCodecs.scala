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
      state: String,
      currentVersion: Int = 1
  )
  object ManagedKeyDto:
    def fromCore(k: ManagedKey): ManagedKeyDto =
      ManagedKeyDto(
        k.id.value,
        KeySpecDto.fromCore(k.spec),
        k.createdAt,
        k.state.toString,
        k.currentVersion
      )

    given Encoder[ManagedKeyDto] = deriveEncoder
    given Decoder[ManagedKeyDto] = deriveDecoder

  final case class KmsErrorDto(code: String, message: String)
  object KmsErrorDto:
    def fromCore(err: KmsError): KmsErrorDto              = KmsErrorDto(err.code.toString, err.message)
    def of(code: ErrorCode, message: String): KmsErrorDto = KmsErrorDto(code.toString, message)

    given Encoder[KmsErrorDto] = deriveEncoder
    given Decoder[KmsErrorDto] = deriveDecoder

  // ── Sign / verify DTOs ──────────────────────────────────────────────────────

  /** Sign request body. `messageBase64` is the base64-encoded message bytes; `algorithm` is one of the
    * `SigAlgorithm` enum values rendered as a string (e.g. `"RsaPssSha256"`).
    */
  final case class SignRequest(messageBase64: String, algorithm: String)
  object SignRequest:
    given Encoder[SignRequest] = deriveEncoder
    given Decoder[SignRequest] = deriveDecoder

  /** Sign response body. `signatureBase64` is the base64-encoded signature; `algorithm` echoes the request.
    */
  final case class SignResponse(signatureBase64: String, algorithm: String)
  object SignResponse:
    def fromCore(sig: Signature): SignResponse = SignResponse(sig.toBase64, sig.algorithm.toString)

    given Encoder[SignResponse] = deriveEncoder
    given Decoder[SignResponse] = deriveDecoder

  /** Verify request body. */
  final case class VerifyRequest(messageBase64: String, signatureBase64: String, algorithm: String)
  object VerifyRequest:
    given Encoder[VerifyRequest] = deriveEncoder
    given Decoder[VerifyRequest] = deriveDecoder

  /** Verify response body. `valid=true` means signature checked out; `valid=false` means it didn't (and is a
    * 200 response, not a 4xx — the verifier ran successfully and produced a negative answer).
    */
  final case class VerifyResponse(valid: Boolean, algorithm: String)
  object VerifyResponse:
    given Encoder[VerifyResponse] = deriveEncoder
    given Decoder[VerifyResponse] = deriveDecoder

  // ── Encrypt / decrypt DTOs ─────────────────────────────────────────────────

  /** Encrypt request body. `plaintextBase64` is the base64-encoded message bytes; `context` is the optional
    * encryption-context map (additional authenticated data). Both encrypt and decrypt must supply the same
    * context — a mismatch on decrypt returns a 400 with `CryptographicFailure`.
    */
  final case class EncryptRequest(plaintextBase64: String, context: Map[String, String] = Map.empty)
  object EncryptRequest:
    given Encoder[EncryptRequest] = deriveEncoder
    given Decoder[EncryptRequest] = deriveDecoder

  final case class EncryptResponse(ciphertextBase64: String, context: Map[String, String])
  object EncryptResponse:
    def of(ct: Ciphertext, context: Map[String, String]): EncryptResponse =
      EncryptResponse(ct.toBase64, context)

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

  // ── Wrap / unwrap DTOs ─────────────────────────────────────────────────────

  /** Wrap request body. `dekBase64` is the base64-encoded DEK material to be wrapped under the named KEK. */
  final case class WrapRequest(dekBase64: String)
  object WrapRequest:
    given Encoder[WrapRequest] = deriveEncoder
    given Decoder[WrapRequest] = deriveDecoder

  final case class WrapResponse(wrappedDekBase64: String)
  object WrapResponse:
    def of(w: WrappedDek): WrapResponse = WrapResponse(w.toBase64)

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

  // ── Compromise DTO ─────────────────────────────────────────────────────────

  /** Compromise request body. The mandatory `reason` is the human-readable justification recorded in the
    * audit row. Empty strings are rejected at the route layer.
    */
  final case class CompromiseRequest(reason: String)
  object CompromiseRequest:
    given Encoder[CompromiseRequest] = deriveEncoder
    given Decoder[CompromiseRequest] = deriveDecoder

  // ── Rotate DTO ─────────────────────────────────────────────────────────────

  /** Rotate request body. `policy` is the wire-format `RotationPolicy.render` string. Defaults to `"Manual"`
    * when the field is absent.
    */
  final case class RotateRequest(policy: String = "Manual")
  object RotateRequest:
    given Encoder[RotateRequest] = deriveEncoder
    given Decoder[RotateRequest] = deriveDecoder

  // ── Agent issuance DTOs (#18) ──────────────────────────────────────────────

  /** Wire body for `POST /v1/agents/issue`.
    *
    *   - `label` — human-readable purpose ("claude-invoice-batch-q2"). Persisted as the agent's `purpose`
    *     claim and shown in audit rows. Required, non-empty.
    *   - `scopes` — KMIP `Operation` names the agent is permitted to call (e.g. `["Sign", "Get"]`). Required,
    *     non-empty. Any name that doesn't resolve to an `Operation` rejects the request with `400
    *     InvalidField`.
    *   - `ttlSeconds` — token lifetime. Must be `> 0` and `≤ 86400` (24 h cap).
    *   - `parent` — optional. When present, must equal the authenticated caller's subject; cross-principal
    *     issuance is rejected in v0.2.0. The field exists so callers can be explicit about who they're
    *     issuing on behalf of (and so future delegated-issuance can reuse the wire shape).
    */
  final case class IssueAgentRequestDto(
      label: String,
      scopes: List[String],
      ttlSeconds: Long,
      parent: Option[String] = None
  )
  object IssueAgentRequestDto:
    given Encoder[IssueAgentRequestDto] = deriveEncoder
    given Decoder[IssueAgentRequestDto] = deriveDecoder

  /** Wire response for `POST /v1/agents/issue`. The JWT is the bearer the agent presents on every subsequent
    * call; `agentId` is the same string that appears in the audit log as the agent's subject; `jti` is the
    * JWT ID, recorded for the future revocation list (#24).
    */
  final case class IssueAgentResponseDto(
      agentId: String,
      jwt: String,
      jti: String,
      expiresAt: Instant
  )
  object IssueAgentResponseDto:
    given Encoder[IssueAgentResponseDto] = deriveEncoder
    given Decoder[IssueAgentResponseDto] = deriveDecoder

  // ── Audit-read DTOs (#20) ─────────────────────────────────────────────────

  /** One audit row over the wire. Mirrors `AuditRecord` minus the typed `Principal` (which doesn't round-trip
    * cleanly — the wire format flattens to `actor` + `actorKind` strings) and the typed `Operation` (rendered
    * as its enum-name string for symmetry with `actorKind`).
    */
  final case class AuditRecordDto(
      at: Instant,
      actor: String,
      actorKind: String,
      operation: String,
      resource: String,
      outcome: String,
      correlationId: String,
      context: Map[String, String]
  )
  object AuditRecordDto:
    def fromCore(r: dev.aegiskms.audit.AuditRecord): AuditRecordDto =
      val kind = r.principal match
        case _: dev.aegiskms.core.Principal.Human   => "Human"
        case _: dev.aegiskms.core.Principal.Service => "Service"
        case _: dev.aegiskms.core.Principal.Agent   => "Agent"
      AuditRecordDto(
        at = r.at,
        actor = r.principal.subject,
        actorKind = kind,
        operation = r.operation.toString,
        resource = r.resource,
        outcome = r.outcome,
        correlationId = r.correlationId,
        context = r.context
      )

    given Encoder[AuditRecordDto] = deriveEncoder
    given Decoder[AuditRecordDto] = deriveDecoder

  /** Wire response for `GET /v1/audit`. `hasMore = true` means at least one more matching row exists past
    * `offset + limit`; clients can paginate by repeating with `offset = offset + limit`. No total-count field
    * — that would force a separate (expensive) `COUNT(*)` per page; the existence flag is enough for "Load
    * more" UX.
    */
  final case class AuditQueryResponseDto(
      records: List[AuditRecordDto],
      limit: Int,
      offset: Int,
      hasMore: Boolean
  )
  object AuditQueryResponseDto:
    given Encoder[AuditQueryResponseDto] = deriveEncoder
    given Decoder[AuditQueryResponseDto] = deriveDecoder
