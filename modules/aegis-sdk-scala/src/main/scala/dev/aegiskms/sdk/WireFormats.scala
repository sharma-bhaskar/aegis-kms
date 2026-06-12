package dev.aegiskms.sdk

import io.circe.*
import io.circe.generic.semiauto.*

import java.time.Instant

/** Wire DTOs the SDK (and the `aegis` CLI on top of it) exchanges with the Aegis server.
  *
  * These mirror the shapes in `aegis-http`'s `JsonCodecs` but are duplicated here on purpose: depending on
  * `aegis-http` would drag Tapir + pekko-http into every SDK consumer, which breaks the library-tier rule and
  * doubles the CLI's packaged size. The shapes are small and stable; if they ever drift, the integration
  * tests in `aegis-http` will fail loudly because they exercise the same JSON.
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

  // ── Agent issuance DTOs (mirrors aegis-http/JsonCodecs.IssueAgentRequestDto + Response) ──

  final case class IssueAgentRequestDto(
      label: String,
      scopes: List[String],
      ttlSeconds: Long,
      parent: Option[String] = None
  )
  object IssueAgentRequestDto:
    given Encoder[IssueAgentRequestDto] = deriveEncoder
    given Decoder[IssueAgentRequestDto] = deriveDecoder

  final case class IssueAgentResponseDto(
      agentId: String,
      jwt: String,
      jti: String,
      expiresAt: Instant
  )
  object IssueAgentResponseDto:
    given Encoder[IssueAgentResponseDto] = deriveEncoder
    given Decoder[IssueAgentResponseDto] = deriveDecoder

  // ── Audit-read DTOs (mirrors aegis-http/JsonCodecs.AuditRecordDto + QueryResponse) ──

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
    given Encoder[AuditRecordDto] = deriveEncoder
    given Decoder[AuditRecordDto] = deriveDecoder

  final case class AuditQueryResponseDto(
      records: List[AuditRecordDto],
      limit: Int,
      offset: Int,
      hasMore: Boolean
  )
  object AuditQueryResponseDto:
    given Encoder[AuditQueryResponseDto] = deriveEncoder
    given Decoder[AuditQueryResponseDto] = deriveDecoder

  // ── Advisor-scan DTOs (mirrors aegis-http/JsonCodecs.AdvisorScanResponseDto, #28) ──

  final case class UnusedKeyDto(keyId: String, lastSeen: Instant, idleDays: Long)
  object UnusedKeyDto:
    given Encoder[UnusedKeyDto] = deriveEncoder
    given Decoder[UnusedKeyDto] = deriveDecoder

  final case class BroadScopeAgentDto(agent: String, operations: List[String])
  object BroadScopeAgentDto:
    given Encoder[BroadScopeAgentDto] = deriveEncoder
    given Decoder[BroadScopeAgentDto] = deriveDecoder

  final case class ActiveAnomalyDto(at: Instant, actor: String, operation: String, outcome: String)
  object ActiveAnomalyDto:
    given Encoder[ActiveAnomalyDto] = deriveEncoder
    given Decoder[ActiveAnomalyDto] = deriveDecoder

  final case class RiskyAgentDto(agent: String, score: Double, failedOps: Int, distinctOps: Int)
  object RiskyAgentDto:
    given Encoder[RiskyAgentDto] = deriveEncoder
    given Decoder[RiskyAgentDto] = deriveDecoder

  final case class AdvisorScanResponseDto(
      windowStart: Instant,
      windowEnd: Instant,
      scannedRecords: Int,
      truncated: Boolean,
      unusedKeys: List[UnusedKeyDto],
      broadScopeAgents: List[BroadScopeAgentDto],
      activeAnomalies: List[ActiveAnomalyDto],
      riskiestAgents: List[RiskyAgentDto]
  )
  object AdvisorScanResponseDto:
    given Encoder[AdvisorScanResponseDto] = deriveEncoder
    given Decoder[AdvisorScanResponseDto] = deriveDecoder

  // ── Advisor-explain DTOs (mirrors aegis-http/JsonCodecs.AdvisorExplainResponseDto, #29) ──

  final case class ExplainEventDto(
      at: Instant,
      operation: String,
      resource: String,
      outcome: String,
      riskScore: Option[Double],
      anomaly: Boolean
  )
  object ExplainEventDto:
    given Encoder[ExplainEventDto] = deriveEncoder
    given Decoder[ExplainEventDto] = deriveDecoder

  final case class ExplainSummaryDto(
      totalEvents: Int,
      distinctOps: List[String],
      anomalies: Int,
      firstSeen: Option[Instant],
      lastSeen: Option[Instant]
  )
  object ExplainSummaryDto:
    given Encoder[ExplainSummaryDto] = deriveEncoder
    given Decoder[ExplainSummaryDto] = deriveDecoder

  final case class AdvisorExplainResponseDto(
      agentId: String,
      windowStart: Instant,
      windowEnd: Instant,
      summary: ExplainSummaryDto,
      events: List[ExplainEventDto],
      narrative: Option[String],
      truncated: Boolean
  )
  object AdvisorExplainResponseDto:
    given Encoder[AdvisorExplainResponseDto] = deriveEncoder
    given Decoder[AdvisorExplainResponseDto] = deriveDecoder

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
