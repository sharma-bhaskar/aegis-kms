package dev.aegiskms.core

/** The outcome of any Aegis-KMS operation.
  *
  * Mirrors the OASIS KMIP Result Status values but is independent of the KMIP wire type so `aegis-core` stays
  * Pekko- and codec-free.
  */
enum OperationResult:
  case Success
  case OperationFailed
  case OperationPending
  case OperationUndone

/** Why an operation failed. Maps one-to-one with KMIP Result Reason values, plus a small set of
  * Aegis-specific extensions for capabilities KMIP doesn't model (notably: interactive step-up auth, which
  * KMIP's batch-oriented wire format predates). Extensions are clearly marked and the KMIP codec layer maps
  * them to the closest standard reason on the wire.
  */
enum ErrorCode:
  case None
  case ItemNotFound
  case ResponseTooLarge
  case AuthenticationNotSuccessful
  case InvalidMessage
  case OperationNotSupported
  case MissingData
  case InvalidField
  case FeatureNotSupported
  case OperationCanceledByRequester
  case CryptographicFailure
  case IllegalOperation
  case PermissionDenied
  case ObjectArchived
  case IndexOutOfBounds
  case ApplicationNamespaceNotSupported
  case KeyFormatTypeNotSupported
  case KeyCompressionTypeNotSupported
  case EncodingOptionError
  case KeyValueNotPresent
  case GeneralFailure

  /** Aegis-specific extension (NOT a KMIP code). Returned when the risk decision adapter (see
    * `DecisionEngine`) requires the caller to re-authenticate with a stronger credential before this request
    * can proceed. The HTTP plane maps this to `401 Unauthorized` with a `WWW-Authenticate: aegis-stepup
    * reason=...` header. The KMIP codec maps it to `OperationCanceledByRequester` (closest standard match) on
    * the wire.
    */
  case StepUpRequired

/** Failure value returned by service operations. */
final case class KmsError(code: ErrorCode, message: String)
