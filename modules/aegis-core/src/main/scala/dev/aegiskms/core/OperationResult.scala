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

/** Why an operation failed. Maps one-to-one with KMIP Result Reason values. */
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

/** Failure value returned by service operations. */
final case class KmsError(code: ErrorCode, message: String)
