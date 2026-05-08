package dev.aegiskms.core

import java.util.Base64

/** Opaque wrapped data-encryption-key bytes produced by `KeyService.wrap` and consumed by
  * `KeyService.unwrap`. The KMIP envelope-encryption flow: the caller has DEK bytes, the KEK identified by
  * `KeyId` wraps them, the result is treated as opaque. No encryption context — that's what `Ciphertext` is
  * for; `WrappedDek` is for the KMIP-style key-wrapping use case where the protected payload is itself a key.
  */
final case class WrappedDek(bytes: Array[Byte]):
  def toBase64: String = Base64.getEncoder.encodeToString(bytes)

object WrappedDek:
  def fromBase64(b64: String): Either[String, WrappedDek] =
    try Right(WrappedDek(Base64.getDecoder.decode(b64)))
    catch case e: IllegalArgumentException => Left(s"invalid base64: ${e.getMessage}")
