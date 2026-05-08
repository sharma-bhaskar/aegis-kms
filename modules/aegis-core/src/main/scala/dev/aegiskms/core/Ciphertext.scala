package dev.aegiskms.core

import java.util.Base64

/** Opaque ciphertext bytes produced by `KeyService.encrypt`. The encryption context (additional authenticated
  * data, AAD) is NOT carried in this value — the caller must supply the same context to `decrypt` for the
  * operation to succeed, mirroring AWS KMS semantics. Decryption with a different context fails with
  * `KmsError(CryptographicFailure, ...)`.
  */
final case class Ciphertext(bytes: Array[Byte]):
  def toBase64: String = Base64.getEncoder.encodeToString(bytes)

object Ciphertext:
  def fromBase64(b64: String): Either[String, Ciphertext] =
    try Right(Ciphertext(Base64.getDecoder.decode(b64)))
    catch case e: IllegalArgumentException => Left(s"invalid base64: ${e.getMessage}")
