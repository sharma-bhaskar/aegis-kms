package dev.aegiskms.crypto

import cats.effect.IO
import dev.aegiskms.core.{ErrorCode, KeyId, KeySpec, KmsError, SigAlgorithm, Signature}

/** SPI for a root-of-trust provider. Implementations live in `dev.aegiskms.crypto.aws`,
  * `dev.aegiskms.crypto.gcp`, `dev.aegiskms.crypto.pkcs11`, etc., and are selected at server startup based on
  * configuration.
  *
  * Contract: no implementation holds raw key material outside its secure boundary. Operations either return
  * wrapped key material or perform the cryptographic op inline and return just the result.
  *
  * Two operation families live on the same trait:
  *
  *   - **Envelope**: `generateDataKey`, `unwrap`, `rotate` — symmetric KEK-wrapped data key flow.
  *   - **Signing**: `sign`, `verify` — asymmetric signing using a CMK that supports it.
  *
  * In AWS KMS a single CMK is either symmetric or asymmetric, so a real deployment will typically configure
  * two `RootOfTrust` instances (one per CMK) and route requests by operation. v0.1.1 keeps both families on
  * one trait for ergonomic reasons; the split lands when GCP / Vault adapters arrive in v0.2.0.
  */
trait RootOfTrust[F[_]]:

  // Envelope family

  def generateDataKey(spec: KeySpec): F[Either[KmsError, WrappedKey]]

  def unwrap(wrapped: WrappedKey): F[Either[KmsError, RawKey]]

  def rotate(id: KeyId): F[Either[KmsError, KeyId]]

  // Signing family

  def sign(id: KeyId, message: Array[Byte], alg: SigAlgorithm): F[Either[KmsError, Signature]]

  def verify(
      id: KeyId,
      message: Array[Byte],
      signature: Signature
  ): F[Either[KmsError, Boolean]]

final case class WrappedKey(bytes: Array[Byte], rotationId: String)
final case class RawKey(bytes: Array[Byte])

object RootOfTrust:

  /** A fake, non-cryptographic root of trust used for tests and the dev/in-memory boot path.
    *
    * `generateDataKey` and `unwrap` return constant byte arrays — they exist only so the boot wiring has
    * something to call. `sign` / `verify` use a deterministic HMAC-SHA-256 keyed by the KeyId so the dev REST
    * surface has a meaningful round-trip for the README quickstart.
    *
    * Never use this in production. The `AwsKmsRootOfTrust` is the production path.
    */
  def inMemory: RootOfTrust[IO] = new RootOfTrust[IO]:
    def generateDataKey(spec: KeySpec): IO[Either[KmsError, WrappedKey]] =
      IO.pure(Right(WrappedKey(Array.fill(32)(0.toByte), "in-memory-rotation-0")))

    def unwrap(wrapped: WrappedKey): IO[Either[KmsError, RawKey]] =
      IO.pure(Right(RawKey(Array.fill(32)(0.toByte))))

    def rotate(id: KeyId): IO[Either[KmsError, KeyId]] =
      IO.pure(Right(id))

    def sign(id: KeyId, message: Array[Byte], alg: SigAlgorithm): IO[Either[KmsError, Signature]] =
      IO {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(new javax.crypto.spec.SecretKeySpec(id.value.getBytes("UTF-8"), "HmacSHA256"))
        Right(Signature(mac.doFinal(message), alg))
      }.handleError(e =>
        Left(KmsError(ErrorCode.CryptographicFailure, s"in-memory sign failed: ${e.getMessage}"))
      )

    def verify(
        id: KeyId,
        message: Array[Byte],
        signature: Signature
    ): IO[Either[KmsError, Boolean]] =
      IO {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(new javax.crypto.spec.SecretKeySpec(id.value.getBytes("UTF-8"), "HmacSHA256"))
        val expected = mac.doFinal(message)
        Right(java.util.Arrays.equals(expected, signature.bytes))
      }.handleError(e =>
        Left(KmsError(ErrorCode.CryptographicFailure, s"in-memory verify failed: ${e.getMessage}"))
      )
