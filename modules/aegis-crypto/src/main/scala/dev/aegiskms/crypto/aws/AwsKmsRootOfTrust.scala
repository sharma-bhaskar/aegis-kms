package dev.aegiskms.crypto.aws

import cats.effect.IO
import dev.aegiskms.core.{Algorithm, ErrorCode, KeyId, KeySpec, KmsError}
import dev.aegiskms.crypto.{RawKey, RootOfTrust, WrappedKey}
import software.amazon.awssdk.services.kms.KmsClient
import software.amazon.awssdk.services.kms.model.{DataKeySpec, KmsException}

/** A `RootOfTrust` backed by AWS KMS, implementing the **layered-mode** key generation flow.
  *
  * In layered mode, Aegis never sees plaintext key material outside an envelope-encryption call. The sequence
  * on `generateDataKey`:
  *   1. Call `GenerateDataKey` on the configured KEK CMK in AWS KMS. 2. AWS returns the plaintext data key +
  *      the wrapped (CiphertextBlob) data key. 3. Aegis returns `WrappedKey(bytes = ciphertextBlob,
  *      rotationId = kekArn)`. The plaintext data key is discarded by this layer — when the caller actually
  *      needs the bytes (e.g. inline AES-GCM in `aegis-crypto`'s envelope module), it calls `unwrap` to
  *      materialize them.
  *
  * `unwrap` reverses by calling `Decrypt` with the same KEK; we pass the KEK explicitly so AWS can validate
  * the ARN context even on aliased CMKs.
  *
  * `rotate` defers to AWS — turning on automatic rotation is the AWS-native primitive; CMKs are then rotated
  * yearly by AWS. A separate "force a new wrapped data key" flow happens at the actor layer (PR W3.b).
  *
  * The class takes an [[AwsKmsPort]] rather than a raw `KmsClient`, so tests can inject a small hand-rolled
  * stub and production wiring can configure region, credentials, retry policy, and client-side metric
  * publication once at the boot site.
  */
final class AwsKmsRootOfTrust(port: AwsKmsPort, kekArn: String) extends RootOfTrust[IO]:

  def generateDataKey(spec: KeySpec): IO[Either[KmsError, WrappedKey]] =
    IO.blocking {
      val res = port.generateDataKey(kekArn, awsDataKeySpec(spec))
      Right(WrappedKey(bytes = res.ciphertext, rotationId = kekArn))
    }.handleError(translate("GenerateDataKey"))

  def unwrap(wrapped: WrappedKey): IO[Either[KmsError, RawKey]] =
    IO.blocking {
      val plain = port.decrypt(kekArn, wrapped.bytes)
      Right(RawKey(plain))
    }.handleError(translate("Decrypt"))

  def rotate(id: KeyId): IO[Either[KmsError, KeyId]] =
    IO.blocking {
      port.enableRotation(kekArn)
      Right(id)
    }.handleError(translate("EnableKeyRotation"))

  // ── Helpers ────────────────────────────────────────────────────────────────

  private def awsDataKeySpec(spec: KeySpec): DataKeySpec =
    spec.algorithm match
      case Algorithm.AES if spec.sizeBits == 256 => DataKeySpec.AES_256
      case Algorithm.AES if spec.sizeBits == 128 => DataKeySpec.AES_128
      case _                                     =>
        // AWS GenerateDataKey only supports AES-128/256 for symmetric data keys; for asymmetric we'd use
        // GenerateDataKeyPair. Map other specs to a default — the actor layer's spec validation should have
        // caught anything unsupported before we got here.
        DataKeySpec.AES_256

  private def translate(opName: String): Throwable => Either[KmsError, Nothing] = {
    case e: KmsException =>
      Left(
        KmsError(
          ErrorCode.CryptographicFailure,
          s"AWS KMS $opName failed: ${e.awsErrorDetails().errorMessage()}"
        )
      )
    case e =>
      Left(KmsError(ErrorCode.GeneralFailure, s"AWS KMS $opName error: ${e.getMessage}"))
  }

object AwsKmsRootOfTrust:

  /** Build an adapter from a config block. Production wiring constructs the `KmsClient` here using the AWS
    * default credential provider chain and the configured region.
    */
  final case class Config(region: String, kekArn: String)

  /** Build with an externally-supplied port. This is the test seam — pass a hand-rolled stub. */
  def withPort(port: AwsKmsPort, kekArn: String): AwsKmsRootOfTrust =
    new AwsKmsRootOfTrust(port, kekArn)

  /** Build a default AWS-region-configured client and wrap. Suitable for production. */
  def fromConfig(cfg: Config): AwsKmsRootOfTrust =
    val client: KmsClient = KmsClient.builder()
      .region(software.amazon.awssdk.regions.Region.of(cfg.region))
      .build()
    new AwsKmsRootOfTrust(AwsKmsPort.fromClient(client), cfg.kekArn)
