package dev.aegiskms.crypto.aws

import software.amazon.awssdk.services.kms.KmsClient
import software.amazon.awssdk.services.kms.model.{
  DataKeySpec,
  DecryptRequest,
  EnableKeyRotationRequest,
  GenerateDataKeyRequest,
  MessageType,
  SignRequest,
  SigningAlgorithmSpec,
  VerifyRequest
}

/** A minimal seam over `software.amazon.awssdk.services.kms.KmsClient` covering only the operations the Aegis
  * RoT calls. Two reasons it exists:
  *   - The SDK client interface has a huge abstract surface; subclassing it for tests is brittle.
  *   - It pins exactly the AWS calls Aegis depends on, which makes it the obvious place to add retry,
  *     metrics, and request-context plumbing in one place.
  *
  * Two implementations: `AwsKmsPort.fromClient(c)` for production, and a hand-rolled stub in tests.
  */
trait AwsKmsPort:
  def generateDataKey(kekArn: String, spec: DataKeySpec): AwsKmsPort.GenerateResult
  def decrypt(kekArn: String, ciphertext: Array[Byte]): Array[Byte]
  def enableRotation(kekArn: String): Unit
  def sign(keyArn: String, message: Array[Byte], alg: SigningAlgorithmSpec): Array[Byte]
  def verify(
      keyArn: String,
      message: Array[Byte],
      signature: Array[Byte],
      alg: SigningAlgorithmSpec
  ): Boolean

object AwsKmsPort:

  /** What `GenerateDataKey` returns: the wrapped (encrypted) form to persist, plus the plaintext form which
    * the caller uses once and discards. We keep them in a tuple so the adapter doesn't depend on the AWS SDK
    * response shapes.
    */
  final case class GenerateResult(ciphertext: Array[Byte], plaintext: Array[Byte])

  /** Default implementation backed by the AWS SDK v2 `KmsClient`. */
  def fromClient(client: KmsClient): AwsKmsPort = new AwsKmsPort:
    def generateDataKey(kekArn: String, spec: DataKeySpec): GenerateResult =
      val res = client.generateDataKey(
        GenerateDataKeyRequest.builder().keyId(kekArn).keySpec(spec).build()
      )
      GenerateResult(
        ciphertext = res.ciphertextBlob().asByteArray(),
        plaintext = res.plaintext().asByteArray()
      )

    def decrypt(kekArn: String, ciphertext: Array[Byte]): Array[Byte] =
      val res = client.decrypt(
        DecryptRequest.builder()
          .keyId(kekArn)
          .ciphertextBlob(software.amazon.awssdk.core.SdkBytes.fromByteArray(ciphertext))
          .build()
      )
      res.plaintext().asByteArray()

    def enableRotation(kekArn: String): Unit =
      val _ = client.enableKeyRotation(EnableKeyRotationRequest.builder().keyId(kekArn).build())

    def sign(keyArn: String, message: Array[Byte], alg: SigningAlgorithmSpec): Array[Byte] =
      val res = client.sign(
        SignRequest.builder()
          .keyId(keyArn)
          .message(software.amazon.awssdk.core.SdkBytes.fromByteArray(message))
          .messageType(MessageType.RAW)
          .signingAlgorithm(alg)
          .build()
      )
      res.signature().asByteArray()

    def verify(
        keyArn: String,
        message: Array[Byte],
        signature: Array[Byte],
        alg: SigningAlgorithmSpec
    ): Boolean =
      // AWS KMS Verify throws KmsInvalidSignatureException on bad signatures; otherwise sets signatureValid.
      // We catch the validity exception here and translate to `false`. Any other exception (network, auth)
      // propagates so the RootOfTrust adapter can map it to KmsError.
      try
        val res = client.verify(
          VerifyRequest.builder()
            .keyId(keyArn)
            .message(software.amazon.awssdk.core.SdkBytes.fromByteArray(message))
            .messageType(MessageType.RAW)
            .signature(software.amazon.awssdk.core.SdkBytes.fromByteArray(signature))
            .signingAlgorithm(alg)
            .build()
        )
        res.signatureValid().booleanValue()
      catch
        case _: software.amazon.awssdk.services.kms.model.KmsInvalidSignatureException => false
