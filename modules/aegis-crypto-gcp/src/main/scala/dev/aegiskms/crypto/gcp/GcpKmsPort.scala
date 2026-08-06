package dev.aegiskms.crypto.gcp

import com.google.cloud.kms.v1.{
  CryptoKeyName,
  CryptoKeyVersion,
  CryptoKeyVersionName,
  DecryptRequest,
  Digest,
  EncryptRequest,
  KeyManagementServiceClient,
  ProtectionLevel
}
import com.google.protobuf.ByteString

/** A minimal seam over `KeyManagementServiceClient`, covering only the Cloud KMS calls the Aegis RoT makes.
  *
  * Mirrors `AwsKmsPort`'s purpose — pin the exact vendor calls we depend on, and keep the SDK's very large
  * abstract surface out of the tests — but the operation list is deliberately *not* a mirror of the AWS one,
  * because Cloud KMS does not offer the same primitives:
  *
  *   - **No `GenerateDataKey`.** AWS returns a plaintext + wrapped DEK pair in one call, generated inside
  *     AWS's HSMs. Cloud KMS has no equivalent, so the adapter composes `generateRandomBytes` (HSM-backed
  *     RNG) with `encrypt` on the KEK to get the same result.
  *   - **No `Verify`.** AWS KMS verifies signatures server-side. Cloud KMS only signs; verification is done
  *     by the caller against the public key, which is why [[publicKeyPem]] exists.
  *   - **Signing takes a digest, not a message.** For the RSA-PSS and ECDSA SHA-256 algorithms Aegis
  *     supports, Cloud KMS wants a pre-computed `Digest`. Hashing happens adapter-side.
  *
  * Two implementations: [[GcpKmsPort.fromClient]] for production, and a hand-rolled stub in tests.
  */
trait GcpKmsPort:

  /** HSM-backed random bytes from the given location (`projects/P/locations/L`). Used to mint DEK material,
    * standing in for AWS's `GenerateDataKey`.
    */
  def generateRandomBytes(location: String, lengthBytes: Int): Array[Byte]

  /** Symmetric encrypt under a CryptoKey. `aad` is bound as additional authenticated data. */
  def encrypt(keyName: CryptoKeyName, plaintext: Array[Byte], aad: Array[Byte]): Array[Byte]

  /** Symmetric decrypt. Fails if `aad` differs from what was supplied at encrypt time. */
  def decrypt(keyName: CryptoKeyName, ciphertext: Array[Byte], aad: Array[Byte]): Array[Byte]

  /** Asymmetric sign over a pre-computed digest, against a specific CryptoKeyVersion. */
  def asymmetricSign(version: CryptoKeyVersionName, digest: Digest): Array[Byte]

  /** PEM-encoded public key for a CryptoKeyVersion, used for local signature verification. */
  def publicKeyPem(version: CryptoKeyVersionName): String

  /** Create a new CryptoKeyVersion, which becomes the key's primary. Cloud KMS's rotation primitive. */
  def createKeyVersion(keyName: CryptoKeyName): String

object GcpKmsPort:

  /** Production implementation over the Google Cloud KMS client.
    *
    * The client is `AutoCloseable` and owns gRPC channels + background threads; `GcpKmsRootOfTrust.resource`
    * is what ties its lifetime to the server's.
    */
  def fromClient(client: KeyManagementServiceClient): GcpKmsPort = new GcpKmsPort:

    def generateRandomBytes(location: String, lengthBytes: Int): Array[Byte] =
      client
        .generateRandomBytes(location, lengthBytes, ProtectionLevel.HSM)
        .getData
        .toByteArray

    // The convenience overloads take only (name, payload) — binding AAD requires the request objects.
    def encrypt(keyName: CryptoKeyName, plaintext: Array[Byte], aad: Array[Byte]): Array[Byte] =
      client
        .encrypt(
          EncryptRequest.newBuilder()
            .setName(keyName.toString)
            .setPlaintext(ByteString.copyFrom(plaintext))
            .setAdditionalAuthenticatedData(ByteString.copyFrom(aad))
            .build()
        )
        .getCiphertext
        .toByteArray

    def decrypt(keyName: CryptoKeyName, ciphertext: Array[Byte], aad: Array[Byte]): Array[Byte] =
      client
        .decrypt(
          DecryptRequest.newBuilder()
            .setName(keyName.toString)
            .setCiphertext(ByteString.copyFrom(ciphertext))
            .setAdditionalAuthenticatedData(ByteString.copyFrom(aad))
            .build()
        )
        .getPlaintext
        .toByteArray

    def asymmetricSign(version: CryptoKeyVersionName, digest: Digest): Array[Byte] =
      client.asymmetricSign(version, digest).getSignature.toByteArray

    def publicKeyPem(version: CryptoKeyVersionName): String =
      client.getPublicKey(version).getPem

    def createKeyVersion(keyName: CryptoKeyName): String =
      client
        .createCryptoKeyVersion(keyName, CryptoKeyVersion.newBuilder().build())
        .getName
