package dev.aegiskms.crypto.azure

import com.azure.security.keyvault.keys.cryptography.CryptographyClient
import com.azure.security.keyvault.keys.cryptography.models.{
  EncryptParameters,
  EncryptionAlgorithm,
  KeyWrapAlgorithm,
  SignatureAlgorithm
}

/** A minimal seam over Azure's `CryptographyClient`, covering only the calls the Aegis RoT makes.
  *
  * Same purpose as `AwsKmsPort` and `GcpKmsPort`. What differs is which primitives Azure actually gives us:
  *
  *   - **Native wrap/unwrap.** Azure has first-class `wrapKey` / `unwrapKey` operations, so the DEK path does
  *     not have to be faked out of `encrypt`, the way it is on AWS.
  *   - **Native verify.** Unlike Cloud KMS, Azure verifies server-side, so no public key is fetched and no
  *     local JCE verification is needed.
  *   - **Still no data-key generation.** Like GCP and unlike AWS, there is no `GenerateDataKey`. Key Vault's
  *     standard tier has no random-bytes endpoint either (Managed HSM does, but requiring the Premium SKU to
  *     create a DEK would be a surprising constraint), so the adapter generates DEK material locally and
  *     wraps it. That difference is documented on [[AzureKeyVaultRootOfTrust]] because it changes where the
  *     randomness comes from.
  *
  * Two implementations: [[AzureKeyVaultPort.fromClient]] for production, and a hand-rolled stub in tests.
  */
trait AzureKeyVaultPort:

  /** Symmetric or asymmetric encrypt. `parameters` carries the algorithm and, for AES-GCM, the AAD.
    *
    * Returns the IV and auth tag alongside the ciphertext because **Azure generates the GCM IV itself** —
    * unlike every other backend here, where the client picks the nonce. Both are required back on decrypt, so
    * discarding them would make AES-GCM ciphertext permanently unreadable.
    */
  def encrypt(parameters: EncryptParameters): AzureKeyVaultPort.EncryptOutcome

  /** Inverse of [[encrypt]]. The IV/tag/AAD travel in the decrypt parameters built by the adapter. */
  def decrypt(
      algorithm: EncryptionAlgorithm,
      ciphertext: Array[Byte],
      iv: Array[Byte],
      authTag: Array[Byte],
      aad: Array[Byte]
  ): Array[Byte]

  /** Sign a pre-computed digest. Azure, like Cloud KMS, signs digests rather than messages. */
  def sign(algorithm: SignatureAlgorithm, digest: Array[Byte]): Array[Byte]

  /** Server-side verification against the same key. */
  def verify(algorithm: SignatureAlgorithm, digest: Array[Byte], signature: Array[Byte]): Boolean

  /** Native key wrapping — no `encrypt` impersonation required. */
  def wrapKey(algorithm: KeyWrapAlgorithm, key: Array[Byte]): Array[Byte]

  def unwrapKey(algorithm: KeyWrapAlgorithm, encryptedKey: Array[Byte]): Array[Byte]

  /** Identifier of the key version these operations resolve to, recorded as the `rotationId` so a wrapped DEK
    * can be traced back to the exact key version that produced it.
    */
  def keyId: String

object AzureKeyVaultPort:

  /** What an encrypt call yields. `iv` and `authTag` are null/empty for RSA-OAEP, which has neither. */
  final case class EncryptOutcome(cipherText: Array[Byte], iv: Array[Byte], authTag: Array[Byte])

  /** Production implementation over `CryptographyClient`.
    *
    * `keyId` is passed in rather than read back from the client: `CryptographyClient` does not expose it, and
    * `getKey()` would spend a network round-trip retrieving something the caller already configured.
    */
  def fromClient(client: CryptographyClient, keyIdentifier: String): AzureKeyVaultPort =
    new AzureKeyVaultPort:

      def encrypt(parameters: EncryptParameters): AzureKeyVaultPort.EncryptOutcome =
        val r = client.encrypt(parameters, com.azure.core.util.Context.NONE)
        AzureKeyVaultPort.EncryptOutcome(r.getCipherText, r.getIv, r.getAuthenticationTag)

      def decrypt(
          algorithm: EncryptionAlgorithm,
          ciphertext: Array[Byte],
          iv: Array[Byte],
          authTag: Array[Byte],
          aad: Array[Byte]
      ): Array[Byte] =
        val params =
          if algorithm == EncryptionAlgorithm.A256GCM then
            com.azure.security.keyvault.keys.cryptography.models.DecryptParameters
              .createA256GcmParameters(ciphertext, iv, authTag, aad)
          else
            com.azure.security.keyvault.keys.cryptography.models.DecryptParameters
              .createRsaOaep256Parameters(ciphertext)
        client.decrypt(params, com.azure.core.util.Context.NONE).getPlainText

      def sign(algorithm: SignatureAlgorithm, digest: Array[Byte]): Array[Byte] =
        client.sign(algorithm, digest).getSignature

      def verify(algorithm: SignatureAlgorithm, digest: Array[Byte], signature: Array[Byte]): Boolean =
        client.verify(algorithm, digest, signature).isValid

      def wrapKey(algorithm: KeyWrapAlgorithm, key: Array[Byte]): Array[Byte] =
        client.wrapKey(algorithm, key).getEncryptedKey

      def unwrapKey(algorithm: KeyWrapAlgorithm, encryptedKey: Array[Byte]): Array[Byte] =
        client.unwrapKey(algorithm, encryptedKey).getKey

      def keyId: String = keyIdentifier
