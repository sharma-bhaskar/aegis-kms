package dev.aegiskms.crypto.azure

import cats.effect.{IO, Resource}
import com.azure.identity.DefaultAzureCredentialBuilder
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder
import com.azure.security.keyvault.keys.cryptography.models.{
  EncryptParameters,
  EncryptionAlgorithm,
  KeyWrapAlgorithm,
  SignatureAlgorithm
}
import dev.aegiskms.core.{
  Algorithm,
  Ciphertext,
  ErrorCode,
  KeyId,
  KeySpec,
  KmsError,
  SigAlgorithm,
  Signature,
  WrappedDek
}
import dev.aegiskms.crypto.{RawKey, RootOfTrust, WrappedKey}

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets.UTF_8
import java.security.{MessageDigest, SecureRandom}

/** A `RootOfTrust` backed by Azure Key Vault (or Managed HSM).
  *
  * Azure sits between AWS and GCP in terms of what it gives you:
  *
  *   - **Native `wrapKey` / `unwrapKey`**, so [[wrap]] and [[unwrapDek]] use real key-wrapping rather than
  *     impersonating it with `encrypt`, which is what the AWS adapter has to do.
  *   - **Native `verify`**, so unlike Cloud KMS no public key is fetched and no local JCE verification
  *     happens — Azure answers the question server-side.
  *   - **No data-key generation.** Like GCP and unlike AWS, there is no `GenerateDataKey`. Cloud KMS at least
  *     offers HSM-backed `GenerateRandomBytes`; Key Vault's standard tier offers nothing equivalent (Managed
  *     HSM has `getRandomBytes`, but requiring the Premium SKU merely to mint a DEK would be a surprising
  *     constraint). So [[generateDataKey]] draws from a local `SecureRandom` and wraps the result. **The
  *     randomness therefore originates in this process, not in Azure's HSMs** — a genuine difference from
  *     AWS, recorded in the ARCHITECTURE root-of-trust table rather than left for someone to discover.
  *
  * ## Algorithm selection
  *
  * The configured key's type decides which primitives are legal. An RSA key gets `RSA-OAEP-256` and cannot
  * carry AAD; an AES key (Managed HSM `oct-HSM`) gets `A256GCM` and can. [[Config.symmetric]] states which
  * one you have, because guessing wrong produces an opaque Azure error at the first crypto call rather than
  * at boot.
  *
  * ## Encryption context
  *
  * On a symmetric key the context is bound as AES-GCM AAD using the same canonical, length-prefixed encoding
  * the software and GCP backends use. On an RSA key there is nowhere to put it: RSA-OAEP has no AAD input.
  * Rather than silently discard the caller's context — which would make `decrypt` succeed under a *different*
  * context and quietly break the security property every other backend upholds — a non-empty context on an
  * RSA key is rejected.
  */
final class AzureKeyVaultRootOfTrust(port: AzureKeyVaultPort, config: AzureKeyVaultRootOfTrust.Config)
    extends RootOfTrust[IO]:

  import AzureKeyVaultRootOfTrust.*

  private val random = new SecureRandom()

  private val encAlg: EncryptionAlgorithm =
    if config.symmetric then EncryptionAlgorithm.A256GCM else EncryptionAlgorithm.RSA_OAEP_256

  private val wrapAlg: KeyWrapAlgorithm =
    if config.symmetric then KeyWrapAlgorithm.A256KW else KeyWrapAlgorithm.RSA_OAEP_256

  def generateDataKey(spec: KeySpec): IO[Either[KmsError, WrappedKey]] =
    IO.blocking {
      val material = new Array[Byte](dataKeyBytes(spec))
      random.nextBytes(material)
      Right(WrappedKey(bytes = port.wrapKey(wrapAlg, material), rotationId = port.keyId))
    }.handleError(translate("WrapKey"))

  def unwrap(wrapped: WrappedKey): IO[Either[KmsError, RawKey]] =
    IO.blocking(Right(RawKey(port.unwrapKey(wrapAlg, wrapped.bytes))))
      .handleError(translate("UnwrapKey"))

  /** Azure rotates by creating a new key version. The adapter is pinned to whatever version the configured
    * key identifier resolves to, so rotation is an operator/Key Vault-policy action rather than something
    * this adapter triggers — issuing a rotate here against a version-pinned client would be a no-op that
    * looked like it worked. Returning the id unchanged keeps the algebra total without pretending.
    */
  def rotate(id: KeyId): IO[Either[KmsError, KeyId]] =
    IO.pure(Right(id))

  def sign(id: KeyId, message: Array[Byte], alg: SigAlgorithm): IO[Either[KmsError, Signature]] =
    IO.blocking {
      Right(Signature(port.sign(sigAlg(alg), sha256(message)), alg))
    }.handleError(translate("Sign"))

  def verify(
      id: KeyId,
      message: Array[Byte],
      signature: Signature
  ): IO[Either[KmsError, Boolean]] =
    IO.blocking {
      Right(port.verify(sigAlg(signature.algorithm), sha256(message), signature.bytes))
    }.handleError(translate("Verify"))

  def encrypt(
      id: KeyId,
      plaintext: Array[Byte],
      context: Map[String, String]
  ): IO[Either[KmsError, Ciphertext]] =
    rejectContextOnRsa(context) {
      IO.blocking {
        if config.symmetric then
          // Azure picks the GCM IV server-side and returns it with the auth tag. All three are packed
          // into one blob so `Ciphertext` stays a single opaque value, the way every other backend's is.
          val out = port.encrypt(EncryptParameters.createA256GcmParameters(plaintext, aad(context)))
          Right(Ciphertext(pack(out.iv, out.cipherText, out.authTag)))
        else
          Right(Ciphertext(
            port.encrypt(EncryptParameters.createRsaOaep256Parameters(plaintext)).cipherText
          ))
      }.handleError(translate("Encrypt"))
    }

  def decrypt(
      id: KeyId,
      ciphertext: Ciphertext,
      context: Map[String, String]
  ): IO[Either[KmsError, Array[Byte]]] =
    rejectContextOnRsa(context) {
      if !config.symmetric then
        IO.blocking(Right(port.decrypt(
          encAlg,
          ciphertext.bytes,
          Array.emptyByteArray,
          Array.emptyByteArray,
          Array.emptyByteArray
        )))
          .handleError(translate("Decrypt"))
      else
        unpack(ciphertext.bytes) match
          case Left(err) => IO.pure(Left(err))
          case Right((iv, ct, tag)) =>
            IO.blocking(Right(port.decrypt(encAlg, ct, iv, tag, aad(context))))
              .handleError(translate("Decrypt"))
    }

  def wrap(id: KeyId, dek: Array[Byte]): IO[Either[KmsError, WrappedDek]] =
    IO.blocking(Right(WrappedDek(port.wrapKey(wrapAlg, dek))))
      .handleError(translate("WrapKey"))

  def unwrapDek(id: KeyId, wrapped: WrappedDek): IO[Either[KmsError, Array[Byte]]] =
    IO.blocking(Right(port.unwrapKey(wrapAlg, wrapped.bytes)))
      .handleError(translate("UnwrapKey"))

  /** RSA-OAEP has no AAD input, so an encryption context cannot be honoured on an RSA key. Failing loudly
    * beats accepting it and silently not binding it — the latter would let ciphertext decrypt under any
    * context, breaking a property every other backend enforces.
    */
  private def rejectContextOnRsa[A](
      context: Map[String, String]
  )(op: => IO[Either[KmsError, A]]): IO[Either[KmsError, A]] =
    if context.nonEmpty && !config.symmetric then
      IO.pure(Left(KmsError(
        ErrorCode.InvalidField,
        "an encryption context cannot be bound on an RSA Key Vault key (RSA-OAEP has no AAD input). " +
          "Use a symmetric key (Managed HSM oct-HSM, aegis.crypto.azure-key-vault.symmetric=true) or drop the context."
      )))
    else op

object AzureKeyVaultRootOfTrust:

  private val GcmNonceBytes = 12
  private val GcmTagBytes   = 16

  /** @param keyIdentifier
    *   full Key Vault key URL, e.g. `https://my-vault.vault.azure.net/keys/invoice-kek/abc123`. Pinning the
    *   version is recommended; omitting it resolves to the current version, which moves under you on
    *   rotation.
    * @param symmetric
    *   true for an AES key (Managed HSM `oct-HSM`), false for RSA. Decides AES-GCM vs RSA-OAEP-256, and
    *   therefore whether an encryption context can be bound at all.
    */
  final case class Config(keyIdentifier: String, symmetric: Boolean = false)

  /** Build with an externally-supplied port. The test seam. */
  def withPort(port: AzureKeyVaultPort, config: Config): AzureKeyVaultRootOfTrust =
    new AzureKeyVaultRootOfTrust(port, config)

  /** Resource-managed builder for `Server.boot`. Credentials come from `DefaultAzureCredential` (environment,
    * workload identity, managed identity, Azure CLI). `CryptographyClient` holds an HTTP pipeline; the
    * Resource exists so it is built once at boot rather than per call.
    */
  def resource(config: Config): Resource[IO, AzureKeyVaultRootOfTrust] =
    Resource.eval(IO.blocking {
      val client = new CryptographyClientBuilder()
        .credential(new DefaultAzureCredentialBuilder().build())
        .keyIdentifier(config.keyIdentifier)
        .buildClient()
      new AzureKeyVaultRootOfTrust(AzureKeyVaultPort.fromClient(client, config.keyIdentifier), config)
    })

  private def dataKeyBytes(spec: KeySpec): Int =
    spec.algorithm match
      case Algorithm.AES if spec.sizeBits == 128 => 16
      case Algorithm.AES if spec.sizeBits == 192 => 24
      case _                                     => 32

  private def sha256(message: Array[Byte]): Array[Byte] =
    MessageDigest.getInstance("SHA-256").digest(message)

  private def sigAlg(alg: SigAlgorithm): SignatureAlgorithm = alg match
    case SigAlgorithm.RsaPssSha256 => SignatureAlgorithm.PS256
    case SigAlgorithm.EcdsaSha256  => SignatureAlgorithm.ES256

  /** `iv ‖ ciphertext ‖ tag`. Azure hands back the tag separately and demands all three on decrypt; packing
    * them keeps `Ciphertext` a single opaque blob, consistent with the other backends.
    */
  private[azure] def pack(iv: Array[Byte], cipherText: Array[Byte], authTag: Array[Byte]): Array[Byte] =
    iv ++ cipherText ++ authTag

  private[azure] def unpack(
      blob: Array[Byte]
  ): Either[KmsError, (Array[Byte], Array[Byte], Array[Byte])] =
    if blob.length < GcmNonceBytes + GcmTagBytes then
      Left(KmsError(
        ErrorCode.CryptographicFailure,
        "ciphertext is too short to be an Azure AES-GCM envelope"
      ))
    else
      val iv   = blob.take(GcmNonceBytes)
      val rest = blob.drop(GcmNonceBytes)
      val ct   = rest.dropRight(GcmTagBytes)
      val tag  = rest.takeRight(GcmTagBytes)
      Right((iv, ct, tag))

  /** Canonical, injective encoding of the encryption context — identical to the software and GCP backends, so
    * the same context produces the same AAD bytes regardless of which root of trust is configured.
    */
  private[azure] def aad(context: Map[String, String]): Array[Byte] =
    if context.isEmpty then Array.emptyByteArray
    else
      val entries = context.toSeq.sortBy(_._1)
      val size = entries.foldLeft(0) { case (n, (k, v)) =>
        n + 8 + k.getBytes(UTF_8).length + v.getBytes(UTF_8).length
      }
      entries
        .foldLeft(ByteBuffer.allocate(size)) { case (buf, (k, v)) =>
          val kb = k.getBytes(UTF_8)
          val vb = v.getBytes(UTF_8)
          buf.putInt(kb.length).put(kb).putInt(vb.length).put(vb)
        }
        .array()

  private def translate(opName: String): Throwable => Either[KmsError, Nothing] = {
    case e: com.azure.core.exception.HttpResponseException =>
      Left(KmsError(
        ErrorCode.CryptographicFailure,
        s"Azure Key Vault $opName failed (${e.getResponse.getStatusCode}): ${e.getMessage}"
      ))
    case e =>
      Left(KmsError(ErrorCode.GeneralFailure, s"Azure Key Vault $opName error: ${e.getMessage}"))
  }
