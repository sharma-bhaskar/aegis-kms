package dev.aegiskms.crypto.gcp

import cats.effect.{IO, Resource}
import com.google.cloud.kms.v1.{CryptoKeyName, CryptoKeyVersionName, Digest, KeyManagementServiceClient}
import com.google.protobuf.ByteString
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
import java.security.spec.X509EncodedKeySpec
import java.security.{KeyFactory, MessageDigest, PublicKey, Signature as JcaSignature}
import java.util.Base64

/** A `RootOfTrust` backed by Google Cloud KMS.
  *
  * The second cloud backend, and the one that proves the SPI is not AWS-shaped. Cloud KMS is missing two
  * primitives the AWS adapter leans on, so this is a genuine adapter rather than a rename:
  *
  * ## No `GenerateDataKey`
  *
  * AWS returns a `(plaintext, wrapped)` DEK pair from one call, generated inside AWS's HSMs. Cloud KMS has no
  * such API, so [[generateDataKey]] composes two calls: `GenerateRandomBytes` at HSM protection level for the
  * material, then `Encrypt` under the KEK to wrap it. The security property is preserved — the bytes come
  * from Google's HSM RNG, not this process's — but it costs an extra round-trip, and the plaintext DEK does
  * transit the client. That is inherent to Cloud KMS, not a shortcut taken here.
  *
  * ## No `Verify`
  *
  * AWS KMS verifies signatures server-side. Cloud KMS only signs. [[verify]] therefore fetches the
  * CryptoKeyVersion's public key and checks the signature locally with JCE. This is the documented Google
  * pattern, and it is not a weakening: verification needs only public material, so doing it in-process
  * reveals nothing. Public keys are fetched per call; a cache is a fair optimisation once there is a
  * benchmark to justify it.
  *
  * ## Signing takes a digest
  *
  * For the RSA-PSS and ECDSA SHA-256 algorithms Aegis exposes, Cloud KMS wants a pre-computed `Digest` rather
  * than the message. Hashing happens here.
  *
  * ## Encryption context
  *
  * Cloud KMS binds a single opaque AAD byte string, where AWS takes a map. The map is serialised with the
  * same canonical, length-prefixed encoding the software backend uses, so `{"ab":"c"}` and `{"a":"bc"}`
  * cannot collide and map ordering never changes the bytes.
  */
final class GcpKmsRootOfTrust(port: GcpKmsPort, config: GcpKmsRootOfTrust.Config) extends RootOfTrust[IO]:

  import GcpKmsRootOfTrust.*

  private val keyName: CryptoKeyName = CryptoKeyName.of(
    config.projectId,
    config.location,
    config.keyRing,
    config.cryptoKey
  )

  private val location: String = s"projects/${config.projectId}/locations/${config.location}"

  private def signingVersion: CryptoKeyVersionName = CryptoKeyVersionName.of(
    config.projectId,
    config.location,
    config.keyRing,
    config.signingKey.getOrElse(config.cryptoKey),
    config.signingKeyVersion
  )

  def generateDataKey(spec: KeySpec): IO[Either[KmsError, WrappedKey]] =
    IO.blocking {
      val material = port.generateRandomBytes(location, dataKeyBytes(spec))
      val wrapped  = port.encrypt(keyName, material, Array.emptyByteArray)
      Right(WrappedKey(bytes = wrapped, rotationId = keyName.toString))
    }.handleError(translate("GenerateDataKey"))

  def unwrap(wrapped: WrappedKey): IO[Either[KmsError, RawKey]] =
    IO.blocking(Right(RawKey(port.decrypt(keyName, wrapped.bytes, Array.emptyByteArray))))
      .handleError(translate("Decrypt"))

  /** Cloud KMS rotates by creating a new CryptoKeyVersion, which becomes primary for subsequent encrypts.
    * Prior versions remain able to decrypt their own ciphertext, so this is non-destructive — the version is
    * embedded in the ciphertext blob by Cloud KMS itself.
    */
  def rotate(id: KeyId): IO[Either[KmsError, KeyId]] =
    IO.blocking {
      port.createKeyVersion(keyName)
      Right(id)
    }.handleError(translate("CreateCryptoKeyVersion"))

  def sign(id: KeyId, message: Array[Byte], alg: SigAlgorithm): IO[Either[KmsError, Signature]] =
    IO.blocking {
      Right(Signature(port.asymmetricSign(signingVersion, digestFor(message)), alg))
    }.handleError(translate("AsymmetricSign"))

  /** Verified locally against the fetched public key — Cloud KMS exposes no verify operation. */
  def verify(
      id: KeyId,
      message: Array[Byte],
      signature: Signature
  ): IO[Either[KmsError, Boolean]] =
    IO.blocking {
      val pub      = publicKeyFrom(port.publicKeyPem(signingVersion), signature.algorithm)
      val verifier = jcaVerifier(signature.algorithm)
      verifier.initVerify(pub)
      verifier.update(message)
      Right(verifier.verify(signature.bytes))
    }.handleError {
      // A structurally invalid signature is a `false` verdict, not an infrastructure failure.
      case _: java.security.SignatureException => Right(false)
      case e                                   => translate("GetPublicKey")(e)
    }

  def encrypt(
      id: KeyId,
      plaintext: Array[Byte],
      context: Map[String, String]
  ): IO[Either[KmsError, Ciphertext]] =
    guardPlaintextSize(plaintext) {
      IO.blocking(Right(Ciphertext(port.encrypt(keyName, plaintext, aad(context)))))
        .handleError(translate("Encrypt"))
    }

  def decrypt(
      id: KeyId,
      ciphertext: Ciphertext,
      context: Map[String, String]
  ): IO[Either[KmsError, Array[Byte]]] =
    IO.blocking(Right(port.decrypt(keyName, ciphertext.bytes, aad(context))))
      .handleError(translate("Decrypt"))

  def wrap(id: KeyId, dek: Array[Byte]): IO[Either[KmsError, WrappedDek]] =
    guardPlaintextSize(dek) {
      IO.blocking(Right(WrappedDek(port.encrypt(keyName, dek, Array.emptyByteArray))))
        .handleError(translate("Wrap"))
    }

  def unwrapDek(id: KeyId, wrapped: WrappedDek): IO[Either[KmsError, Array[Byte]]] =
    IO.blocking(Right(port.decrypt(keyName, wrapped.bytes, Array.emptyByteArray)))
      .handleError(translate("Unwrap"))

  /** Cloud KMS caps symmetric `Encrypt` plaintext at 64 KiB. Checking here turns a remote `INVALID_ARGUMENT`
    * into a local error that names the limit — the AWS adapter has the same class of cap (4 KiB) and lets the
    * service report it, which is a worse experience.
    */
  private def guardPlaintextSize[A](
      plaintext: Array[Byte]
  )(op: => IO[Either[KmsError, A]]): IO[Either[KmsError, A]] =
    if plaintext.length > MaxPlaintextBytes then
      IO.pure(Left(KmsError(
        ErrorCode.InvalidField,
        s"plaintext is ${plaintext.length} bytes; Cloud KMS symmetric encrypt accepts at most $MaxPlaintextBytes"
      )))
    else op

object GcpKmsRootOfTrust:

  /** Cloud KMS symmetric-encrypt plaintext limit. */
  val MaxPlaintextBytes: Int = 64 * 1024

  /** Where the keys live.
    *
    * @param signingKey
    *   an optional separate CryptoKey for asymmetric signing. Cloud KMS keys have a single purpose — a key
    *   with `ENCRYPT_DECRYPT` cannot sign — so a deployment doing both needs two. Defaults to `cryptoKey`,
    *   which is correct only when the deployment does not sign.
    * @param signingKeyVersion
    *   Cloud KMS asymmetric operations address a specific version, not the key.
    */
  final case class Config(
      projectId: String,
      location: String,
      keyRing: String,
      cryptoKey: String,
      signingKey: Option[String] = None,
      signingKeyVersion: String = "1"
  )

  /** Build with an externally-supplied port. The test seam. */
  def withPort(port: GcpKmsPort, config: Config): GcpKmsRootOfTrust =
    new GcpKmsRootOfTrust(port, config)

  /** Resource-managed builder for `Server.boot`. `KeyManagementServiceClient` owns gRPC channels and
    * background threads, so it must be closed on shutdown rather than leaked for the process lifetime.
    * Credentials come from Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS`, workload
    * identity, or the metadata server).
    */
  def resource(config: Config): Resource[IO, GcpKmsRootOfTrust] =
    Resource
      .fromAutoCloseable(IO.blocking(KeyManagementServiceClient.create()))
      .map(client => new GcpKmsRootOfTrust(GcpKmsPort.fromClient(client), config))

  private def dataKeyBytes(spec: KeySpec): Int =
    spec.algorithm match
      case Algorithm.AES if spec.sizeBits == 128 => 16
      case Algorithm.AES if spec.sizeBits == 192 => 24
      case _                                     => 32

  private def digestFor(message: Array[Byte]): Digest =
    val sha = MessageDigest.getInstance("SHA-256").digest(message)
    Digest.newBuilder().setSha256(ByteString.copyFrom(sha)).build()

  private def jcaVerifier(alg: SigAlgorithm): JcaSignature = alg match
    case SigAlgorithm.RsaPssSha256 =>
      val s = JcaSignature.getInstance("RSASSA-PSS")
      s.setParameter(new java.security.spec.PSSParameterSpec(
        "SHA-256",
        "MGF1",
        java.security.spec.MGF1ParameterSpec.SHA256,
        32,
        1
      ))
      s
    case SigAlgorithm.EcdsaSha256 => JcaSignature.getInstance("SHA256withECDSA")

  /** Parse the PEM Cloud KMS returns from `GetPublicKey` into a JCA `PublicKey`. */
  private[gcp] def publicKeyFrom(pem: String, alg: SigAlgorithm): PublicKey =
    val body = pem
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replace("-----END PUBLIC KEY-----", "")
      .replaceAll("\\s", "")
    val der = Base64.getDecoder.decode(body)
    val factory = alg match
      case SigAlgorithm.RsaPssSha256 => KeyFactory.getInstance("RSA")
      case SigAlgorithm.EcdsaSha256  => KeyFactory.getInstance("EC")
    factory.generatePublic(new X509EncodedKeySpec(der))

  /** Canonical, injective encoding of the encryption context, matching the software backend's. Cloud KMS
    * binds one opaque AAD string, so the map has to collapse to bytes deterministically: sorted by key, and
    * length-prefixed so `{"ab":"c"}` and `{"a":"bc"}` cannot produce the same input.
    */
  private[gcp] def aad(context: Map[String, String]): Array[Byte] =
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
    case e: com.google.api.gax.rpc.ApiException =>
      Left(KmsError(
        ErrorCode.CryptographicFailure,
        s"GCP KMS $opName failed (${e.getStatusCode.getCode}): ${e.getMessage}"
      ))
    case e =>
      Left(KmsError(ErrorCode.GeneralFailure, s"GCP KMS $opName error: ${e.getMessage}"))
  }
