package dev.aegiskms.crypto.software

import cats.effect.{IO, Resource}
import dev.aegiskms.core.{
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
import org.slf4j.LoggerFactory

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Path
import java.security.spec.{MGF1ParameterSpec, PSSParameterSpec}
import java.security.{SecureRandom, Signature as JcaSignature}
import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}
import javax.crypto.{Cipher, Mac}

/** A `RootOfTrust` implemented entirely with the JDK's own JCE providers, backed by a `KeyStore`.
  *
  * ## What this is for
  *
  * Every other `RootOfTrust` needs an account somewhere — an AWS CMK, a GCP CryptoKey, a Vault cluster, an
  * HSM slot. That makes the shortest path to trying Aegis, or to running an integration test in CI, involve
  * cloud credentials. This adapter removes that: it performs **real cryptography** (AES-256-GCM, RSA-PSS,
  * ECDSA P-256) with no external dependency and no network call, so `sign`, `encrypt`, `wrap` and friends
  * behave like the production adapters rather than like the deterministic-MAC
  * [[dev.aegiskms.crypto.RootOfTrust.inMemory]] stub.
  *
  * ## Why it is not for production
  *
  * The [[dev.aegiskms.crypto.RootOfTrust]] contract says no implementation holds raw key material outside its
  * secure boundary. Here the boundary *is* the JVM heap: the KEK and the signing private keys are ordinary
  * `java.security.Key` objects in the same process as the request handlers. A heap dump, a `/proc/<pid>/mem`
  * read, or an RCE in the server is game over for every key ever wrapped by this adapter — none of which is
  * true of AWS KMS or a PKCS#11 HSM, where the key never leaves the module.
  *
  * It is therefore **not enabled by default** (`aegis.crypto.kind` defaults to `in-memory`), it logs a
  * warning banner on construction, and `Preflight` reports it as a dev-grade setting that must not bind a
  * network-reachable address. Production deployments use a real KMS or HSM.
  *
  * ## Ciphertext format
  *
  * Everything this adapter produces — `generateDataKey`, `encrypt`, `wrap` — shares one self-describing
  * layout:
  *
  * {{{
  * ┌────────┬─────────────────┬──────────────┬───────────────────────────┐
  * │ 1 byte │ 4 bytes         │ 12 bytes     │ n bytes                   │
  * │ format │ KEK generation  │ GCM nonce    │ AES-256-GCM ct ‖ 16B tag  │
  * └────────┴─────────────────┴──────────────┴───────────────────────────┘
  * }}}
  *
  * Carrying the KEK generation in the header is what makes [[rotate]] non-destructive: a rotation mints a new
  * generation for future writes while every prior generation stays in the keystore, so material wrapped
  * before the rotation still unwraps afterwards. This mirrors how AWS KMS keeps prior CMK backing keys alive
  * after automatic rotation.
  *
  * Each operation family derives its own AES key from the KEK with HKDF-SHA-256, using a purpose label and —
  * where the API supplies one — the `KeyId` as the `info` input. Two consequences: ciphertext produced for
  * key A cannot be decrypted as key B even by this same adapter, and the wrap, encrypt, and data-key families
  * are cryptographically separated from each other. The encryption context is additionally bound as GCM AAD,
  * so a context mismatch fails authentication rather than returning garbage.
  *
  * ## Known limitation: signing is not separated per key
  *
  * The envelope families derive a distinct AES key per `KeyId`, but [[sign]] and [[verify]] do not — there is
  * one keypair per [[dev.aegiskms.core.SigAlgorithm]] for the whole keystore, so a signature produced for key
  * A verifies under key B. This matches `AwsKmsRootOfTrust`, which signs with the single configured CMK
  * regardless of `KeyId`; per-key backing keys are ROADMAP 3.0.e (per-key RoT routing) across every adapter,
  * not something to fix here alone. It is not fixable the same way the envelope families were: HKDF gives you
  * symmetric key material, whereas per-key signing needs deterministic asymmetric keygen from a derived seed,
  * which is awkward for EC and impractical for RSA. `SoftwareRootOfTrustSpec` pins the current behaviour so a
  * future change to per-key signing fails loudly rather than silently.
  */
final class SoftwareRootOfTrust(keyStore: SoftwareKeyStore) extends RootOfTrust[IO]:

  import SoftwareRootOfTrust.*

  private val random = new SecureRandom()

  def generateDataKey(spec: KeySpec): IO[Either[KmsError, WrappedKey]] =
    IO.blocking {
      val material = new Array[Byte](dataKeyBytes(spec))
      random.nextBytes(material)
      val generation = keyStore.currentKekVersion
      val envelope   = seal(generation, DataKeyPurpose, material, Map.empty)
      Right(WrappedKey(bytes = envelope, rotationId = s"kek-v$generation"))
    }.handleError(translate("GenerateDataKey"))

  def unwrap(wrapped: WrappedKey): IO[Either[KmsError, RawKey]] =
    IO.blocking(open(DataKeyPurpose, wrapped.bytes, Map.empty).map(RawKey(_)))
      .handleError(translate("Unwrap"))

  /** Mint the next KEK generation. Prior generations stay in the keystore, so material wrapped before this
    * call remains recoverable; only new writes use the new generation.
    */
  def rotate(id: KeyId): IO[Either[KmsError, KeyId]] =
    IO.blocking {
      val next = keyStore.rotateKek()
      logger.info(s"software root-of-trust: KEK rotated to generation v$next")
      Right(id)
    }.handleError(translate("Rotate"))

  def sign(id: KeyId, message: Array[Byte], alg: SigAlgorithm): IO[Either[KmsError, Signature]] =
    IO.blocking {
      val (priv, _) = keyStore.signingKeyPair(alg)
      val signer    = jcaSigner(alg)
      signer.initSign(priv, random)
      signer.update(message)
      Right(Signature(signer.sign(), alg))
    }.handleError(translate("Sign"))

  def verify(
      id: KeyId,
      message: Array[Byte],
      signature: Signature
  ): IO[Either[KmsError, Boolean]] =
    IO.blocking {
      val (_, pub) = keyStore.signingKeyPair(signature.algorithm)
      val verifier = jcaSigner(signature.algorithm)
      verifier.initVerify(pub)
      verifier.update(message)
      Right(verifier.verify(signature.bytes))
    }.handleError {
      // A structurally invalid signature is a `false` verdict, not an infrastructure failure — the caller
      // asked "does this signature check out?" and the answer is no.
      case _: java.security.SignatureException => Right(false)
      case e                                   => translate("Verify")(e)
    }

  def encrypt(
      id: KeyId,
      plaintext: Array[Byte],
      context: Map[String, String]
  ): IO[Either[KmsError, Ciphertext]] =
    IO.blocking {
      Right(Ciphertext(seal(keyStore.currentKekVersion, encryptPurpose(id), plaintext, context)))
    }.handleError(translate("Encrypt"))

  def decrypt(
      id: KeyId,
      ciphertext: Ciphertext,
      context: Map[String, String]
  ): IO[Either[KmsError, Array[Byte]]] =
    IO.blocking(open(encryptPurpose(id), ciphertext.bytes, context))
      .handleError(translate("Decrypt"))

  def wrap(id: KeyId, dek: Array[Byte]): IO[Either[KmsError, WrappedDek]] =
    IO.blocking {
      Right(WrappedDek(seal(keyStore.currentKekVersion, wrapPurpose(id), dek, Map.empty)))
    }.handleError(translate("Wrap"))

  def unwrapDek(id: KeyId, wrapped: WrappedDek): IO[Either[KmsError, Array[Byte]]] =
    IO.blocking(open(wrapPurpose(id), wrapped.bytes, Map.empty))
      .handleError(translate("Unwrap"))

  // ── Envelope ───────────────────────────────────────────────────────────────

  /** AES-256-GCM encrypt under the HKDF-derived subkey for `purpose`, prefixed with the header. */
  private def seal(
      generation: Int,
      purpose: String,
      plaintext: Array[Byte],
      context: Map[String, String]
  ): Array[Byte] =
    val nonce = new Array[Byte](NonceBytes)
    random.nextBytes(nonce)
    val cipher = Cipher.getInstance(AeadTransformation)
    cipher.init(
      Cipher.ENCRYPT_MODE,
      subkey(generation, purpose),
      new GCMParameterSpec(TagBits, nonce)
    )
    cipher.updateAAD(aad(context))
    header(generation) ++ nonce ++ cipher.doFinal(plaintext)

  /** Inverse of [[seal]]. Returns a `KmsError` rather than throwing for the two failures a caller can
    * legitimately provoke: a blob that is not ours, and a wrong encryption context.
    */
  private def open(
      purpose: String,
      blob: Array[Byte],
      context: Map[String, String]
  ): Either[KmsError, Array[Byte]] =
    if blob.length < HeaderBytes + NonceBytes + TagBits / 8 then
      Left(KmsError(ErrorCode.CryptographicFailure, "ciphertext is too short to be an Aegis envelope"))
    else if blob(0) != FormatVersion then
      Left(KmsError(
        ErrorCode.CryptographicFailure,
        s"unsupported envelope format version ${blob(0)} (this build writes $FormatVersion)"
      ))
    else
      val generation = ByteBuffer.wrap(blob, 1, 4).getInt
      val nonce      = blob.slice(HeaderBytes, HeaderBytes + NonceBytes)
      val body       = blob.drop(HeaderBytes + NonceBytes)
      try
        val cipher = Cipher.getInstance(AeadTransformation)
        cipher.init(
          Cipher.DECRYPT_MODE,
          subkey(generation, purpose),
          new GCMParameterSpec(TagBits, nonce)
        )
        cipher.updateAAD(aad(context))
        Right(cipher.doFinal(body))
      catch
        case _: javax.crypto.AEADBadTagException =>
          Left(KmsError(
            ErrorCode.CryptographicFailure,
            "authentication failed — wrong key, wrong encryption context, or tampered ciphertext"
          ))

  /** HKDF-SHA-256 over the generation's KEK. `purpose` is the `info` input, so each operation family (and,
    * where the API exposes one, each `KeyId`) gets a distinct AES key.
    */
  private def subkey(generation: Int, purpose: String): SecretKeySpec =
    new SecretKeySpec(Hkdf.derive(keyStore.kek(generation).getEncoded, purpose.getBytes(UTF_8), 32), "AES")

object SoftwareRootOfTrust:

  private val logger = LoggerFactory.getLogger(classOf[SoftwareRootOfTrust])

  private val FormatVersion      = 1.toByte
  private val HeaderBytes        = 5 // format byte + 4-byte generation
  private val NonceBytes         = 12
  private val TagBits            = 128
  private val AeadTransformation = "AES/GCM/NoPadding"

  private val DataKeyPurpose = "aegis/v1/datakey"

  private def encryptPurpose(id: KeyId): String = s"aegis/v1/encrypt/${id.value}"
  private def wrapPurpose(id: KeyId): String    = s"aegis/v1/wrap/${id.value}"

  /** Configuration for the software backend.
    *
    * @param keystorePath
    *   where to persist key material. `None` uses an ephemeral in-heap keystore — every key wrapped against
    *   it is unrecoverable once the JVM exits, which is what you want in CI and nowhere else.
    * @param keystorePassword
    *   protects the keystore file. Required whenever `keystorePath` is set.
    */
  final case class Config(keystorePath: Option[Path], keystorePassword: String)

  /** Build the adapter, logging the mandatory warning banner. */
  def fromConfig(cfg: Config): SoftwareRootOfTrust =
    val store = cfg.keystorePath match
      case Some(path) =>
        require(cfg.keystorePassword.nonEmpty, "software root-of-trust requires a keystore password")
        SoftwareKeyStore.atPath(path, cfg.keystorePassword)
      case None => SoftwareKeyStore.ephemeral()
    warn(cfg)
    new SoftwareRootOfTrust(store)

  /** Resource-managed builder for `Server.boot`. There is no external client to close, so the finalizer only
    * drops the reference; the shape exists so the boot wiring treats every backend identically.
    */
  def resource(cfg: Config): Resource[IO, SoftwareRootOfTrust] =
    Resource.eval(IO.blocking(fromConfig(cfg)))

  /** Build directly from a keystore. The test seam, and the entry point for embedders that manage their own
    * `KeyStore` lifecycle. Does not log the banner — callers taking this path have opted in explicitly.
    */
  def withKeyStore(store: SoftwareKeyStore): SoftwareRootOfTrust =
    new SoftwareRootOfTrust(store)

  private def warn(cfg: Config): Unit =
    val where = cfg.keystorePath.fold("ephemeral (in-heap; key material lost on exit)")(p =>
      s"keystore at $p"
    )
    logger.warn(
      s"""
         |╔═══════════════════════════════════════════════════════════════════════════════╗
         |  CRYPTO: software root-of-trust — $where
         |  Real AES-256-GCM / RSA-PSS / ECDSA, but the KEK and signing keys live in this
         |  JVM's heap. A heap dump or process compromise exposes every key ever wrapped.
         |  Intended for local development, CI, and demos ONLY. Production deployments must
         |  set aegis.crypto.kind=aws-kms (or another HSM/KMS-backed adapter).
         |╚═══════════════════════════════════════════════════════════════════════════════╝""".stripMargin
    )

  private def header(generation: Int): Array[Byte] =
    ByteBuffer.allocate(HeaderBytes).put(FormatVersion).putInt(generation).array()

  /** Canonical, injective encoding of the encryption context for use as GCM AAD. Sorted by key so map
    * ordering never changes the bytes, and length-prefixed so `{"ab" -> "c"}` and `{"a" -> "bc"}` cannot
    * collide.
    */
  private def aad(context: Map[String, String]): Array[Byte] =
    if context.isEmpty then Array.emptyByteArray
    else
      context.toSeq.sortBy(_._1).foldLeft(ByteBuffer.allocate(estimatedAadSize(context))) {
        case (buf, (k, v)) =>
          val kb = k.getBytes(UTF_8)
          val vb = v.getBytes(UTF_8)
          buf.putInt(kb.length).put(kb).putInt(vb.length).put(vb)
      }.array()

  private def estimatedAadSize(context: Map[String, String]): Int =
    context.foldLeft(0) { case (n, (k, v)) =>
      n + 8 + k.getBytes(UTF_8).length + v.getBytes(UTF_8).length
    }

  /** Data-key size in bytes. AES specs use their declared size; anything else falls back to 256 bits,
    * matching the AWS adapter's behaviour for specs the actor layer should already have rejected.
    */
  private def dataKeyBytes(spec: KeySpec): Int =
    spec.algorithm match
      case dev.aegiskms.core.Algorithm.AES if spec.sizeBits == 128 => 16
      case dev.aegiskms.core.Algorithm.AES if spec.sizeBits == 192 => 24
      case _                                                       => 32

  private def jcaSigner(alg: SigAlgorithm): JcaSignature = alg match
    case SigAlgorithm.RsaPssSha256 =>
      val s = JcaSignature.getInstance("RSASSA-PSS")
      s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
      s
    case SigAlgorithm.EcdsaSha256 => JcaSignature.getInstance("SHA256withECDSA")

  private def translate(opName: String): Throwable => Either[KmsError, Nothing] = e =>
    Left(KmsError(
      ErrorCode.CryptographicFailure,
      s"software root-of-trust $opName failed: ${e.getMessage}"
    ))

/** HKDF-SHA-256 (RFC 5869), extract-then-expand. Implemented here rather than pulled from a library because
  * `aegis-crypto` deliberately ships no third-party crypto dependency, and the JDK exposes no HKDF before JDK
  * 24's `KDF` API.
  */
private object Hkdf:

  private val HashLen = 32

  def derive(ikm: Array[Byte], info: Array[Byte], lengthBytes: Int): Array[Byte] =
    expand(extract(ikm), info, lengthBytes)

  /** `PRK = HMAC(salt, IKM)`. The salt is the all-zero string, per RFC 5869 §2.2 for callers with no salt —
    * the IKM here is a full-entropy 256-bit KEK, so a salt adds nothing.
    */
  private def extract(ikm: Array[Byte]): Array[Byte] =
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(new Array[Byte](HashLen), "HmacSHA256"))
    mac.doFinal(ikm)

  private def expand(prk: Array[Byte], info: Array[Byte], lengthBytes: Int): Array[Byte] =
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(prk, "HmacSHA256"))
    val out      = new Array[Byte](lengthBytes)
    var previous = Array.emptyByteArray
    var written  = 0
    var counter  = 1
    while written < lengthBytes do
      mac.update(previous)
      mac.update(info)
      mac.update(counter.toByte)
      previous = mac.doFinal()
      val take = math.min(previous.length, lengthBytes - written)
      System.arraycopy(previous, 0, out, written, take)
      written += take
      counter += 1
    out
