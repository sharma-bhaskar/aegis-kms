package dev.aegiskms.crypto.vault

import cats.effect.{IO, Resource}
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
import io.circe.Json

import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64

/** A `RootOfTrust` backed by HashiCorp Vault's Transit secrets engine.
  *
  * Transit is the closest of the four backends to AWS KMS in capability, and the furthest in shape:
  *
  *   - **It has data-key generation.** `transit/datakey/plaintext/:key` returns a plaintext + wrapped pair in
  *     one call, exactly like AWS's `GenerateDataKey`. Neither GCP nor Azure offers this, so of the three
  *     non-AWS backends only this one preserves the property that DEK material originates in the KMS.
  *   - **It has server-side sign and verify**, like AWS and Azure, unlike Cloud KMS.
  *   - **It has native key rotation** (`transit/keys/:key/rotate`), and Transit ciphertext carries its key
  *     version in the `vault:v1:` prefix, so rotation is genuinely non-destructive — old ciphertext keeps
  *     decrypting without the adapter tracking versions itself.
  *   - **Ciphertext is a string, not bytes.** Transit returns `vault:v1:<base64>`. That string is stored
  *     verbatim as the ciphertext bytes, so the prefix survives the round-trip and Vault can pick the right
  *     key version on the way back.
  *
  * ## Encryption context
  *
  * Transit's `context` parameter only applies to keys created with `derived=true`, where it derives a
  * per-context subkey — which is stronger than AAD, since a wrong context yields a different key rather than
  * a failed tag check. It is sent whenever the caller supplies a context; on a non-derived key Vault rejects
  * the request rather than ignoring it, so a context can never be silently dropped.
  *
  * The map is serialised with the same canonical, length-prefixed encoding the software, GCP, and Azure
  * backends use, then base64'd, so the same context produces the same derivation input on every backend.
  */
final class VaultTransitRootOfTrust(port: VaultTransitPort, config: VaultTransitRootOfTrust.Config)
    extends RootOfTrust[IO]:

  import VaultTransitRootOfTrust.*

  private def keyPath(op: String): String  = s"${config.mount}/$op/${config.keyName}"
  private def signPath(op: String): String = s"${config.mount}/$op/${config.signingKeyName}"

  /** Transit's own data-key endpoint — the only non-AWS backend here that has one. */
  def generateDataKey(spec: KeySpec): IO[Either[KmsError, WrappedKey]] =
    IO.blocking {
      val body = Json.obj("bits" -> Json.fromInt(dataKeyBits(spec)))
      val data = port.post(s"${config.mount}/datakey/plaintext/${config.keyName}", body)
      // `plaintext` is deliberately ignored: the SPI's contract is that generateDataKey returns only the
      // wrapped form, and the caller re-derives the plaintext through `unwrap` when it actually needs it.
      str(data, "ciphertext") match
        case Some(ct) => Right(WrappedKey(ct.getBytes(UTF_8), config.keyName))
        case None     => Left(missing("datakey", "ciphertext"))
    }.handleError(translate("GenerateDataKey"))

  def unwrap(wrapped: WrappedKey): IO[Either[KmsError, RawKey]] =
    IO.blocking {
      val body = Json.obj("ciphertext" -> Json.fromString(new String(wrapped.bytes, UTF_8)))
      val data = port.post(keyPath("decrypt"), body)
      str(data, "plaintext") match
        case Some(b64) => Right(RawKey(Base64.getDecoder.decode(b64)))
        case None      => Left(missing("decrypt", "plaintext"))
    }.handleError(translate("Decrypt"))

  def rotate(id: KeyId): IO[Either[KmsError, KeyId]] =
    IO.blocking {
      port.post(s"${config.mount}/keys/${config.keyName}/rotate", Json.obj())
      Right(id)
    }.handleError(translate("Rotate"))

  def sign(id: KeyId, message: Array[Byte], alg: SigAlgorithm): IO[Either[KmsError, Signature]] =
    IO.blocking {
      val body = Json.obj(
        "input"               -> Json.fromString(b64(message)),
        "signature_algorithm" -> Json.fromString(vaultSigAlgorithm(alg)),
        "hash_algorithm"      -> Json.fromString("sha2-256")
      )
      val data = port.post(signPath("sign"), body)
      str(data, "signature") match
        // Vault's signature is `vault:v1:<base64>`; stored verbatim so `verify` can hand it straight back
        // and Vault resolves the key version itself.
        case Some(sig) => Right(Signature(sig.getBytes(UTF_8), alg))
        case None      => Left(missing("sign", "signature"))
    }.handleError(translate("Sign"))

  def verify(
      id: KeyId,
      message: Array[Byte],
      signature: Signature
  ): IO[Either[KmsError, Boolean]] =
    IO.blocking {
      val body = Json.obj(
        "input"               -> Json.fromString(b64(message)),
        "signature"           -> Json.fromString(new String(signature.bytes, UTF_8)),
        "signature_algorithm" -> Json.fromString(vaultSigAlgorithm(signature.algorithm)),
        "hash_algorithm"      -> Json.fromString("sha2-256")
      )
      val data = port.post(signPath("verify"), body)
      Right(data.hcursor.get[Boolean]("valid").getOrElse(false))
    }.handleError {
      // A malformed signature string is Vault answering "that isn't a signature", which is a `false`
      // verdict rather than an outage.
      case VaultTransitPort.VaultHttpError(400, _) => Right(false)
      case e                                       => translate("Verify")(e)
    }

  def encrypt(
      id: KeyId,
      plaintext: Array[Byte],
      context: Map[String, String]
  ): IO[Either[KmsError, Ciphertext]] =
    IO.blocking {
      val data = port.post(
        keyPath("encrypt"),
        withContext(
          Json.obj(
            "plaintext" -> Json.fromString(b64(plaintext))
          ),
          context
        )
      )
      str(data, "ciphertext") match
        case Some(ct) => Right(Ciphertext(ct.getBytes(UTF_8)))
        case None     => Left(missing("encrypt", "ciphertext"))
    }.handleError(translate("Encrypt"))

  def decrypt(
      id: KeyId,
      ciphertext: Ciphertext,
      context: Map[String, String]
  ): IO[Either[KmsError, Array[Byte]]] =
    IO.blocking {
      val data = port.post(
        keyPath("decrypt"),
        withContext(
          Json.obj(
            "ciphertext" -> Json.fromString(new String(ciphertext.bytes, UTF_8))
          ),
          context
        )
      )
      str(data, "plaintext") match
        case Some(b) => Right(Base64.getDecoder.decode(b))
        case None    => Left(missing("decrypt", "plaintext"))
    }.handleError(translate("Decrypt"))

  def wrap(id: KeyId, dek: Array[Byte]): IO[Either[KmsError, WrappedDek]] =
    IO.blocking {
      val data = port.post(keyPath("encrypt"), Json.obj("plaintext" -> Json.fromString(b64(dek))))
      str(data, "ciphertext") match
        case Some(ct) => Right(WrappedDek(ct.getBytes(UTF_8)))
        case None     => Left(missing("encrypt", "ciphertext"))
    }.handleError(translate("Wrap"))

  def unwrapDek(id: KeyId, wrapped: WrappedDek): IO[Either[KmsError, Array[Byte]]] =
    IO.blocking {
      val body = Json.obj("ciphertext" -> Json.fromString(new String(wrapped.bytes, UTF_8)))
      val data = port.post(keyPath("decrypt"), body)
      str(data, "plaintext") match
        case Some(b) => Right(Base64.getDecoder.decode(b))
        case None    => Left(missing("decrypt", "plaintext"))
    }.handleError(translate("Unwrap"))

object VaultTransitRootOfTrust:

  /** @param mount
    *   Transit mount path, `transit` unless remounted.
    * @param signingKeyName
    *   Transit keys are type-specific — an `aes256-gcm96` key cannot sign — so signing needs its own
    *   `ecdsa-p256` or `rsa-2048` key. Defaults to `keyName`, which is correct only if you never sign.
    */
  final case class Config(
      address: String,
      token: String,
      keyName: String,
      mount: String = "transit",
      signingKeyName: String = "",
      namespace: Option[String] = None
  ):
    def resolvedSigningKey: String = if signingKeyName.isEmpty then keyName else signingKeyName

  /** Build with an externally-supplied port. The test seam. */
  def withPort(port: VaultTransitPort, config: Config): VaultTransitRootOfTrust =
    new VaultTransitRootOfTrust(port, config.copy(signingKeyName = config.resolvedSigningKey))

  /** Resource-managed builder for `Server.boot`. The JDK `HttpClient` needs no explicit shutdown, so the
    * Resource exists for symmetry with the other backends and to keep the boot wiring uniform.
    */
  def resource(config: Config): Resource[IO, VaultTransitRootOfTrust] =
    Resource.eval(IO.blocking {
      val port = VaultTransitPort.fromConfig(config.address, config.token, config.namespace)
      withPort(port, config)
    })

  private def b64(bytes: Array[Byte]): String = Base64.getEncoder.encodeToString(bytes)

  private def str(data: Json, field: String): Option[String] =
    data.hcursor.get[String](field).toOption

  /** Transit derives a per-context subkey on `derived=true` keys — stronger than AAD, since a wrong context
    * produces a different key rather than a failed tag check. Sent only when the caller supplies one.
    */
  private[vault] def withContext(body: Json, context: Map[String, String]): Json =
    if context.isEmpty then body
    else body.deepMerge(Json.obj("context" -> Json.fromString(b64(canonicalContext(context)))))

  /** Same canonical, length-prefixed encoding as the software, GCP, and Azure backends, so an identical
    * context maps to identical bytes no matter which root of trust is configured.
    */
  private[vault] def canonicalContext(context: Map[String, String]): Array[Byte] =
    val entries = context.toSeq.sortBy(_._1)
    val size = entries.foldLeft(0) { case (n, (k, v)) =>
      n + 8 + k.getBytes(UTF_8).length + v.getBytes(UTF_8).length
    }
    entries
      .foldLeft(java.nio.ByteBuffer.allocate(size)) { case (buf, (k, v)) =>
        val kb = k.getBytes(UTF_8)
        val vb = v.getBytes(UTF_8)
        buf.putInt(kb.length).put(kb).putInt(vb.length).put(vb)
      }
      .array()

  private def dataKeyBits(spec: KeySpec): Int =
    spec.algorithm match
      case Algorithm.AES if spec.sizeBits == 128 => 128
      case _                                     => 256

  private def vaultSigAlgorithm(alg: SigAlgorithm): String = alg match
    case SigAlgorithm.RsaPssSha256 => "pss"
    // Transit's `signature_algorithm` only applies to RSA keys; ECDSA ignores it, and "pkcs1v15" is the
    // value Vault accepts without complaint for non-RSA keys.
    case SigAlgorithm.EcdsaSha256 => "pkcs1v15"

  private def missing(op: String, field: String): KmsError =
    KmsError(
      ErrorCode.GeneralFailure,
      s"Vault Transit $op response did not contain '$field' — is the mount path or key name correct?"
    )

  private def translate(opName: String): Throwable => Either[KmsError, Nothing] = {
    case VaultTransitPort.VaultHttpError(status, body) =>
      val code =
        if status == 400 || status == 404 then ErrorCode.InvalidField else ErrorCode.CryptographicFailure
      Left(KmsError(code, s"Vault Transit $opName failed ($status): ${body.take(200)}"))
    case e =>
      Left(KmsError(ErrorCode.GeneralFailure, s"Vault Transit $opName error: ${e.getMessage}"))
  }
