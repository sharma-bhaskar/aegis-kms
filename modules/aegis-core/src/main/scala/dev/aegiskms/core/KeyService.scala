package dev.aegiskms.core

import cats.effect.{IO, Ref}
import cats.syntax.all.*

import java.time.Instant

/** Describes a stored key from the service's perspective. */
final case class ManagedKey(
    id: KeyId,
    spec: KeySpec,
    owner: Principal,
    createdAt: Instant,
    state: KeyState
)

enum KeyState:
  case PreActive, Active, Deactivated, Compromised, Destroyed

/** The primary algebra for interacting with Aegis-KMS from a library consumer's point of view.
  *
  * Parameterized on an effect `F[_]` so callers can plug in `cats.effect.IO`, `ZIO`, or any other compatible
  * effect type. The server modules wrap this trait with Pekko Typed actors; library users can use it directly
  * without ever touching an actor system.
  */
trait KeyService[F[_]]:
  def create(spec: KeySpec, by: Principal): F[Either[KmsError, ManagedKey]]
  def get(id: KeyId, by: Principal): F[Either[KmsError, ManagedKey]]
  def locate(namePattern: String, by: Principal): F[List[ManagedKey]]
  def activate(id: KeyId, by: Principal): F[Either[KmsError, ManagedKey]]
  def revoke(id: KeyId, by: Principal): F[Either[KmsError, ManagedKey]]
  def destroy(id: KeyId, by: Principal): F[Either[KmsError, Unit]]

  /** Sign `message` with the key identified by `id` using `alg`. The key must be in `KeyState.Active`. */
  def sign(id: KeyId, message: Array[Byte], alg: SigAlgorithm, by: Principal): F[Either[KmsError, Signature]]

  /** Verify `signature` over `message` for the key identified by `id`. Returns `Right(true)` for a valid
    * signature, `Right(false)` for a bad one, `Left(_)` for missing keys / lookup failures. The error/false
    * distinction matters: a caller seeing `Right(false)` knows the key was found and the verifier ran; only
    * `Left` indicates that the verifier could not even be invoked.
    */
  def verify(
      id: KeyId,
      message: Array[Byte],
      signature: Signature,
      by: Principal
  ): F[Either[KmsError, Boolean]]

  /** Encrypt `plaintext` under the key identified by `id`. The key must be in `KeyState.Active`. The supplied
    * `context` is bound into the ciphertext as additional authenticated data (AAD); the same context must be
    * supplied to `decrypt` or the operation fails. Mirrors AWS KMS `Encrypt` with `EncryptionContext`.
    */
  def encrypt(
      id: KeyId,
      plaintext: Array[Byte],
      context: Map[String, String],
      by: Principal
  ): F[Either[KmsError, Ciphertext]]

  /** Decrypt `ciphertext` produced by [[encrypt]] under the same key and context. A context mismatch returns
    * `Left(KmsError(CryptographicFailure, ...))`. Decrypt is permitted on `Active` and `Deactivated` keys so
    * existing ciphertexts can still be read after rotation; `Compromised` and `Destroyed` are refused.
    */
  def decrypt(
      id: KeyId,
      ciphertext: Ciphertext,
      context: Map[String, String],
      by: Principal
  ): F[Either[KmsError, Array[Byte]]]

  /** Wrap a Data Encryption Key (`dek`) under the KEK identified by `id`. Same state-gate as `encrypt`: key
    * must be `Active`. The returned [[WrappedDek]] is opaque ciphertext suitable for storage alongside data
    * encrypted with the unwrapped DEK — the KMIP envelope-encryption pattern.
    */
  def wrap(id: KeyId, dek: Array[Byte], by: Principal): F[Either[KmsError, WrappedDek]]

  /** Unwrap a previously-wrapped DEK. Permitted on `Active` and `Deactivated` (so historical envelopes remain
    * readable across rotations); refused on `Compromised` and `Destroyed`.
    */
  def unwrap(id: KeyId, wrapped: WrappedDek, by: Principal): F[Either[KmsError, Array[Byte]]]

  /** Operator-issued compromise: marks the key as `Compromised` so it can no longer perform any cryptographic
    * operation. The `reason` is the mandatory human-readable justification (e.g. "discovered in S3 audit leak
    * 2026-05-08"). Compromise is one-way: from `{PreActive, Active, Deactivated}` → `Compromised` and is
    * idempotent on an already-`Compromised` key. `Destroyed` keys cannot be compromised.
    */
  def compromise(id: KeyId, reason: String, by: Principal): F[Either[KmsError, ManagedKey]]

object KeyService:

  /** An in-memory reference implementation. Not durable, not safe for production — useful for tests, smoke
    * examples, and as a shape reference for real backends under `aegis-persistence` and `aegis-crypto`.
    */
  def inMemory: IO[KeyService[IO]] =
    Ref.of[IO, Map[KeyId, ManagedKey]](Map.empty).map { ref =>
      new KeyService[IO]:

        def create(spec: KeySpec, by: Principal): IO[Either[KmsError, ManagedKey]] =
          for
            now <- IO.realTimeInstant
            id  = KeyId.generate()
            key = ManagedKey(id, spec, by, now, KeyState.PreActive)
            _ <- ref.update(_ + (id -> key))
          yield Right(key)

        def get(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
          ref.get.map(_.get(id).toRight(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}")))

        def locate(namePattern: String, by: Principal): IO[List[ManagedKey]] =
          ref.get.map(_.values.filter(_.spec.name.contains(namePattern)).toList)

        def activate(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
          transition(id, KeyState.Active)

        def revoke(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
          transition(id, KeyState.Deactivated)

        def destroy(id: KeyId, by: Principal): IO[Either[KmsError, Unit]] =
          ref.modify { m =>
            m.get(id) match
              case None    => (m, Left(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}")))
              case Some(_) => (m - id, Right(()))
          }

        def sign(
            id: KeyId,
            message: Array[Byte],
            alg: SigAlgorithm,
            by: Principal
        ): IO[Either[KmsError, Signature]] =
          ref.get.map { m =>
            m.get(id) match
              case None =>
                Left(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}"))
              case Some(k) if k.state != KeyState.Active =>
                Left(KmsError(ErrorCode.IllegalOperation, s"Key ${id.value} is ${k.state}, must be Active"))
              case Some(_) =>
                Right(Signature(deterministicMac(id, message), alg))
          }

        def verify(
            id: KeyId,
            message: Array[Byte],
            signature: Signature,
            by: Principal
        ): IO[Either[KmsError, Boolean]] =
          ref.get.map { m =>
            m.get(id) match
              case None =>
                Left(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}"))
              case Some(k) if k.state == KeyState.Compromised || k.state == KeyState.Destroyed =>
                Left(KmsError(ErrorCode.IllegalOperation, s"Key ${id.value} is ${k.state}"))
              case Some(_) =>
                val expected = deterministicMac(id, message)
                Right(java.util.Arrays.equals(expected, signature.bytes))
          }

        def encrypt(
            id: KeyId,
            plaintext: Array[Byte],
            context: Map[String, String],
            by: Principal
        ): IO[Either[KmsError, Ciphertext]] =
          ref.get.map { m =>
            m.get(id) match
              case None =>
                Left(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}"))
              case Some(k) if k.state != KeyState.Active =>
                Left(KmsError(ErrorCode.IllegalOperation, s"Key ${id.value} is ${k.state}, must be Active"))
              case Some(_) =>
                Right(Ciphertext(deterministicSeal(id, context, plaintext)))
          }

        def decrypt(
            id: KeyId,
            ciphertext: Ciphertext,
            context: Map[String, String],
            by: Principal
        ): IO[Either[KmsError, Array[Byte]]] =
          ref.get.map { m =>
            m.get(id) match
              case None =>
                Left(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}"))
              case Some(k) if k.state == KeyState.Compromised || k.state == KeyState.Destroyed =>
                Left(KmsError(ErrorCode.IllegalOperation, s"Key ${id.value} is ${k.state}"))
              case Some(_) =>
                deterministicOpen(id, context, ciphertext.bytes)
          }

        def wrap(id: KeyId, dek: Array[Byte], by: Principal): IO[Either[KmsError, WrappedDek]] =
          ref.get.map { m =>
            m.get(id) match
              case None =>
                Left(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}"))
              case Some(k) if k.state != KeyState.Active =>
                Left(KmsError(ErrorCode.IllegalOperation, s"Key ${id.value} is ${k.state}, must be Active"))
              case Some(_) =>
                Right(WrappedDek(deterministicSeal(id, Map.empty, dek)))
          }

        def unwrap(
            id: KeyId,
            wrapped: WrappedDek,
            by: Principal
        ): IO[Either[KmsError, Array[Byte]]] =
          ref.get.map { m =>
            m.get(id) match
              case None =>
                Left(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}"))
              case Some(k) if k.state == KeyState.Compromised || k.state == KeyState.Destroyed =>
                Left(KmsError(ErrorCode.IllegalOperation, s"Key ${id.value} is ${k.state}"))
              case Some(_) =>
                deterministicOpen(id, Map.empty, wrapped.bytes)
          }

        def compromise(
            id: KeyId,
            reason: String,
            by: Principal
        ): IO[Either[KmsError, ManagedKey]] =
          ref.modify { m =>
            m.get(id) match
              case None =>
                (m, Left(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}")))
              case Some(k) if k.state == KeyState.Destroyed =>
                (m, Left(KmsError(ErrorCode.IllegalOperation, s"Key ${id.value} is Destroyed")))
              case Some(k) =>
                val updated = k.copy(state = KeyState.Compromised)
                (m + (id -> updated), Right(updated))
          }

        private def transition(id: KeyId, to: KeyState): IO[Either[KmsError, ManagedKey]] =
          ref.modify { m =>
            m.get(id) match
              case None =>
                (m, Left(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}")))
              case Some(k) =>
                val updated = k.copy(state = to)
                (m + (id -> updated), Right(updated))
          }
    }

  /** Deterministic in-memory MAC keyed by the KeyId. Not real cryptography — the in-memory KeyService is a
    * dev/test reference, and "sign/verify round-trip" is the only contract its tests assert. Real signing
    * lives in `AwsKmsRootOfTrust` (and the upcoming GCP/Azure/Vault adapters).
    */
  private def deterministicMac(id: KeyId, message: Array[Byte]): Array[Byte] =
    val mac = javax.crypto.Mac.getInstance("HmacSHA256")
    mac.init(new javax.crypto.spec.SecretKeySpec(id.value.getBytes("UTF-8"), "HmacSHA256"))
    mac.doFinal(message)

  /** Deterministic in-memory "encryption" used by the dev `KeyService`. Layout: HMAC(id, ctx) || plaintext
    * XOR keystream(id, ctx). Round-trips correctly and detects context mismatch via the HMAC prefix; not real
    * confidentiality. Real encryption lives in `AwsKmsRootOfTrust`.
    */
  private def deterministicSeal(
      id: KeyId,
      context: Map[String, String],
      plaintext: Array[Byte]
  ): Array[Byte] =
    contextTag(id, context) ++ xorKeystream(id, context, plaintext)

  private def deterministicOpen(
      id: KeyId,
      context: Map[String, String],
      ciphertext: Array[Byte]
  ): Either[KmsError, Array[Byte]] =
    if ciphertext.length < 32 then
      Left(KmsError(ErrorCode.CryptographicFailure, "ciphertext too short"))
    else
      val (tag, masked) = ciphertext.splitAt(32)
      val expected      = contextTag(id, context)
      if !java.util.Arrays.equals(tag, expected) then
        Left(KmsError(ErrorCode.CryptographicFailure, "encryption-context mismatch"))
      else Right(xorKeystream(id, context, masked))

  private def contextTag(id: KeyId, context: Map[String, String]): Array[Byte] =
    val mac = javax.crypto.Mac.getInstance("HmacSHA256")
    mac.init(new javax.crypto.spec.SecretKeySpec(id.value.getBytes("UTF-8"), "HmacSHA256"))
    mac.doFinal(serializeContext(context))

  private def xorKeystream(
      id: KeyId,
      context: Map[String, String],
      data: Array[Byte]
  ): Array[Byte] =
    val mac     = javax.crypto.Mac.getInstance("HmacSHA256")
    val keyBase = id.value.getBytes("UTF-8") ++ serializeContext(context)
    mac.init(new javax.crypto.spec.SecretKeySpec(keyBase, "HmacSHA256"))
    val out = new Array[Byte](data.length)
    var i   = 0
    var ctr = 0
    while i < data.length do
      val block = mac.doFinal(java.nio.ByteBuffer.allocate(4).putInt(ctr).array())
      var j     = 0
      while j < block.length && i + j < data.length do
        out(i + j) = (data(i + j) ^ block(j)).toByte
        j += 1
      i += block.length
      ctr += 1
    out

  private def serializeContext(context: Map[String, String]): Array[Byte] =
    context.toSeq.sortBy(_._1).map((k, v) => s"$k=$v").mkString(" ").getBytes("UTF-8")
