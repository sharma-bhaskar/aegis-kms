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
              case Some(_) =>
                val expected = deterministicMac(id, message)
                Right(java.util.Arrays.equals(expected, signature.bytes))
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
