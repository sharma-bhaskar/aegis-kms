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

/** The primary algebra for interacting with Aegis-KMS from a library
  * consumer's point of view.
  *
  * Parameterized on an effect `F[_]` so callers can plug in `cats.effect.IO`,
  * `ZIO`, or any other compatible effect type. The server modules wrap this
  * trait with Pekko Typed actors; library users can use it directly without
  * ever touching an actor system.
  */
trait KeyService[F[_]]:
  def create(spec: KeySpec, by: Principal): F[Either[KmsError, ManagedKey]]
  def get(id: KeyId, by: Principal): F[Either[KmsError, ManagedKey]]
  def locate(namePattern: String, by: Principal): F[List[ManagedKey]]
  def activate(id: KeyId, by: Principal): F[Either[KmsError, ManagedKey]]
  def revoke(id: KeyId, by: Principal): F[Either[KmsError, ManagedKey]]
  def destroy(id: KeyId, by: Principal): F[Either[KmsError, Unit]]

object KeyService:

  /** An in-memory reference implementation. Not durable, not safe for
    * production — useful for tests, smoke examples, and as a shape reference
    * for real backends under `aegis-persistence` and `aegis-crypto`.
    */
  def inMemory: IO[KeyService[IO]] =
    Ref.of[IO, Map[KeyId, ManagedKey]](Map.empty).map { ref =>
      new KeyService[IO]:

        def create(spec: KeySpec, by: Principal): IO[Either[KmsError, ManagedKey]] =
          for
            now <- IO.realTimeInstant
            id   = KeyId.generate()
            key  = ManagedKey(id, spec, by, now, KeyState.PreActive)
            _   <- ref.update(_ + (id -> key))
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
