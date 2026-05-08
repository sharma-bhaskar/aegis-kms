package dev.aegiskms.app

import cats.effect.IO
import dev.aegiskms.core.*
import dev.aegiskms.crypto.RootOfTrust
import org.apache.pekko.actor.typed.scaladsl.AskPattern.*
import org.apache.pekko.actor.typed.{ActorRef, Scheduler}
import org.apache.pekko.util.Timeout

/** Adapts a `KeyOpsActor` to the synchronous `KeyService[IO]` algebra used by the REST and KMIP wires.
  *
  * Each state-changing or lookup method `ask`s the actor and bridges the resulting `Future` into `IO`. All
  * requests share the same timeout; the timeout is per-operation, not per-batch.
  *
  * `sign` / `verify` are different: they don't mutate actor state, so they don't go through the actor's
  * mailbox. Instead we ask the actor only to confirm the key exists and is `Active`, then delegate to the
  * injected `RootOfTrust[IO]`. This means parallel signing requests don't queue behind each other on the
  * actor — sign throughput scales with the underlying KMS, not with the actor's single-threaded receive.
  *
  * The default `RootOfTrust` is the in-memory deterministic-MAC implementation, which is what dev mode and
  * the in-memory boot path use. Production wiring passes `AwsKmsRootOfTrust.fromConfig(...)`.
  */
final class ActorBackedKeyService(
    actor: ActorRef[KeyOpsActor.Command],
    rootOfTrust: RootOfTrust[IO] = RootOfTrust.inMemory
)(using timeout: Timeout, scheduler: Scheduler)
    extends KeyService[IO]:

  def create(spec: KeySpec, by: Principal): IO[Either[KmsError, ManagedKey]] =
    IO.fromFuture(IO(actor.ask[Either[KmsError, ManagedKey]](ref => KeyOpsActor.Create(spec, by, ref))))

  def get(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    IO.fromFuture(IO(actor.ask[Either[KmsError, ManagedKey]](ref => KeyOpsActor.Get(id, by, ref))))

  def locate(namePattern: String, by: Principal): IO[List[ManagedKey]] =
    IO.fromFuture(IO(actor.ask[List[ManagedKey]](ref => KeyOpsActor.Locate(namePattern, by, ref))))

  def activate(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    IO.fromFuture(IO(actor.ask[Either[KmsError, ManagedKey]](ref => KeyOpsActor.Activate(id, by, ref))))

  def revoke(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    IO.fromFuture(IO(actor.ask[Either[KmsError, ManagedKey]](ref => KeyOpsActor.Revoke(id, by, ref))))

  def destroy(id: KeyId, by: Principal): IO[Either[KmsError, Unit]] =
    IO.fromFuture(IO(actor.ask[Either[KmsError, Unit]](ref => KeyOpsActor.Destroy(id, by, ref))))

  def sign(
      id: KeyId,
      message: Array[Byte],
      alg: SigAlgorithm,
      by: Principal
  ): IO[Either[KmsError, Signature]] =
    get(id, by).flatMap {
      case Left(err) => IO.pure(Left(err))
      case Right(k) if k.state != KeyState.Active =>
        IO.pure(Left(KmsError(ErrorCode.IllegalOperation, s"Key ${id.value} is ${k.state}, must be Active")))
      case Right(_) => rootOfTrust.sign(id, message, alg)
    }

  def verify(
      id: KeyId,
      message: Array[Byte],
      signature: Signature,
      by: Principal
  ): IO[Either[KmsError, Boolean]] =
    get(id, by).flatMap {
      case Left(err) => IO.pure(Left(err))
      case Right(_)  => rootOfTrust.verify(id, message, signature)
    }

  def encrypt(
      id: KeyId,
      plaintext: Array[Byte],
      context: Map[String, String],
      by: Principal
  ): IO[Either[KmsError, Ciphertext]] =
    get(id, by).flatMap {
      case Left(err) => IO.pure(Left(err))
      case Right(k) if k.state != KeyState.Active =>
        IO.pure(Left(KmsError(ErrorCode.IllegalOperation, s"Key ${id.value} is ${k.state}, must be Active")))
      case Right(_) => rootOfTrust.encrypt(id, plaintext, context)
    }

  def decrypt(
      id: KeyId,
      ciphertext: Ciphertext,
      context: Map[String, String],
      by: Principal
  ): IO[Either[KmsError, Array[Byte]]] =
    get(id, by).flatMap {
      case Left(err) => IO.pure(Left(err))
      case Right(k) if k.state == KeyState.Compromised || k.state == KeyState.Destroyed =>
        IO.pure(Left(KmsError(ErrorCode.IllegalOperation, s"Key ${id.value} is ${k.state}")))
      case Right(_) => rootOfTrust.decrypt(id, ciphertext, context)
    }

  def wrap(id: KeyId, dek: Array[Byte], by: Principal): IO[Either[KmsError, WrappedDek]] =
    get(id, by).flatMap {
      case Left(err) => IO.pure(Left(err))
      case Right(k) if k.state != KeyState.Active =>
        IO.pure(Left(KmsError(ErrorCode.IllegalOperation, s"Key ${id.value} is ${k.state}, must be Active")))
      case Right(_) => rootOfTrust.wrap(id, dek)
    }

  def unwrap(
      id: KeyId,
      wrapped: WrappedDek,
      by: Principal
  ): IO[Either[KmsError, Array[Byte]]] =
    get(id, by).flatMap {
      case Left(err) => IO.pure(Left(err))
      case Right(k) if k.state == KeyState.Compromised || k.state == KeyState.Destroyed =>
        IO.pure(Left(KmsError(ErrorCode.IllegalOperation, s"Key ${id.value} is ${k.state}")))
      case Right(_) => rootOfTrust.unwrapDek(id, wrapped)
    }

  /** State-mutating: routes through the actor mailbox so the journal append + state transition are serialized
    * with the rest of the lifecycle.
    */
  def compromise(id: KeyId, reason: String, by: Principal): IO[Either[KmsError, ManagedKey]] =
    IO.fromFuture(IO(actor.ask[Either[KmsError, ManagedKey]](ref =>
      KeyOpsActor.Compromise(id, reason, by, ref)
    )))

  /** State-mutating: routes through the actor for the same reason as `compromise`. v0.1.1 doesn't yet drive
    * AWS-side `EnableKeyRotation` from this path — that wiring lands when per-Aegis-key-to-CMK mapping
    * arrives in v0.2.0 (PR L2).
    */
  def rotate(id: KeyId, policy: RotationPolicy, by: Principal): IO[Either[KmsError, ManagedKey]] =
    IO.fromFuture(IO(actor.ask[Either[KmsError, ManagedKey]](ref =>
      KeyOpsActor.Rotate(id, policy, by, ref)
    )))
