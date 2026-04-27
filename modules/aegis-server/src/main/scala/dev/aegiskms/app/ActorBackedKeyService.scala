package dev.aegiskms.app

import cats.effect.IO
import dev.aegiskms.core.*
import org.apache.pekko.actor.typed.scaladsl.AskPattern.*
import org.apache.pekko.actor.typed.{ActorRef, Scheduler}
import org.apache.pekko.util.Timeout

/** Adapts a `KeyOpsActor` to the synchronous `KeyService[IO]` algebra used by the REST and KMIP wires.
  *
  * Each method `ask`s the actor and bridges the resulting `Future` into `IO`. All requests share the same
  * timeout; the timeout is per-operation, not per-batch.
  */
final class ActorBackedKeyService(
    actor: ActorRef[KeyOpsActor.Command]
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
