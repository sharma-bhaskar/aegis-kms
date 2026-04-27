package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import dev.aegiskms.core.*
import dev.aegiskms.persistence.EventJournal
import org.apache.pekko.actor.typed.scaladsl.{ActorContext, Behaviors}
import org.apache.pekko.actor.typed.{ActorRef, Behavior}

import java.time.Clock
import scala.util.{Failure, Success, Try}

/** The single Pekko Typed actor that owns the live `Map[KeyId, ManagedKey]` and is the only thing in the
  * system that mutates key-lifecycle state.
  *
  * Why one actor:
  *   - State changes happen on a single thread, so the lifecycle state machine is trivially consistent
  *     without any locking.
  *   - All effects (journal append, audit write, anomaly stream emit) happen in a deterministic order.
  *   - It's the obvious place to plug Pekko Persistence later if we want event-sourced recovery beyond what
  *     the journal SPI gives us.
  *
  * State is recovered on `boot`: every event in the `EventJournal` is replayed in order, so the in-memory map
  * is rebuilt deterministically. This means the journal is the source of truth — losing the actor's process
  * is recoverable as long as the journal is durable.
  *
  * Concurrency: callers send `Command`s with a reply-to `ActorRef`. The actor processes one command at a
  * time. Use `ActorBackedKeyService` to adapt this to the `KeyService[IO]` algebra.
  */
object KeyOpsActor:

  // ── Public command protocol ──────────────────────────────────────────────────

  sealed trait Command

  final case class Create(
      spec: KeySpec,
      by: Principal,
      replyTo: ActorRef[Either[KmsError, ManagedKey]]
  ) extends Command

  final case class Get(
      id: KeyId,
      by: Principal,
      replyTo: ActorRef[Either[KmsError, ManagedKey]]
  ) extends Command

  final case class Locate(
      pattern: String,
      by: Principal,
      replyTo: ActorRef[List[ManagedKey]]
  ) extends Command

  final case class Activate(
      id: KeyId,
      by: Principal,
      replyTo: ActorRef[Either[KmsError, ManagedKey]]
  ) extends Command

  final case class Revoke(
      id: KeyId,
      by: Principal,
      replyTo: ActorRef[Either[KmsError, ManagedKey]]
  ) extends Command

  final case class Destroy(
      id: KeyId,
      by: Principal,
      replyTo: ActorRef[Either[KmsError, Unit]]
  ) extends Command

  // ── Boot ─────────────────────────────────────────────────────────────────────

  /** Build a behavior that has already replayed `replayed` into its state map. The supplied `clock` and
    * `idGen` are seams for deterministic tests.
    */
  def behavior(
      journal: EventJournal[IO],
      replayed: List[KeyEvent],
      clock: Clock = Clock.systemUTC(),
      idGen: () => KeyId = () => KeyId.generate()
  )(using runtime: IORuntime): Behavior[Command] =
    val initial = replayed.foldLeft(Map.empty[KeyId, ManagedKey])(applyEvent)
    running(journal, initial, clock, idGen)

  /** Convenience: build a `Behavior` from a journal by first replaying it. Blocks the caller's thread until
    * the replay completes — only meaningful at boot time.
    */
  def fromJournal(
      journal: EventJournal[IO],
      clock: Clock = Clock.systemUTC(),
      idGen: () => KeyId = () => KeyId.generate()
  )(using runtime: IORuntime): Behavior[Command] =
    behavior(journal, journal.replay().unsafeRunSync(), clock, idGen)

  // ── Internal behavior ────────────────────────────────────────────────────────

  private def running(
      journal: EventJournal[IO],
      state: Map[KeyId, ManagedKey],
      clock: Clock,
      idGen: () => KeyId
  )(using runtime: IORuntime): Behavior[Command] =
    Behaviors.receive { (ctx, msg) =>
      val now = clock.instant()

      msg match

        case Create(spec, by, replyTo) =>
          val id  = idGen()
          val key = ManagedKey(id, spec, by, now, KeyState.PreActive)
          val event = KeyEvent.Created(
            eventId = KeyEvent.freshId(),
            at = now,
            keyId = id,
            spec = spec,
            ownerSubject = by.subject,
            actorSubject = by.subject
          )
          appendOr(journal, event, ctx) {
            replyTo ! Right(key)
            running(journal, state + (id -> key), clock, idGen)
          } { err =>
            replyTo ! Left(KmsError(ErrorCode.GeneralFailure, s"journal append failed: ${err.getMessage}"))
            Behaviors.same
          }

        case Get(id, _, replyTo) =>
          replyTo ! state.get(id).toRight(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}"))
          Behaviors.same

        case Locate(pattern, _, replyTo) =>
          replyTo ! state.values.filter(_.spec.name.contains(pattern)).toList
          Behaviors.same

        case Activate(id, by, replyTo) =>
          state.get(id) match
            case None =>
              replyTo ! Left(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}"))
              Behaviors.same
            case Some(k) =>
              val event   = KeyEvent.Activated(KeyEvent.freshId(), now, id, by.subject)
              val updated = k.copy(state = KeyState.Active)
              appendOr(journal, event, ctx) {
                replyTo ! Right(updated)
                running(journal, state + (id -> updated), clock, idGen)
              } { err =>
                replyTo ! Left(KmsError(
                  ErrorCode.GeneralFailure,
                  s"journal append failed: ${err.getMessage}"
                ))
                Behaviors.same
              }

        case Revoke(id, by, replyTo) =>
          state.get(id) match
            case None =>
              replyTo ! Left(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}"))
              Behaviors.same
            case Some(k) =>
              val event   = KeyEvent.Deactivated(KeyEvent.freshId(), now, id, by.subject, "operator-revoke")
              val updated = k.copy(state = KeyState.Deactivated)
              appendOr(journal, event, ctx) {
                replyTo ! Right(updated)
                running(journal, state + (id -> updated), clock, idGen)
              } { err =>
                replyTo ! Left(KmsError(
                  ErrorCode.GeneralFailure,
                  s"journal append failed: ${err.getMessage}"
                ))
                Behaviors.same
              }

        case Destroy(id, by, replyTo) =>
          state.get(id) match
            case None =>
              replyTo ! Left(KmsError(ErrorCode.ItemNotFound, s"No key with id ${id.value}"))
              Behaviors.same
            case Some(_) =>
              val event = KeyEvent.Destroyed(KeyEvent.freshId(), now, id, by.subject)
              appendOr(journal, event, ctx) {
                replyTo ! Right(())
                running(journal, state - id, clock, idGen)
              } { err =>
                replyTo ! Left(KmsError(
                  ErrorCode.GeneralFailure,
                  s"journal append failed: ${err.getMessage}"
                ))
                Behaviors.same
              }
    }

  /** Synchronously append `event` to the journal. On success: run `onOk`. On failure: log and run `onErr`.
    *
    * `unsafeRunSync` is acceptable here because the actor's mailbox is the back-pressure boundary — one
    * mailbox slot blocking on a slow journal is fine; we will never have multiple appends in flight.
    */
  private def appendOr(
      journal: EventJournal[IO],
      event: KeyEvent,
      ctx: ActorContext[Command]
  )(onOk: => Behavior[Command])(onErr: Throwable => Behavior[Command])(using
      runtime: IORuntime
  ): Behavior[Command] =
    Try(journal.append(event).unsafeRunSync()) match
      case Success(_) => onOk
      case Failure(t) =>
        ctx.log.error(s"journal append failed for event=${event.eventId}", t)
        onErr(t)

  // ── Event-replay helper (pure function) ──────────────────────────────────────

  private def applyEvent(state: Map[KeyId, ManagedKey], event: KeyEvent): Map[KeyId, ManagedKey] =
    event match
      case KeyEvent.Created(_, at, id, spec, ownerSubject, _) =>
        state + (id -> ManagedKey(
          id = id,
          spec = spec,
          owner = Principal.Human(ownerSubject, Set.empty),
          createdAt = at,
          state = KeyState.PreActive
        ))
      case KeyEvent.Activated(_, _, id, _) =>
        state.get(id).fold(state)(k => state + (id -> k.copy(state = KeyState.Active)))
      case KeyEvent.Deactivated(_, _, id, _, _) =>
        state.get(id).fold(state)(k => state + (id -> k.copy(state = KeyState.Deactivated)))
      case KeyEvent.Destroyed(_, _, id, _) =>
        state - id
