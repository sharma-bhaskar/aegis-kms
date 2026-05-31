package dev.aegiskms.core

import java.time.Instant
import java.util.UUID

/** Domain events emitted by the key-lifecycle state machine.
  *
  * Events are append-only and form the source of truth for managed-key state. The actor that owns the live
  * state map (`KeyOpsActor` in `aegis-server`) replays these events on boot. Persistent backends — Postgres,
  * Kafka, S3 — store the same `KeyEvent` shape so the audit trail and the state machine never disagree.
  *
  * Every event is timestamped at the moment the actor decided the transition, not at the moment the event is
  * written to durable storage. The two are usually equal, but on a slow journal they can drift; the
  * decision-time stamp is what audit consumers care about.
  */
sealed trait KeyEvent:
  def at: Instant
  def keyId: KeyId
  def actorSubject: String
  def eventId: String

object KeyEvent:

  final case class Created(
      eventId: String,
      at: Instant,
      keyId: KeyId,
      spec: KeySpec,
      ownerSubject: String,
      actorSubject: String
  ) extends KeyEvent

  final case class Activated(
      eventId: String,
      at: Instant,
      keyId: KeyId,
      actorSubject: String
  ) extends KeyEvent

  final case class Deactivated(
      eventId: String,
      at: Instant,
      keyId: KeyId,
      actorSubject: String,
      reason: String
  ) extends KeyEvent

  final case class Destroyed(
      eventId: String,
      at: Instant,
      keyId: KeyId,
      actorSubject: String
  ) extends KeyEvent

  /** Operator-issued compromise: locks the key out of every cryptographic operation. The `reason` is the
    * mandatory human-readable justification — it ends up on the highest-severity audit row and in the
    * post-incident report.
    */
  final case class Compromised(
      eventId: String,
      at: Instant,
      keyId: KeyId,
      actorSubject: String,
      reason: String
  ) extends KeyEvent

  /** Rotation: the logical key's `currentVersion` advanced from `newVersion - 1` to `newVersion`. The
    * `policy` records why — `Manual` for an explicit `aegis keys rotate` call, `TimeBased` / `OpCountBased`
    * (rendered string) for the auto-scheduler roadmapped for a later release.
    */
  final case class Rotated(
      eventId: String,
      at: Instant,
      keyId: KeyId,
      actorSubject: String,
      newVersion: Int,
      policy: String
  ) extends KeyEvent

  /** Generate a fresh event id. UUIDv4 is fine — events are not ordered by id, only by `at`. */
  def freshId(): String = UUID.randomUUID().toString
