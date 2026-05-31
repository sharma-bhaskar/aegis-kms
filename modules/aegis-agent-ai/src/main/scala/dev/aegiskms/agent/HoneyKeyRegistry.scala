package dev.aegiskms.agent

import dev.aegiskms.core.KeyId

/** Registry of "honey" (canary) `KeyId`s — keys the operator has marked as bait. Any **agent** operation
  * against a honey key fires a `HoneyKey` recommendation at `Severity.High`, which the
  * `AutoResponder.DefaultRules` translate into a `Revoke` action — killing both the offending key and the
  * agent's JWT via the wired `RevocationList`.
  *
  * Why a separate SPI rather than a `boolean` flag on `ManagedKey`: marking a key honey is an **operational**
  * decision that often happens AFTER key creation (e.g. "we noticed Claude is fishing for treasury keys —
  * let's plant a canary named `treasury-master-canary`"). A schema flag would require key rotation to mark an
  * existing key, which is hostile to the operator workflow. The registry pattern also keeps the library tier
  * (`aegis-core`, `aegis-persistence`) unchanged so embedders don't see a binary-compat break.
  *
  * Closes ROADMAP §v0.2.0 2.0.l (closes #26).
  */
trait HoneyKeyRegistry:

  /** True iff `keyId` is registered as a honey key. */
  def isHoney(keyId: KeyId): Boolean

  /** Snapshot of all currently-registered honey keys. Used by `Server.boot` to log how many honey keys are
    * active and by future operator UIs that list the canaries.
    */
  def snapshot: Set[KeyId]

object HoneyKeyRegistry:

  /** The default — no honey keys are registered. Used when `aegis.security.honey-keys` is empty (the
    * production-safe default; operators opt in explicitly) and as the constructor default on
    * `BaselineDetector` so existing call sites compile unchanged.
    */
  val empty: HoneyKeyRegistry = new HoneyKeyRegistry:
    def isHoney(keyId: KeyId): Boolean = false
    def snapshot: Set[KeyId]           = Set.empty

  /** Construct a registry from a fixed set of `KeyId`s. The set is captured by reference at boot; dynamic
    * add/remove is deferred to a v0.3.0 HTTP API.
    */
  def fromSet(ids: Set[KeyId]): HoneyKeyRegistry = new HoneyKeyRegistry:
    def isHoney(keyId: KeyId): Boolean = ids.contains(keyId)
    def snapshot: Set[KeyId]           = ids
