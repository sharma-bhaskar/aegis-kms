package dev.aegiskms.audit

import cats.effect.{IO, IOLocal}

/** Per-request side-channel for context keys that originate at the transport layer (HTTP / KMIP / MCP) but
  * need to land in `AuditRecord.context` deep inside `AuditingKeyService`. Today carries `source.ip`;
  * tomorrow it can carry `user-agent`, `mcp.session-id`, `kmip.client-cn`, etc.
  *
  * Why this exists: `AuditingKeyService` cannot accept HTTP-shaped parameters without dragging Pekko / Tapir
  * into `aegis-audit` (which would break the two-tier rule). And we cannot thread the IP through every
  * `KeyService` method without changing the algebra for every embedder. The IOLocal-backed implementation
  * lets the HTTP layer call `set` once per request, then the auditing decorator reads `current` deep in its
  * instrument loop — both ends speak only `IO` and `Map[String, String]`.
  *
  * `IOLocal` is fiber-local: it propagates through `flatMap`/`map` within the same fiber. As long as the HTTP
  * layer calls `set` as the first IO step (before `unsafeToFuture`), every downstream `current` sees the
  * value. Tests that don't care can pass [[RequestContext.empty]].
  */
trait RequestContext:

  /** The current per-request context map. Returns `Map.empty` when no request scope is active (boot code,
    * background fibers, tests that didn't set anything).
    */
  def current: IO[Map[String, String]]

  /** Set the context for the rest of the current fiber. The HTTP layer calls this exactly once per request,
    * as the first IO step, before any user-facing work runs.
    */
  def set(ctx: Map[String, String]): IO[Unit]

object RequestContext:

  /** The no-op context — `current` always returns `Map.empty`, `set` is a no-op. Use this in
    * `AuditingKeyService` tests that don't exercise the source-ip path, and as the constructor default so
    * older callers compile unchanged.
    */
  val empty: RequestContext = new RequestContext:
    def current: IO[Map[String, String]]        = IO.pure(Map.empty)
    def set(ctx: Map[String, String]): IO[Unit] = IO.unit

  /** Wire-up against a cats-effect `IOLocal`. The IOLocal must be constructed at boot time via
    * `IOLocal(Map.empty[String, String])` and shared across `HttpRoutes` and `AuditingKeyService`.
    */
  def fromIOLocal(local: IOLocal[Map[String, String]]): RequestContext = new RequestContext:
    def current: IO[Map[String, String]]        = local.get
    def set(ctx: Map[String, String]): IO[Unit] = local.set(ctx)
