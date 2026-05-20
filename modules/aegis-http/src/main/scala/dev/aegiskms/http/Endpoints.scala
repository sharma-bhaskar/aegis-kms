package dev.aegiskms.http

import dev.aegiskms.http.JsonCodecs.*
import sttp.model.StatusCode
import sttp.tapir.*
import sttp.tapir.generic.auto.*
import sttp.tapir.json.circe.*

import java.time.Instant

/** Pure Tapir endpoint definitions. No server logic, no Pekko types — these can be reused by the OpenAPI
  * generator, by sttp clients in `aegis-sdk-scala`, and by the test stub interpreter.
  *
  * Each endpoint reads two optional auth headers:
  *   - `Authorization: Bearer <jwt>` — production path (consumed by `PrincipalResolver.jwt`).
  *   - `X-Aegis-User` — dev-mode path (consumed by `PrincipalResolver.dev`).
  *
  * The endpoint surface accepts both regardless of which resolver is wired in; the resolver picked at boot
  * time decides which (if either) is honoured. This keeps the OpenAPI shape stable across deployment modes.
  */
object Endpoints:

  /** Bearer-token header. Honoured when the server is configured with `aegis.auth.kind=hmac` (or any other
    * future JWT-based mode); silently ignored under `aegis.auth.kind=dev`.
    */
  private val authHeader: EndpointInput[Option[String]] =
    header[Option[String]]("Authorization")
      .description("Bearer JWT (`Authorization: Bearer <jwt>`). Honoured under `aegis.auth.kind=hmac`.")

  /** Dev-mode user header. Honoured under `aegis.auth.kind=dev` only; production deployments must rely on
    * `Authorization` instead.
    */
  private val devUserHeader: EndpointInput[Option[String]] =
    header[Option[String]]("X-Aegis-User")
      .description("Dev-mode principal subject. Honoured ONLY under `aegis.auth.kind=dev`.")

  /** Common path + headers + error contract shared by every keys endpoint. */
  private val keysBase =
    endpoint
      .in("v1" / "keys")
      .in(authHeader)
      .in(devUserHeader)
      .errorOut(statusCode and jsonBody[KmsErrorDto].description("Failure detail"))
      .tag("keys")

  /** `POST /v1/keys` — create a new managed key. Returns 201 with the new key in PreActive state. */
  val createKey: PublicEndpoint[
    (Option[String], Option[String], CreateKeyRequest),
    (StatusCode, KmsErrorDto),
    ManagedKeyDto,
    Any
  ] =
    keysBase.post
      .in(jsonBody[CreateKeyRequest])
      .out(statusCode(StatusCode.Created))
      .out(jsonBody[ManagedKeyDto])
      .summary("Create a managed key")
      .description("Creates a key in the PreActive state. Call /activate to make it usable for crypto ops.")

  /** `GET /v1/keys/{id}` — fetch a key by id. */
  val getKey: PublicEndpoint[
    (Option[String], Option[String], String),
    (StatusCode, KmsErrorDto),
    ManagedKeyDto,
    Any
  ] =
    keysBase.get
      .in(path[String]("id"))
      .out(jsonBody[ManagedKeyDto])
      .summary("Get a key by id")

  /** `POST /v1/keys/{id}/activate` — transition PreActive → Active. */
  val activateKey: PublicEndpoint[
    (Option[String], Option[String], String),
    (StatusCode, KmsErrorDto),
    ManagedKeyDto,
    Any
  ] =
    keysBase.post
      .in(path[String]("id") / "activate")
      .out(jsonBody[ManagedKeyDto])
      .summary("Activate a key")

  /** `DELETE /v1/keys/{id}` — destroy a key. Returns 204 on success. */
  val destroyKey: PublicEndpoint[
    (Option[String], Option[String], String),
    (StatusCode, KmsErrorDto),
    Unit,
    Any
  ] =
    keysBase.delete
      .in(path[String]("id"))
      .out(statusCode(StatusCode.NoContent))
      .summary("Destroy a key")

  /** `POST /v1/keys/{id}/sign` — sign a base64-encoded message with the named key. Key must be `Active`. */
  val signKey: PublicEndpoint[
    (Option[String], Option[String], String, SignRequest),
    (StatusCode, KmsErrorDto),
    SignResponse,
    Any
  ] =
    keysBase.post
      .in(path[String]("id") / "sign")
      .in(jsonBody[SignRequest])
      .out(jsonBody[SignResponse])
      .summary("Sign a message")
      .description("Signs the supplied (base64) message with the key. Key must be in Active state.")

  /** `POST /v1/keys/{id}/verify` — verify a signature over a message. */
  val verifyKey: PublicEndpoint[
    (Option[String], Option[String], String, VerifyRequest),
    (StatusCode, KmsErrorDto),
    VerifyResponse,
    Any
  ] =
    keysBase.post
      .in(path[String]("id") / "verify")
      .in(jsonBody[VerifyRequest])
      .out(jsonBody[VerifyResponse])
      .summary("Verify a signature")
      .description("Returns `valid: true` when the signature checks out, `valid: false` otherwise.")

  /** `POST /v1/keys/{id}/encrypt` — encrypt a base64-encoded plaintext. Key must be `Active`. The encryption
    * context is bound as AAD; the same context must be supplied at decrypt time.
    */
  val encryptKey: PublicEndpoint[
    (Option[String], Option[String], String, EncryptRequest),
    (StatusCode, KmsErrorDto),
    EncryptResponse,
    Any
  ] =
    keysBase.post
      .in(path[String]("id") / "encrypt")
      .in(jsonBody[EncryptRequest])
      .out(jsonBody[EncryptResponse])
      .summary("Encrypt a plaintext")
      .description(
        "Encrypts the supplied (base64) plaintext with the key. Encryption context is bound as AAD."
      )

  /** `POST /v1/keys/{id}/decrypt` — decrypt a ciphertext produced by /encrypt. Same context required. */
  val decryptKey: PublicEndpoint[
    (Option[String], Option[String], String, DecryptRequest),
    (StatusCode, KmsErrorDto),
    DecryptResponse,
    Any
  ] =
    keysBase.post
      .in(path[String]("id") / "decrypt")
      .in(jsonBody[DecryptRequest])
      .out(jsonBody[DecryptResponse])
      .summary("Decrypt a ciphertext")
      .description("Decrypts a ciphertext produced by `/encrypt`. The context must match or the call fails.")

  /** `POST /v1/keys/{id}/wrap` — wrap a data-encryption key under the named KEK. Key must be `Active`. */
  val wrapKey: PublicEndpoint[
    (Option[String], Option[String], String, WrapRequest),
    (StatusCode, KmsErrorDto),
    WrapResponse,
    Any
  ] =
    keysBase.post
      .in(path[String]("id") / "wrap")
      .in(jsonBody[WrapRequest])
      .out(jsonBody[WrapResponse])
      .summary("Wrap a DEK")
      .description(
        "KMIP-style envelope: the supplied DEK is wrapped under the KEK and returned as opaque bytes."
      )

  /** `POST /v1/keys/{id}/unwrap` — unwrap a previously wrapped DEK. Permitted on Active + Deactivated. */
  val unwrapKey: PublicEndpoint[
    (Option[String], Option[String], String, UnwrapRequest),
    (StatusCode, KmsErrorDto),
    UnwrapResponse,
    Any
  ] =
    keysBase.post
      .in(path[String]("id") / "unwrap")
      .in(jsonBody[UnwrapRequest])
      .out(jsonBody[UnwrapResponse])
      .summary("Unwrap a DEK")
      .description("Recovers the original DEK bytes. Permitted on Active and Deactivated keys.")

  /** `POST /v1/keys/{id}/compromise` — operator-issued lockdown. The key transitions to `Compromised` and
    * refuses every cryptographic operation thereafter.
    */
  val compromiseKey: PublicEndpoint[
    (Option[String], Option[String], String, CompromiseRequest),
    (StatusCode, KmsErrorDto),
    ManagedKeyDto,
    Any
  ] =
    keysBase.post
      .in(path[String]("id") / "compromise")
      .in(jsonBody[CompromiseRequest])
      .out(jsonBody[ManagedKeyDto])
      .summary("Compromise a key (operator override)")
      .description(
        "Marks the key as Compromised. From this state every cryptographic operation refuses with " +
          "IllegalOperation. The supplied `reason` is recorded on the audit row at severity=Critical."
      )

  /** `POST /v1/keys/{id}/rotate` — bump the key's `currentVersion`. Legal source state is `Active` only. */
  val rotateKey: PublicEndpoint[
    (Option[String], Option[String], String, RotateRequest),
    (StatusCode, KmsErrorDto),
    ManagedKeyDto,
    Any
  ] =
    keysBase.post
      .in(path[String]("id") / "rotate")
      .in(jsonBody[RotateRequest])
      .out(jsonBody[ManagedKeyDto])
      .summary("Rotate a key (bump current version)")
      .description(
        "Increments the key's currentVersion. Legal source state is Active. Existing signatures and " +
          "ciphertexts produced before the rotation continue to verify and decrypt. The supplied policy " +
          "is recorded on the audit row."
      )

  // ── Agent tokens ────────────────────────────────────────────────────────────

  /** Common path + headers + error contract for the agent-management surface. The base differs from
    * `keysBase` (path = `v1/agents`, tag = `"agents"`) so OpenAPI groups them cleanly in Swagger UI.
    */
  private val agentsBase =
    endpoint
      .in("v1" / "agents")
      .in(authHeader)
      .in(devUserHeader)
      .errorOut(statusCode and jsonBody[KmsErrorDto].description("Failure detail"))
      .tag("agents")

  /** `POST /v1/agents/issue` — issue a short-lived JWT for an AI agent acting under a human's authority.
    * Caller must be a `Principal.Human` (Service and Agent callers are refused with 403).
    *
    * Request body: `{ label, scopes, ttlSeconds, parent? }` Response: `{ agentId, jwt, jti, expiresAt }`
    */
  val issueAgent: PublicEndpoint[
    (Option[String], Option[String], IssueAgentRequestDto),
    (StatusCode, KmsErrorDto),
    IssueAgentResponseDto,
    Any
  ] =
    agentsBase.post
      .in("issue")
      .in(jsonBody[IssueAgentRequestDto])
      .out(statusCode(StatusCode.Created))
      .out(jsonBody[IssueAgentResponseDto])
      .summary("Issue an agent JWT")
      .description(
        "Mints a short-lived JWT carrying `kind=agent`, the caller's subject as parent, and the " +
          "requested scopes (KMIP Operation names). Only humans can issue agents — service and agent " +
          "principals are refused with 403. Maximum TTL is 24 hours (the agent credential lifetime is " +
          "deliberately short because the only revocation mechanism is the JTI blacklist that lands in #24)."
      )

  // ── Audit read (#20) ──────────────────────────────────────────────────────

  /** Common base for the audit-read surface — `/v1/audit`, same auth headers, same error contract, distinct
    * OpenAPI tag so Swagger groups the endpoint with future audit-read additions.
    */
  private val auditBase =
    endpoint
      .in("v1" / "audit")
      .in(authHeader)
      .in(devUserHeader)
      .errorOut(statusCode and jsonBody[KmsErrorDto].description("Failure detail"))
      .tag("audit")

  /** `GET /v1/audit` — paginated read of `aegis_audit_events`. Filters compose with AND. Only
    * `Principal.Human` callers are permitted (Service and Agent return 403); this is a deliberate v0.2.0
    * simplification of the future "audit:read permission via policy engine" model.
    *
    * Query parameters:
    *   - `since` — ISO-8601 instant; rows with `occurred_at >= since` (inclusive).
    *   - `until` — ISO-8601 instant; rows with `occurred_at < until` (exclusive).
    *   - `actor` — exact match on `actor_subject`.
    *   - `key` — exact match on `resource` (e.g. `"key:abc-123"` or `"agent:agent-7a3"`).
    *   - `op` — KMIP Operation enum name (`Sign`, `Get`, …).
    *   - `limit` — page size, default 100, max 1000.
    *   - `offset` — starting row offset, default 0.
    */
  val queryAudit: PublicEndpoint[
    (
        Option[String],
        Option[String],
        Option[Instant],
        Option[Instant],
        Option[String],
        Option[String],
        Option[String],
        Option[Int],
        Option[Int]
    ),
    (StatusCode, KmsErrorDto),
    AuditQueryResponseDto,
    Any
  ] =
    auditBase.get
      .in(query[Option[Instant]]("since").description("ISO-8601 lower bound (inclusive) on occurred_at"))
      .in(query[Option[Instant]]("until").description("ISO-8601 upper bound (exclusive) on occurred_at"))
      .in(query[Option[String]]("actor").description(
        "Exact match on actor_subject (e.g. 'alice@org', 'agent-7a3', 'aegis-system')"
      ))
      .in(query[Option[String]]("key").description("Exact match on resource (e.g. 'key:abc-123')"))
      .in(query[Option[String]]("op").description("KMIP Operation enum name (Sign / Get / Encrypt / …)"))
      .in(query[Option[Int]]("limit").description("Page size; defaults to 100, capped at 1000"))
      .in(query[Option[Int]]("offset").description("Starting row offset for paging; defaults to 0"))
      .out(jsonBody[AuditQueryResponseDto])
      .summary("Query the audit log")
      .description(
        "Paginated read of `aegis_audit_events`. Filters compose with AND. Caller must be a " +
          "human principal — service and agent principals are refused with 403."
      )

  /** All endpoint definitions. Used by the OpenAPI generator and tests. */
  val all: List[AnyEndpoint] =
    List(
      createKey,
      getKey,
      activateKey,
      destroyKey,
      signKey,
      verifyKey,
      encryptKey,
      decryptKey,
      wrapKey,
      unwrapKey,
      compromiseKey,
      rotateKey,
      issueAgent,
      queryAudit
    )
