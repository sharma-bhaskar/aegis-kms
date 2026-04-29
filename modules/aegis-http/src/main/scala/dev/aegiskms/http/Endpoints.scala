package dev.aegiskms.http

import dev.aegiskms.http.JsonCodecs.*
import sttp.model.StatusCode
import sttp.tapir.*
import sttp.tapir.generic.auto.*
import sttp.tapir.json.circe.*

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

  /** All endpoint definitions. Used by the OpenAPI generator and tests. */
  val all: List[AnyEndpoint] = List(createKey, getKey, activateKey, destroyKey)
