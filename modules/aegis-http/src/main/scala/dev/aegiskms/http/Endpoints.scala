package dev.aegiskms.http

import dev.aegiskms.http.JsonCodecs.*
import sttp.model.StatusCode
import sttp.tapir.*
import sttp.tapir.generic.auto.*
import sttp.tapir.json.circe.*

/** Pure Tapir endpoint definitions. No server logic, no Pekko types — these can be reused by the OpenAPI
  * generator, by sttp clients in `aegis-sdk-scala`, and by the test stub interpreter.
  *
  * Authentication is intentionally minimal: an `X-Aegis-User` header maps to a `Principal.Human`. PR #5
  * replaces this with OIDC + JWT and adds `Principal.Service` / `Principal.Agent` issuance.
  */
object Endpoints:

  /** Optional dev-mode user header. Replaced by JWT auth in PR #5. */
  private val principalHeader: EndpointInput[Option[String]] =
    header[Option[String]]("X-Aegis-User")
      .description("Dev-mode principal subject. Will be replaced by JWT bearer auth.")

  /** Common path + headers + error contract shared by every keys endpoint. */
  private val keysBase =
    endpoint
      .in("v1" / "keys")
      .in(principalHeader)
      .errorOut(statusCode and jsonBody[KmsErrorDto].description("Failure detail"))
      .tag("keys")

  /** `POST /v1/keys` — create a new managed key. Returns 201 with the new key in PreActive state. */
  val createKey
      : PublicEndpoint[(Option[String], CreateKeyRequest), (StatusCode, KmsErrorDto), ManagedKeyDto, Any] =
    keysBase.post
      .in(jsonBody[CreateKeyRequest])
      .out(statusCode(StatusCode.Created))
      .out(jsonBody[ManagedKeyDto])
      .summary("Create a managed key")
      .description("Creates a key in the PreActive state. Call /activate to make it usable for crypto ops.")

  /** `GET /v1/keys/{id}` — fetch a key by id. */
  val getKey: PublicEndpoint[(Option[String], String), (StatusCode, KmsErrorDto), ManagedKeyDto, Any] =
    keysBase.get
      .in(path[String]("id"))
      .out(jsonBody[ManagedKeyDto])
      .summary("Get a key by id")

  /** `POST /v1/keys/{id}/activate` — transition PreActive → Active. */
  val activateKey: PublicEndpoint[(Option[String], String), (StatusCode, KmsErrorDto), ManagedKeyDto, Any] =
    keysBase.post
      .in(path[String]("id") / "activate")
      .out(jsonBody[ManagedKeyDto])
      .summary("Activate a key")

  /** `DELETE /v1/keys/{id}` — destroy a key. Returns 204 on success. */
  val destroyKey: PublicEndpoint[(Option[String], String), (StatusCode, KmsErrorDto), Unit, Any] =
    keysBase.delete
      .in(path[String]("id"))
      .out(statusCode(StatusCode.NoContent))
      .summary("Destroy a key")

  /** All endpoint definitions. Used by the OpenAPI generator and tests. */
  val all: List[AnyEndpoint] = List(createKey, getKey, activateKey, destroyKey)
