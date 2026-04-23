package dev.aegiskms.sdk

import dev.aegiskms.core.{KeyId, KeySpec, KmsError, ManagedKey, Principal}

/** Thin client over the Aegis-KMS REST surface.
  *
  * This is a placeholder during scaffolding; the real implementation will use
  * sttp + circe and will be generated from the Tapir-authored OpenAPI spec.
  */
trait AegisClient[F[_]]:
  def keys: AegisKeysApi[F]

trait AegisKeysApi[F[_]]:
  def create(spec: KeySpec): F[Either[KmsError, ManagedKey]]
  def get(id: KeyId): F[Either[KmsError, ManagedKey]]
  def locate(pattern: String): F[List[ManagedKey]]
  def revoke(id: KeyId): F[Either[KmsError, ManagedKey]]
  def destroy(id: KeyId): F[Either[KmsError, Unit]]

object AegisClient:
  def https[F[_]](baseUrl: String, token: String): AegisClient[F] =
    throw new NotImplementedError("AegisClient.https is not yet implemented (scaffold)")
