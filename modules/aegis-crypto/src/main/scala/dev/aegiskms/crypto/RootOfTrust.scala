package dev.aegiskms.crypto

import dev.aegiskms.core.{KeyId, KeySpec, KmsError}

/** SPI for a root-of-trust provider. Implementations live in `dev.aegiskms.crypto.aws`,
  * `dev.aegiskms.crypto.gcp`, `dev.aegiskms.crypto.pkcs11`, etc., and are selected at server startup based on
  * configuration.
  *
  * Contract: no implementation holds raw key material outside its secure boundary. Operations either return
  * wrapped key material or perform the cryptographic op inline and return just the result.
  */
trait RootOfTrust[F[_]]:

  def generateDataKey(spec: KeySpec): F[Either[KmsError, WrappedKey]]

  def unwrap(wrapped: WrappedKey): F[Either[KmsError, RawKey]]

  def rotate(id: KeyId): F[Either[KmsError, KeyId]]

final case class WrappedKey(bytes: Array[Byte], rotationId: String)
final case class RawKey(bytes: Array[Byte])
