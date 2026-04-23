package dev.aegiskms.core

import java.util.UUID

/** Stable identifier for a managed key. Opaque so callers cannot construct arbitrary IDs by coercing a
  * `String`.
  */
opaque type KeyId = String

object KeyId:
  /** Parse an incoming string (e.g. from the wire) into a KeyId. */
  def fromString(value: String): Either[String, KeyId] =
    if value.isEmpty || value.length > 256 then Left(s"Invalid KeyId length: ${value.length}")
    else Right(value)

  /** Generate a fresh KeyId. */
  def generate(): KeyId = UUID.randomUUID().toString

  extension (id: KeyId) def value: String = id
