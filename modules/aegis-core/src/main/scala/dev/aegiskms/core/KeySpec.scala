package dev.aegiskms.core

/** KMIP object types we support. Values mirror the OASIS KMIP 2.x spec. */
enum KeyObjectType:
  case SymmetricKey, PrivateKey, PublicKey, Certificate

/** Cryptographic algorithm. */
enum Algorithm:
  case AES, RSA, EC, HMAC_SHA256

/** KMIP operation names. Used for principal allowlists and audit records. */
enum Operation:
  case Create, Get, Locate, Activate, Revoke, Destroy, Query, GetAttributes, AddAttribute

/** Specification for a new key the server must generate. */
final case class KeySpec(
    name: String,
    algorithm: Algorithm,
    sizeBits: Int,
    objectType: KeyObjectType
):
  require(name.nonEmpty, "KeySpec.name must be non-empty")
  require(sizeBits > 0, s"KeySpec.sizeBits must be positive, was $sizeBits")

object KeySpec:
  def aes256(name: String): KeySpec =
    KeySpec(name, Algorithm.AES, 256, KeyObjectType.SymmetricKey)

  def rsa2048(name: String): KeySpec =
    KeySpec(name, Algorithm.RSA, 2048, KeyObjectType.PrivateKey)

  def rsa4096(name: String): KeySpec =
    KeySpec(name, Algorithm.RSA, 4096, KeyObjectType.PrivateKey)
