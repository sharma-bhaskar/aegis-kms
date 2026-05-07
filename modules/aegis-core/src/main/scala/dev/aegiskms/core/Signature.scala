package dev.aegiskms.core

import java.util.Base64

/** Signing algorithm. Maps one-to-one with AWS KMS `SigningAlgorithmSpec` values, but the enum is
  * cloud-neutral so the same algebra method signature works for the in-memory dev impl, the AWS-backed root
  * of trust, and (later) GCP / Azure / Vault adapters.
  *
  * v0.1.1 ships the RSA-PSS-SHA-256 and ECDSA-SHA-256 variants — the two widest-deployed asymmetric signing
  * algorithms. Additional variants (PKCS#1, longer hashes, Ed25519) land in v0.2.0 alongside the GCP/Azure
  * adapters.
  */
enum SigAlgorithm:
  case RsaPssSha256
  case EcdsaSha256

object SigAlgorithm:

  /** Parse a wire-format string back to the enum. Used by the REST DTOs and the CLI. */
  def fromString(s: String): Either[String, SigAlgorithm] =
    values.find(_.toString.equalsIgnoreCase(s)).toRight(s"Unknown signing algorithm: $s")

/** A produced signature: opaque bytes plus the algorithm used to make them.
  *
  * Carrying the algorithm next to the bytes means callers don't have to remember it out-of-band — `verify`
  * always knows what to do with the value it receives. The bytes are kept as a plain `Array[Byte]`; we never
  * compare two `Signature` values with `==` (use `verify` for that), so the auto-generated case-class
  * equality being reference-based on the array is acceptable and intentional.
  */
final case class Signature(bytes: Array[Byte], algorithm: SigAlgorithm):
  /** Render the signature bytes as base64. The standard wire representation in REST and CLI surfaces. */
  def toBase64: String = Base64.getEncoder.encodeToString(bytes)

object Signature:
  def fromBase64(b64: String, algorithm: SigAlgorithm): Either[String, Signature] =
    try Right(Signature(Base64.getDecoder.decode(b64), algorithm))
    catch case e: IllegalArgumentException => Left(s"invalid base64: ${e.getMessage}")
