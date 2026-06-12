package dev.aegiskms.sdk.javadsl

import dev.aegiskms.sdk.WireFormats.*
import dev.aegiskms.sdk.{AegisClient, AegisHttpClient}

import scala.jdk.CollectionConverters.*

/** Thrown by [[AegisJavaClient]] when the server (or the wire) reports a failure. Java callers get one
  * exception type with a rendered message instead of the Scala `Either` channel.
  */
final class AegisClientException(message: String) extends RuntimeException(message)

/** Java-friendly facade over [[dev.aegiskms.sdk.AegisHttpClient]]: `java.util` collections in, DTOs out,
  * failures as [[AegisClientException]]. `aegis-sdk-java`'s `AegisClientJ` delegates here so the Java
  * artifact stays a thin pure-Java shim.
  */
final class AegisJavaClient private (underlying: AegisHttpClient):

  def createKey(name: String, algorithm: String, sizeBits: Int): ManagedKeyDto =
    orThrow(underlying.createKey(KeySpecDto(name, algorithm, sizeBits, "SymmetricKey")))

  def getKey(id: String): ManagedKeyDto = orThrow(underlying.getKey(id))

  def activateKey(id: String): ManagedKeyDto = orThrow(underlying.activateKey(id))

  def destroyKey(id: String): Unit = orThrow(underlying.destroyKey(id))

  def sign(id: String, messageBase64: String, algorithm: String): SignResponse =
    orThrow(underlying.signKey(id, SignRequest(messageBase64, algorithm)))

  def verify(id: String, messageBase64: String, signatureBase64: String, algorithm: String): Boolean =
    orThrow(underlying.verifyKey(id, VerifyRequest(messageBase64, signatureBase64, algorithm))).valid

  def encrypt(
      id: String,
      plaintextBase64: String,
      context: java.util.Map[String, String]
  ): EncryptResponse =
    orThrow(underlying.encryptKey(id, EncryptRequest(plaintextBase64, context.asScala.toMap)))

  def decrypt(
      id: String,
      ciphertextBase64: String,
      context: java.util.Map[String, String]
  ): DecryptResponse =
    orThrow(underlying.decryptKey(id, DecryptRequest(ciphertextBase64, context.asScala.toMap)))

  def wrap(id: String, dekBase64: String): WrapResponse =
    orThrow(underlying.wrapKey(id, WrapRequest(dekBase64)))

  def unwrap(id: String, wrappedDekBase64: String): UnwrapResponse =
    orThrow(underlying.unwrapKey(id, UnwrapRequest(wrappedDekBase64)))

  def compromiseKey(id: String, reason: String): ManagedKeyDto =
    orThrow(underlying.compromiseKey(id, CompromiseRequest(reason)))

  def rotateKey(id: String, policy: String): ManagedKeyDto =
    orThrow(underlying.rotateKey(id, RotateRequest(policy)))

  def issueAgent(
      label: String,
      scopes: java.util.List[String],
      ttlSeconds: Long,
      parent: String /* nullable */
  ): IssueAgentResponseDto =
    orThrow(
      underlying.issueAgent(
        IssueAgentRequestDto(label, scopes.asScala.toList, ttlSeconds, Option(parent))
      )
    )

  private def orThrow[A](res: Either[AegisHttpClient.ClientError, A]): A =
    res.fold(err => throw new AegisClientException(AegisHttpClient.renderError(err)), identity)

object AegisJavaClient:

  /** Connect with a bearer JWT — the production path. */
  def https(baseUrl: String, token: String): AegisJavaClient =
    new AegisJavaClient(AegisClient.https(baseUrl, token))

  /** Connect to a dev-mode server via the `X-Aegis-User` header. Workstation use only. */
  def dev(baseUrl: String, principal: String): AegisJavaClient =
    new AegisJavaClient(AegisClient.dev(baseUrl, principal))
