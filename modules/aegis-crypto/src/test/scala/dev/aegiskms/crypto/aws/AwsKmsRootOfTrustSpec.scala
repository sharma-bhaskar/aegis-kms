package dev.aegiskms.crypto.aws

import cats.effect.unsafe.implicits.global
import dev.aegiskms.core.{Algorithm, ErrorCode, KeyId, KeyObjectType, KeySpec}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import software.amazon.awssdk.awscore.exception.AwsErrorDetails
import software.amazon.awssdk.services.kms.model.{DataKeySpec, KmsException}

/** Unit tests for `AwsKmsRootOfTrust` using a hand-rolled stub of `AwsKmsPort`.
  *
  * We test against the port rather than the AWS SDK `KmsClient` directly: the port has only the three
  * operations the adapter actually calls, so the stub stays tiny and the tests focus on the layered-mode
  * contract (wire shape, kekArn plumbing, error translation) without dragging in AWS SDK internals.
  */
final class AwsKmsRootOfTrustSpec extends AnyFunSuite with Matchers:

  private val kekArn = "arn:aws:kms:us-east-1:123456789012:key/aaaa-bbbb"

  test("generateDataKey returns wrapped bytes from the port and stamps the kekArn as rotationId") {
    val cipher = "ENCRYPTED-DATA-KEY".getBytes
    val plain  = "0123456789ABCDEF".getBytes // 16 bytes; discarded by the adapter
    var generateCalledWith: Option[(String, DataKeySpec)] = None

    val port = new StubAwsKmsPort(
      generate = (arn, spec) => {
        generateCalledWith = Some((arn, spec))
        AwsKmsPort.GenerateResult(ciphertext = cipher, plaintext = plain)
      }
    )

    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val res = rot.generateDataKey(KeySpec.aes256("invoice-2026")).unsafeRunSync()

    res.isRight shouldBe true
    val wrapped = res.toOption.get
    wrapped.bytes shouldBe cipher
    wrapped.rotationId shouldBe kekArn
    generateCalledWith shouldBe Some((kekArn, DataKeySpec.AES_256))
  }

  test("generateDataKey maps AES-128 to DataKeySpec.AES_128") {
    var seenSpec: Option[DataKeySpec] = None
    val port = new StubAwsKmsPort(
      generate = (_, spec) => {
        seenSpec = Some(spec)
        AwsKmsPort.GenerateResult(ciphertext = "c".getBytes, plaintext = "p".getBytes)
      }
    )
    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val aes128Spec = KeySpec("k", Algorithm.AES, 128, KeyObjectType.SymmetricKey)
    rot.generateDataKey(aes128Spec).unsafeRunSync()
    seenSpec shouldBe Some(DataKeySpec.AES_128)
  }

  test("unwrap returns the plaintext bytes that the port's Decrypt produced") {
    val cipher = "ENCRYPTED".getBytes
    val plain  = "PLAINTEXT-DATA".getBytes
    var decryptCalledWith: Option[(String, Array[Byte])] = None

    val port = new StubAwsKmsPort(
      decryptFn = (arn, ct) => {
        decryptCalledWith = Some((arn, ct))
        plain
      }
    )

    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val raw = rot.unwrap(dev.aegiskms.crypto.WrappedKey(cipher, kekArn)).unsafeRunSync()

    raw.isRight shouldBe true
    raw.toOption.get.bytes shouldBe plain
    decryptCalledWith.map(_._1) shouldBe Some(kekArn)
    decryptCalledWith.map(_._2.toSeq) shouldBe Some(cipher.toSeq)
  }

  test("AWS KmsException is translated into KmsError(CryptographicFailure, ...) with the op name") {
    val port = new StubAwsKmsPort(
      generate = (_, _) =>
        throw KmsException.builder()
          .awsErrorDetails(
            AwsErrorDetails.builder().errorMessage("AccessDenied").errorCode("AccessDenied").build()
          )
          .message("AccessDenied")
          .build()
    )
    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val res = rot.generateDataKey(KeySpec.aes256("k")).unsafeRunSync()

    res.isLeft shouldBe true
    val err = res.swap.toOption.get
    err.code shouldBe ErrorCode.CryptographicFailure
    err.message should include("GenerateDataKey")
    err.message should include("AccessDenied")
  }

  test("non-KMS exceptions on Decrypt translate to GeneralFailure") {
    val port = new StubAwsKmsPort(
      decryptFn = (_, _) => throw new RuntimeException("network blip")
    )
    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val res = rot.unwrap(dev.aegiskms.crypto.WrappedKey("c".getBytes, kekArn)).unsafeRunSync()

    res.isLeft shouldBe true
    val err = res.swap.toOption.get
    err.code shouldBe ErrorCode.GeneralFailure
    err.message should include("Decrypt")
    err.message should include("network blip")
  }

  test("rotate enables CMK rotation on the configured kekArn and returns the same KeyId") {
    var calledWith: Option[String] = None
    val port = new StubAwsKmsPort(
      enableRotationFn = arn => calledWith = Some(arn)
    )
    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val id  = KeyId.generate()
    val res = rot.rotate(id).unsafeRunSync()

    res.isRight shouldBe true
    res.toOption.get shouldBe id
    calledWith shouldBe Some(kekArn)
  }

  // ── Stub ────────────────────────────────────────────────────────────────────

  /** Minimal stub of `AwsKmsPort`. Each operation defaults to throwing so a test only has to override the
    * operations it actually exercises — anything else is loud failure rather than a silent no-op. The
    * constructor parameters intentionally do NOT share names with the trait methods (`generateDataKey`,
    * `decrypt`, `enableRotation`) to avoid Scala name-shadowing inside the method bodies.
    */
  private final class StubAwsKmsPort(
      generate: (String, DataKeySpec) => AwsKmsPort.GenerateResult = (_, _) =>
        throw new UnsupportedOperationException("generate not stubbed"),
      decryptFn: (String, Array[Byte]) => Array[Byte] = (_, _) =>
        throw new UnsupportedOperationException("decrypt not stubbed"),
      enableRotationFn: String => Unit = _ =>
        throw new UnsupportedOperationException("enableRotation not stubbed")
  ) extends AwsKmsPort:
    def generateDataKey(kekArn: String, spec: DataKeySpec): AwsKmsPort.GenerateResult =
      generate(kekArn, spec)
    def decrypt(kekArn: String, ciphertext: Array[Byte]): Array[Byte] =
      decryptFn(kekArn, ciphertext)
    def enableRotation(kekArn: String): Unit =
      enableRotationFn(kekArn)
