package dev.aegiskms.crypto.aws

import cats.effect.unsafe.implicits.global
import dev.aegiskms.core.{
  Algorithm,
  Ciphertext,
  ErrorCode,
  KeyId,
  KeyObjectType,
  KeySpec,
  SigAlgorithm,
  Signature,
  WrappedDek
}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import software.amazon.awssdk.awscore.exception.AwsErrorDetails
import software.amazon.awssdk.services.kms.model.{DataKeySpec, KmsException, SigningAlgorithmSpec}

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
    val rot        = AwsKmsRootOfTrust.withPort(port, kekArn)
    val aes128Spec = KeySpec("k", Algorithm.AES, 128, KeyObjectType.SymmetricKey)
    rot.generateDataKey(aes128Spec).unsafeRunSync()
    seenSpec shouldBe Some(DataKeySpec.AES_128)
  }

  test("unwrap returns the plaintext bytes that the port's Decrypt produced") {
    val cipher                                           = "ENCRYPTED".getBytes
    val plain                                            = "PLAINTEXT-DATA".getBytes
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

  test("sign delegates to the port with the mapped SigningAlgorithmSpec and wraps the bytes") {
    val sigBytes                                                  = "STUB-SIG".getBytes
    var seen: Option[(String, Array[Byte], SigningAlgorithmSpec)] = None
    val port = new StubAwsKmsPort(
      signFn = (arn, msg, alg) => {
        seen = Some((arn, msg, alg))
        sigBytes
      }
    )
    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val res = rot.sign(KeyId.generate(), "hello".getBytes, SigAlgorithm.RsaPssSha256).unsafeRunSync()

    res.isRight shouldBe true
    val sig = res.toOption.get
    sig.algorithm shouldBe SigAlgorithm.RsaPssSha256
    sig.bytes.toSeq shouldBe sigBytes.toSeq
    seen.map(_._1) shouldBe Some(kekArn)
    seen.map(_._3) shouldBe Some(SigningAlgorithmSpec.RSASSA_PSS_SHA_256)
  }

  test("verify returns Right(true|false) based on the port's boolean answer") {
    val port = new StubAwsKmsPort(verifyFn = (_, _, _, _) => true)
    val rot  = AwsKmsRootOfTrust.withPort(port, kekArn)
    val sig  = Signature("any".getBytes, SigAlgorithm.EcdsaSha256)
    val res  = rot.verify(KeyId.generate(), "msg".getBytes, sig).unsafeRunSync()
    res shouldBe Right(true)

    val portFalse = new StubAwsKmsPort(verifyFn = (_, _, _, _) => false)
    val rotFalse  = AwsKmsRootOfTrust.withPort(portFalse, kekArn)
    val resFalse  = rotFalse.verify(KeyId.generate(), "msg".getBytes, sig).unsafeRunSync()
    resFalse shouldBe Right(false)
  }

  test("encrypt delegates to the port with the supplied context and wraps the bytes") {
    var seenContext: Map[String, String] = Map.empty
    val port = new StubAwsKmsPort(
      encryptFn = (arn, pt, ctx) => {
        arn shouldBe kekArn
        seenContext = ctx
        pt ++ Array[Byte](0xff.toByte)
      }
    )
    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val res = rot.encrypt(KeyId.generate(), "hi".getBytes, Map("a" -> "1")).unsafeRunSync()

    res.isRight shouldBe true
    res.toOption.get.bytes.last shouldBe 0xff.toByte
    seenContext shouldBe Map("a" -> "1")
  }

  test("decrypt delegates to the port with the supplied context") {
    var seenContext: Map[String, String] = Map.empty
    val port = new StubAwsKmsPort(
      decryptCtxFn = (arn, ct, ctx) => {
        arn shouldBe kekArn
        seenContext = ctx
        "hi".getBytes
      }
    )
    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val res = rot
      .decrypt(KeyId.generate(), Ciphertext("anything".getBytes), Map("a" -> "1"))
      .unsafeRunSync()

    res.isRight shouldBe true
    new String(res.toOption.get, "UTF-8") shouldBe "hi"
    seenContext shouldBe Map("a" -> "1")
  }

  test("AWS KmsException on Encrypt translates to KmsError(CryptographicFailure, ...)") {
    val port = new StubAwsKmsPort(
      encryptFn = (_, _, _) =>
        throw KmsException.builder()
          .awsErrorDetails(
            AwsErrorDetails.builder().errorMessage("Disabled").errorCode("KeyDisabled").build()
          )
          .message("Disabled")
          .build()
    )
    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val res = rot.encrypt(KeyId.generate(), "x".getBytes, Map.empty).unsafeRunSync()

    res.isLeft shouldBe true
    res.swap.toOption.get.code shouldBe ErrorCode.CryptographicFailure
    res.swap.toOption.get.message should include("Encrypt")
  }

  test("wrap calls the port's encrypt with empty context and stamps the bytes onto a WrappedDek") {
    var seenContext: Map[String, String] = Map("present" -> "wrong")
    val port = new StubAwsKmsPort(
      encryptFn = (arn, dek, ctx) => {
        arn shouldBe kekArn
        seenContext = ctx
        dek ++ Array[Byte](0xee.toByte)
      }
    )
    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val res = rot.wrap(KeyId.generate(), "dek-bytes".getBytes).unsafeRunSync()

    res.isRight shouldBe true
    res.toOption.get.bytes.last shouldBe 0xee.toByte
    seenContext shouldBe Map.empty // wrap MUST NOT carry an AAD
  }

  test("unwrapDek calls the port's decrypt with empty context and returns the recovered bytes") {
    var seenContext: Map[String, String] = Map("present" -> "wrong")
    val port = new StubAwsKmsPort(
      decryptCtxFn = (arn, blob, ctx) => {
        arn shouldBe kekArn
        seenContext = ctx
        "recovered-dek".getBytes
      }
    )
    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val res = rot.unwrapDek(KeyId.generate(), WrappedDek("anything".getBytes)).unsafeRunSync()

    res.isRight shouldBe true
    new String(res.toOption.get, "UTF-8") shouldBe "recovered-dek"
    seenContext shouldBe Map.empty
  }

  test("AWS KmsException on Wrap translates to KmsError(CryptographicFailure, ...)") {
    val port = new StubAwsKmsPort(
      encryptFn = (_, _, _) =>
        throw KmsException.builder()
          .awsErrorDetails(
            AwsErrorDetails.builder().errorMessage("Disabled").errorCode("KeyDisabled").build()
          )
          .message("Disabled")
          .build()
    )
    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val res = rot.wrap(KeyId.generate(), "x".getBytes).unsafeRunSync()

    res.isLeft shouldBe true
    res.swap.toOption.get.code shouldBe ErrorCode.CryptographicFailure
    res.swap.toOption.get.message should include("Wrap")
  }

  test("AWS KmsException on Sign translates to KmsError(CryptographicFailure, ...)") {
    val port = new StubAwsKmsPort(
      signFn = (_, _, _) =>
        throw KmsException.builder()
          .awsErrorDetails(
            AwsErrorDetails.builder().errorMessage("BadKey").errorCode("InvalidKey").build()
          )
          .message("BadKey")
          .build()
    )
    val rot = AwsKmsRootOfTrust.withPort(port, kekArn)
    val res = rot.sign(KeyId.generate(), "msg".getBytes, SigAlgorithm.EcdsaSha256).unsafeRunSync()

    res.isLeft shouldBe true
    res.swap.toOption.get.code shouldBe ErrorCode.CryptographicFailure
    res.swap.toOption.get.message should include("Sign")
  }

  // ── Stub ────────────────────────────────────────────────────────────────────

  /** Minimal stub of `AwsKmsPort`. Each operation defaults to throwing so a test only has to override the
    * operations it actually exercises — anything else is loud failure rather than a silent no-op. The
    * constructor parameters intentionally do NOT share names with the trait methods (`generateDataKey`,
    * `decrypt`, `enableRotation`) to avoid Scala name-shadowing inside the method bodies.
    */
  final private class StubAwsKmsPort(
      generate: (String, DataKeySpec) => AwsKmsPort.GenerateResult = (_, _) =>
        throw new UnsupportedOperationException("generate not stubbed"),
      decryptFn: (String, Array[Byte]) => Array[Byte] = (_, _) =>
        throw new UnsupportedOperationException("decrypt not stubbed"),
      enableRotationFn: String => Unit = _ =>
        throw new UnsupportedOperationException("enableRotation not stubbed"),
      signFn: (String, Array[Byte], SigningAlgorithmSpec) => Array[Byte] = (_, _, _) =>
        throw new UnsupportedOperationException("sign not stubbed"),
      verifyFn: (String, Array[Byte], Array[Byte], SigningAlgorithmSpec) => Boolean = (_, _, _, _) =>
        throw new UnsupportedOperationException("verify not stubbed"),
      encryptFn: (String, Array[Byte], Map[String, String]) => Array[Byte] = (_, _, _) =>
        throw new UnsupportedOperationException("encrypt not stubbed"),
      decryptCtxFn: (String, Array[Byte], Map[String, String]) => Array[Byte] = (_, _, _) =>
        throw new UnsupportedOperationException("decryptWithContext not stubbed")
  ) extends AwsKmsPort:
    def generateDataKey(kekArn: String, spec: DataKeySpec): AwsKmsPort.GenerateResult =
      generate(kekArn, spec)
    def decrypt(kekArn: String, ciphertext: Array[Byte]): Array[Byte] =
      decryptFn(kekArn, ciphertext)
    def enableRotation(kekArn: String): Unit =
      enableRotationFn(kekArn)
    def sign(keyArn: String, message: Array[Byte], alg: SigningAlgorithmSpec): Array[Byte] =
      signFn(keyArn, message, alg)
    def verify(
        keyArn: String,
        message: Array[Byte],
        signature: Array[Byte],
        alg: SigningAlgorithmSpec
    ): Boolean =
      verifyFn(keyArn, message, signature, alg)
    def encrypt(keyArn: String, plaintext: Array[Byte], context: Map[String, String]): Array[Byte] =
      encryptFn(keyArn, plaintext, context)
    def decryptWithContext(
        keyArn: String,
        ciphertext: Array[Byte],
        context: Map[String, String]
    ): Array[Byte] =
      decryptCtxFn(keyArn, ciphertext, context)
