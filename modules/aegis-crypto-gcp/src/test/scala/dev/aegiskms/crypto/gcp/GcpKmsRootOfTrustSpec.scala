package dev.aegiskms.crypto.gcp

import cats.effect.unsafe.implicits.global
import com.google.cloud.kms.v1.{CryptoKeyName, CryptoKeyVersionName, Digest}
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

import java.security.spec.ECGenParameterSpec
import java.security.{KeyPairGenerator, MessageDigest, SecureRandom}
import java.util.Base64

/** Unit tests for `GcpKmsRootOfTrust` against a hand-rolled `GcpKmsPort` stub — the same approach
  * `AwsKmsRootOfTrustSpec` takes, and for the same reason: the Cloud KMS client has an enormous abstract
  * surface, and what needs pinning is the adapter's contract, not Google's.
  *
  * The stub is not a fake KMS. Where it matters — signature verification — it uses a real JCE keypair, so the
  * local-verification path (which is Aegis's own code, not Google's) is exercised end to end rather than
  * asserted against a canned boolean.
  */
final class GcpKmsRootOfTrustSpec extends AnyFunSuite with Matchers:

  private val config = GcpKmsRootOfTrust.Config(
    projectId = "acme-prod",
    location = "europe-west2",
    keyRing = "aegis",
    cryptoKey = "invoice-kek"
  )

  private val keyA = KeyId.fromString("key-a").toOption.get

  /** A real EC P-256 keypair, so `verify` runs actual cryptography. */
  private val ecPair =
    val g = KeyPairGenerator.getInstance("EC")
    g.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom())
    g.generateKeyPair()

  /** A real RSA keypair for the RSA-PSS verification path. */
  private lazy val rsaPair =
    val g = KeyPairGenerator.getInstance("RSA")
    g.initialize(2048, new SecureRandom())
    g.generateKeyPair()

  private def pemOf(pub: java.security.PublicKey): String =
    val b64 = Base64.getMimeEncoder(64, "\n".getBytes).encodeToString(pub.getEncoded)
    s"-----BEGIN PUBLIC KEY-----\n$b64\n-----END PUBLIC KEY-----\n"

  /** Records every call and returns scripted results. Encryption is modelled as a reversible tagged
    * concatenation so AAD binding can be asserted without a real KMS.
    */
  final private class StubPort extends GcpKmsPort:
    var randomCalls: List[(String, Int)]                       = Nil
    var encryptCalls: List[(String, Array[Byte], Array[Byte])] = Nil
    var signedDigests: List[Array[Byte]]                       = Nil
    var versionsCreated: List[String]                          = Nil
    var publicKeyRequests: List[String]                        = Nil
    var failWith: Option[Throwable]                            = None

    /** Serve a different PEM — used to drive the RSA verification path. */
    var publicKeyOverride: Option[String] = None

    private def raiseIfScripted(): Unit = failWith.foreach(throw _)

    def generateRandomBytes(location: String, lengthBytes: Int): Array[Byte] =
      raiseIfScripted()
      randomCalls = randomCalls :+ (location, lengthBytes)
      Array.tabulate(lengthBytes)(i => (i + 1).toByte)

    def encrypt(keyName: CryptoKeyName, plaintext: Array[Byte], aad: Array[Byte]): Array[Byte] =
      raiseIfScripted()
      encryptCalls = encryptCalls :+ (keyName.toString, plaintext, aad)
      // aadLen ++ aad ++ plaintext — reversible, and decrypt can check the AAD matches.
      Array(aad.length.toByte) ++ aad ++ plaintext

    def decrypt(keyName: CryptoKeyName, ciphertext: Array[Byte], aad: Array[Byte]): Array[Byte] =
      raiseIfScripted()
      val aadLen   = ciphertext.head.toInt
      val storeAad = ciphertext.slice(1, 1 + aadLen)
      if !java.util.Arrays.equals(storeAad, aad) then
        throw new IllegalStateException("AAD mismatch")
      ciphertext.drop(1 + aadLen)

    def asymmetricSign(version: CryptoKeyVersionName, digest: Digest): Array[Byte] =
      raiseIfScripted()
      signedDigests = signedDigests :+ digest.getSha256.toByteArray
      // Cloud KMS applies the signature primitive directly to the supplied digest — it does not hash
      // again. NONEwithECDSA models that exactly; using SHA256withECDSA here would sign H(H(m)) and
      // produce signatures that real Cloud KMS would never emit, making the verify test meaningless.
      val s = java.security.Signature.getInstance("NONEwithECDSA")
      s.initSign(ecPair.getPrivate)
      s.update(digest.getSha256.toByteArray)
      s.sign()

    def publicKeyPem(version: CryptoKeyVersionName): String =
      raiseIfScripted()
      publicKeyRequests = publicKeyRequests :+ version.toString
      publicKeyOverride.getOrElse(pemOf(ecPair.getPublic))

    def createKeyVersion(keyName: CryptoKeyName): String =
      raiseIfScripted()
      versionsCreated = versionsCreated :+ keyName.toString
      s"${keyName.toString}/cryptoKeyVersions/2"

  private def rotWith(port: GcpKmsPort, cfg: GcpKmsRootOfTrust.Config = config) =
    GcpKmsRootOfTrust.withPort(port, cfg)

  private val expectedKeyName =
    "projects/acme-prod/locations/europe-west2/keyRings/aegis/cryptoKeys/invoice-kek"

  // ── Resource naming ───────────────────────────────────────────────────────

  test("operations address the fully-qualified CryptoKey resource name") {
    val port = new StubPort
    rotWith(port).encrypt(keyA, "p".getBytes, Map.empty).unsafeRunSync()

    port.encryptCalls.head._1 shouldBe expectedKeyName
  }

  test("data-key material is requested from the key's own location") {
    val port = new StubPort
    rotWith(port).generateDataKey(KeySpec.aes256("k")).unsafeRunSync()

    port.randomCalls.head._1 shouldBe "projects/acme-prod/locations/europe-west2"
  }

  test("signing addresses a specific CryptoKeyVersion, and a separate signing key when configured") {
    val port = new StubPort
    val cfg  = config.copy(signingKey = Some("invoice-signer"), signingKeyVersion = "3")

    rotWith(port, cfg).verify(keyA, "m".getBytes, Signature(Array[Byte](1), SigAlgorithm.EcdsaSha256))
      .unsafeRunSync()

    port.publicKeyRequests.head shouldBe
      "projects/acme-prod/locations/europe-west2/keyRings/aegis/cryptoKeys/invoice-signer/cryptoKeyVersions/3"
  }

  test("without a separate signing key it falls back to the encryption key") {
    val port = new StubPort
    rotWith(port).verify(keyA, "m".getBytes, Signature(Array[Byte](1), SigAlgorithm.EcdsaSha256))
      .unsafeRunSync()

    port.publicKeyRequests.head should endWith("cryptoKeys/invoice-kek/cryptoKeyVersions/1")
  }

  // ── generateDataKey: the composed GenerateRandomBytes + Encrypt ───────────

  test("generateDataKey mints HSM random bytes and returns them wrapped, never in the clear") {
    val port = new StubPort

    val wrapped = rotWith(port).generateDataKey(KeySpec.aes256("k")).unsafeRunSync().toOption.get

    port.randomCalls.head._2 shouldBe 32
    // The wrapped blob is what Encrypt produced, not the raw material.
    port.encryptCalls should have size 1
    wrapped.bytes shouldBe port.encryptCalls.head.let(c => Array(0.toByte) ++ c._3 ++ c._2)
    wrapped.rotationId shouldBe expectedKeyName
  }

  test("generateDataKey honours the requested AES size") {
    val port   = new StubPort
    val aes128 = KeySpec("k", Algorithm.AES, 128, KeyObjectType.SymmetricKey)

    rotWith(port).generateDataKey(aes128).unsafeRunSync()

    port.randomCalls.head._2 shouldBe 16
  }

  test("a non-AES spec falls back to 256 bits, matching the AWS adapter") {
    val port = new StubPort
    rotWith(port).generateDataKey(KeySpec.rsa2048("signing")).unsafeRunSync()

    port.randomCalls.head._2 shouldBe 32
  }

  test("generateDataKey then unwrap round-trips the material") {
    val port = new StubPort
    val rot  = rotWith(port)

    val wrapped = rot.generateDataKey(KeySpec.aes256("k")).unsafeRunSync().toOption.get
    val raw     = rot.unwrap(wrapped).unsafeRunSync().toOption.get

    raw.bytes shouldBe Array.tabulate(32)(i => (i + 1).toByte)
  }

  // ── Encryption context → AAD ──────────────────────────────────────────────

  test("the encryption context is bound as AAD") {
    val port = new StubPort
    rotWith(port).encrypt(keyA, "p".getBytes, Map("tenant" -> "acme")).unsafeRunSync()

    port.encryptCalls.head._3 shouldBe GcpKmsRootOfTrust.aad(Map("tenant" -> "acme"))
    port.encryptCalls.head._3 shouldNot be(empty)
  }

  test("encrypt then decrypt round-trips under a matching context") {
    val port = new StubPort
    val rot  = rotWith(port)
    val ctx  = Map("tenant" -> "acme", "purpose" -> "billing")

    val ct = rot.encrypt(keyA, "invoice".getBytes, ctx).unsafeRunSync().toOption.get
    rot.decrypt(keyA, ct, ctx).unsafeRunSync().toOption.get shouldBe "invoice".getBytes
  }

  test("a mismatched context fails rather than returning plaintext") {
    val port = new StubPort
    val rot  = rotWith(port)

    val ct = rot.encrypt(keyA, "p".getBytes, Map("tenant" -> "acme")).unsafeRunSync().toOption.get
    rot.decrypt(keyA, ct, Map("tenant" -> "evil")).unsafeRunSync().isLeft shouldBe true
  }

  test("the AAD encoding is canonical — map ordering does not change the bytes") {
    GcpKmsRootOfTrust.aad(Map("z" -> "1", "a" -> "2")) shouldBe
      GcpKmsRootOfTrust.aad(Map("a" -> "2", "z" -> "1"))
  }

  test("the AAD encoding is injective — {ab:c} and {a:bc} do not collide") {
    GcpKmsRootOfTrust.aad(Map("ab" -> "c")) shouldNot be(GcpKmsRootOfTrust.aad(Map("a" -> "bc")))
  }

  test("an empty context produces empty AAD, matching a wrap with no context") {
    GcpKmsRootOfTrust.aad(Map.empty) shouldBe Array.emptyByteArray
  }

  test("wrap uses no AAD, so a wrapped DEK is not context-bound") {
    val port = new StubPort
    rotWith(port).wrap(keyA, "dek".getBytes).unsafeRunSync()

    port.encryptCalls.head._3 shouldBe Array.emptyByteArray
  }

  test("wrap then unwrapDek round-trips") {
    val port = new StubPort
    val rot  = rotWith(port)
    val dek  = Array.tabulate(32)(_.toByte)

    val wrapped = rot.wrap(keyA, dek).unsafeRunSync().toOption.get
    rot.unwrapDek(keyA, wrapped).unsafeRunSync().toOption.get shouldBe dek
  }

  // ── Signing: digest computed locally, verification done locally ───────────

  test("sign sends a SHA-256 digest of the message, not the message itself") {
    val port    = new StubPort
    val message = "audit-record-4711".getBytes

    rotWith(port).sign(keyA, message, SigAlgorithm.EcdsaSha256).unsafeRunSync()

    port.signedDigests.head shouldBe MessageDigest.getInstance("SHA-256").digest(message)
    port.signedDigests.head shouldNot be(message)
  }

  test("sign then verify accepts the signature, exercising the local verification path") {
    val port = new StubPort
    val rot  = rotWith(port)
    val msg  = "sign-me".getBytes

    val sig = rot.sign(keyA, msg, SigAlgorithm.EcdsaSha256).unsafeRunSync().toOption.get
    rot.verify(keyA, msg, sig).unsafeRunSync().toOption.get shouldBe true
  }

  test("verify rejects a signature over a different message") {
    val port = new StubPort
    val rot  = rotWith(port)

    val sig = rot.sign(keyA, "original".getBytes, SigAlgorithm.EcdsaSha256).unsafeRunSync().toOption.get
    rot.verify(keyA, "tampered".getBytes, sig).unsafeRunSync().toOption.get shouldBe false
  }

  test("verify returns false rather than erroring on a structurally invalid signature") {
    val port = new StubPort
    val res = rotWith(port)
      .verify(keyA, "m".getBytes, Signature(Array[Byte](1, 2, 3), SigAlgorithm.EcdsaSha256))
      .unsafeRunSync()

    res shouldBe Right(false)
  }

  test("the PEM returned by GetPublicKey parses into a usable JCA key") {
    val parsed = GcpKmsRootOfTrust.publicKeyFrom(pemOf(ecPair.getPublic), SigAlgorithm.EcdsaSha256)
    parsed.getEncoded shouldBe ecPair.getPublic.getEncoded
  }

  test("an RSA PEM parses under the RSA-PSS algorithm") {
    val parsed = GcpKmsRootOfTrust.publicKeyFrom(pemOf(rsaPair.getPublic), SigAlgorithm.RsaPssSha256)
    parsed.getAlgorithm shouldBe "RSA"
    parsed.getEncoded shouldBe rsaPair.getPublic.getEncoded
  }

  test("PEM parsing tolerates the line wrapping and trailing newline Cloud KMS emits") {
    // Cloud KMS returns 64-column-wrapped base64 with a trailing newline; a parser that assumed a
    // single line would work in a unit test built from unwrapped input and fail against the service.
    val wrapped = pemOf(ecPair.getPublic)
    wrapped should include("\n")
    GcpKmsRootOfTrust.publicKeyFrom(wrapped, SigAlgorithm.EcdsaSha256).getEncoded shouldBe
      ecPair.getPublic.getEncoded
  }

  test("RSA-PSS verification accepts a genuine signature — exercising the PSS parameters") {
    // Independently produced with the same PSS parameters Cloud KMS uses for
    // RSA_SIGN_PSS_2048_SHA256. If jcaVerifier's salt length or MGF were wrong, this fails.
    val msg    = "invoice-4711".getBytes
    val signer = java.security.Signature.getInstance("RSASSA-PSS")
    signer.setParameter(new java.security.spec.PSSParameterSpec(
      "SHA-256",
      "MGF1",
      java.security.spec.MGF1ParameterSpec.SHA256,
      32,
      1
    ))
    signer.initSign(rsaPair.getPrivate)
    signer.update(msg)
    val sig = Signature(signer.sign(), SigAlgorithm.RsaPssSha256)

    val port = new StubPort
    port.publicKeyOverride = Some(pemOf(rsaPair.getPublic))

    rotWith(port).verify(keyA, msg, sig).unsafeRunSync().toOption.get shouldBe true
  }

  test("RSA-PSS verification rejects a signature over a different message") {
    val signer = java.security.Signature.getInstance("RSASSA-PSS")
    signer.setParameter(new java.security.spec.PSSParameterSpec(
      "SHA-256",
      "MGF1",
      java.security.spec.MGF1ParameterSpec.SHA256,
      32,
      1
    ))
    signer.initSign(rsaPair.getPrivate)
    signer.update("original".getBytes)
    val sig = Signature(signer.sign(), SigAlgorithm.RsaPssSha256)

    val port = new StubPort
    port.publicKeyOverride = Some(pemOf(rsaPair.getPublic))

    rotWith(port).verify(keyA, "tampered".getBytes, sig).unsafeRunSync().toOption.get shouldBe false
  }

  // ── Rotation ──────────────────────────────────────────────────────────────

  test("rotate creates a new CryptoKeyVersion against the configured key") {
    val port = new StubPort

    rotWith(port).rotate(keyA).unsafeRunSync() shouldBe Right(keyA)
    port.versionsCreated shouldBe List(expectedKeyName)
  }

  // ── Limits and failures ───────────────────────────────────────────────────

  test("an oversized plaintext is rejected locally, naming the Cloud KMS limit") {
    val port = new StubPort
    val big  = new Array[Byte](GcpKmsRootOfTrust.MaxPlaintextBytes + 1)

    val res = rotWith(port).encrypt(keyA, big, Map.empty).unsafeRunSync()

    res.left.toOption.get.code shouldBe ErrorCode.InvalidField
    res.left.toOption.get.message should include("65536")
    // The call never left the process.
    port.encryptCalls shouldBe empty
  }

  test("a plaintext exactly at the limit is accepted") {
    val port    = new StubPort
    val atLimit = new Array[Byte](GcpKmsRootOfTrust.MaxPlaintextBytes)

    rotWith(port).encrypt(keyA, atLimit, Map.empty).unsafeRunSync().isRight shouldBe true
  }

  test("wrap is size-guarded too") {
    val port = new StubPort
    val big  = new Array[Byte](GcpKmsRootOfTrust.MaxPlaintextBytes + 1)

    rotWith(port).wrap(keyA, big).unsafeRunSync().isLeft shouldBe true
    port.encryptCalls shouldBe empty
  }

  test("a transport failure becomes a KmsError naming the operation, not an exception") {
    val port = new StubPort
    port.failWith = Some(new RuntimeException("deadline exceeded"))

    val res = rotWith(port).encrypt(keyA, "p".getBytes, Map.empty).unsafeRunSync()

    res.left.toOption.get.code shouldBe ErrorCode.GeneralFailure
    res.left.toOption.get.message should include("Encrypt")
  }

  test("every operation degrades to a KmsError rather than throwing") {
    val port = new StubPort
    port.failWith = Some(new RuntimeException("boom"))
    val rot = rotWith(port)

    rot.generateDataKey(KeySpec.aes256("k")).unsafeRunSync().isLeft shouldBe true
    rot.unwrap(dev.aegiskms.crypto.WrappedKey(Array[Byte](0), "r")).unsafeRunSync().isLeft shouldBe true
    rot.rotate(keyA).unsafeRunSync().isLeft shouldBe true
    rot.sign(keyA, "m".getBytes, SigAlgorithm.EcdsaSha256).unsafeRunSync().isLeft shouldBe true
    rot.decrypt(keyA, Ciphertext(Array[Byte](0)), Map.empty).unsafeRunSync().isLeft shouldBe true
    rot.unwrapDek(keyA, WrappedDek(Array[Byte](0))).unsafeRunSync().isLeft shouldBe true
  }

  extension [A](a: A) private def let[B](f: A => B): B = f(a)
