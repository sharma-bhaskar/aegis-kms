package dev.aegiskms.crypto.azure

import cats.effect.unsafe.implicits.global
import com.azure.security.keyvault.keys.cryptography.models.{
  EncryptParameters,
  EncryptionAlgorithm,
  KeyWrapAlgorithm,
  SignatureAlgorithm
}
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
import dev.aegiskms.crypto.WrappedKey
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.security.MessageDigest

/** Unit tests for `AzureKeyVaultRootOfTrust` against a hand-rolled `AzureKeyVaultPort` stub — the same
  * approach the AWS and GCP specs take.
  *
  * The properties worth pinning here are the ones specific to Azure: that the IV Azure chooses server-side
  * survives the round-trip, that native wrap/unwrap is used instead of faking it with encrypt, that digests
  * rather than messages are signed, and that an encryption context is refused rather than silently dropped on
  * an RSA key.
  */
final class AzureKeyVaultRootOfTrustSpec extends AnyFunSuite with Matchers:

  private val keyUrl          = "https://acme.vault.azure.net/keys/invoice-kek/abc123"
  private val symmetricConfig = AzureKeyVaultRootOfTrust.Config(keyUrl, symmetric = true)
  private val rsaConfig       = AzureKeyVaultRootOfTrust.Config(keyUrl, symmetric = false)
  private val keyA            = KeyId.fromString("key-a").toOption.get

  /** Models Key Vault closely enough to matter: it invents its own IV (as Azure does), returns the auth tag
    * separately, and refuses to decrypt when the IV, tag, or AAD do not match what it issued.
    */
  final private class StubPort extends AzureKeyVaultPort:
    var encryptCalls: List[EncryptParameters]                = Nil
    var wrapCalls: List[(KeyWrapAlgorithm, Array[Byte])]     = Nil
    var signCalls: List[(SignatureAlgorithm, Array[Byte])]   = Nil
    var verifyCalls: List[(SignatureAlgorithm, Array[Byte])] = Nil
    var failWith: Option[Throwable]                          = None
    var verifyResult: Boolean                                = true

    private val fixedIv              = Array.tabulate(12)(i => (0xa0 + i).toByte)
    private val fixedTag             = Array.tabulate(16)(i => (0xb0 + i).toByte)
    private var lastAad: Array[Byte] = Array.emptyByteArray

    private def boom(): Unit = failWith.foreach(throw _)

    def encrypt(parameters: EncryptParameters): AzureKeyVaultPort.EncryptOutcome =
      boom()
      encryptCalls = encryptCalls :+ parameters
      lastAad = Option(parameters.getAdditionalAuthenticatedData).getOrElse(Array.emptyByteArray)
      AzureKeyVaultPort.EncryptOutcome(
        cipherText = parameters.getPlainText.map(b => (b ^ 0x5a).toByte),
        iv = fixedIv,
        authTag = fixedTag
      )

    def decrypt(
        algorithm: EncryptionAlgorithm,
        ciphertext: Array[Byte],
        iv: Array[Byte],
        authTag: Array[Byte],
        aad: Array[Byte]
    ): Array[Byte] =
      boom()
      if algorithm == EncryptionAlgorithm.A256GCM then
        if !java.util.Arrays.equals(iv, fixedIv) then throw new IllegalStateException("IV mismatch")
        if !java.util.Arrays.equals(authTag, fixedTag) then throw new IllegalStateException("tag mismatch")
        if !java.util.Arrays.equals(aad, lastAad) then throw new IllegalStateException("AAD mismatch")
      ciphertext.map(b => (b ^ 0x5a).toByte)

    def sign(algorithm: SignatureAlgorithm, digest: Array[Byte]): Array[Byte] =
      boom(); signCalls = signCalls :+ (algorithm, digest); "SIG".getBytes ++ digest.take(4)

    def verify(algorithm: SignatureAlgorithm, digest: Array[Byte], signature: Array[Byte]): Boolean =
      boom(); verifyCalls = verifyCalls :+ (algorithm, digest); verifyResult

    def wrapKey(algorithm: KeyWrapAlgorithm, key: Array[Byte]): Array[Byte] =
      boom(); wrapCalls = wrapCalls :+ (algorithm, key); "WRAPPED:".getBytes ++ key

    def unwrapKey(algorithm: KeyWrapAlgorithm, encryptedKey: Array[Byte]): Array[Byte] =
      boom(); encryptedKey.drop("WRAPPED:".length)

    def keyId: String = keyUrl

  private def sym(port: AzureKeyVaultPort) = AzureKeyVaultRootOfTrust.withPort(port, symmetricConfig)
  private def rsa(port: AzureKeyVaultPort) = AzureKeyVaultRootOfTrust.withPort(port, rsaConfig)

  // ── Native wrap / unwrap ──────────────────────────────────────────────────

  test("generateDataKey uses native wrapKey, not encrypt-pretending-to-be-wrap") {
    val port = new StubPort

    val wrapped = sym(port).generateDataKey(KeySpec.aes256("k")).unsafeRunSync().toOption.get

    port.wrapCalls should have size 1
    port.encryptCalls shouldBe empty
    wrapped.rotationId shouldBe keyUrl
  }

  test("generateDataKey then unwrap round-trips the material") {
    val port = new StubPort
    val rot  = sym(port)

    val wrapped = rot.generateDataKey(KeySpec.aes256("k")).unsafeRunSync().toOption.get
    rot.unwrap(wrapped).unsafeRunSync().toOption.get.bytes.length shouldBe 32
  }

  test("generateDataKey honours the requested AES size") {
    val port = new StubPort
    sym(port).generateDataKey(KeySpec("k", Algorithm.AES, 128, KeyObjectType.SymmetricKey)).unsafeRunSync()
    port.wrapCalls.head._2.length shouldBe 16
  }

  test("a symmetric key uses A256KW, an RSA key uses RSA-OAEP-256") {
    val s = new StubPort; sym(s).wrap(keyA, "dek".getBytes).unsafeRunSync()
    val r = new StubPort; rsa(r).wrap(keyA, "dek".getBytes).unsafeRunSync()

    s.wrapCalls.head._1 shouldBe KeyWrapAlgorithm.A256KW
    r.wrapCalls.head._1 shouldBe KeyWrapAlgorithm.RSA_OAEP_256
  }

  test("wrap then unwrapDek round-trips") {
    val port = new StubPort
    val rot  = sym(port)
    val dek  = Array.tabulate(32)(_.toByte)

    val wrapped = rot.wrap(keyA, dek).unsafeRunSync().toOption.get
    rot.unwrapDek(keyA, wrapped).unsafeRunSync().toOption.get shouldBe dek
  }

  // ── Azure chooses the IV ──────────────────────────────────────────────────

  test("the IV Azure generates survives the round-trip") {
    val port = new StubPort
    val rot  = sym(port)

    val ct = rot.encrypt(keyA, "invoice".getBytes, Map.empty).unsafeRunSync().toOption.get
    // The stub refuses to decrypt unless it gets back the exact IV and tag it issued.
    rot.decrypt(keyA, ct, Map.empty).unsafeRunSync().toOption.get shouldBe "invoice".getBytes
  }

  test("the packed envelope is iv ++ ciphertext ++ tag") {
    val port = new StubPort
    val ct   = sym(port).encrypt(keyA, "abcd".getBytes, Map.empty).unsafeRunSync().toOption.get

    ct.bytes.length shouldBe 12 + 4 + 16
  }

  test("a truncated envelope is a clean error rather than an exception") {
    val port = new StubPort
    val res  = sym(port).decrypt(keyA, Ciphertext(Array[Byte](1, 2, 3)), Map.empty).unsafeRunSync()

    res.left.toOption.get.code shouldBe ErrorCode.CryptographicFailure
    res.left.toOption.get.message should include("too short")
  }

  // ── Encryption context ────────────────────────────────────────────────────

  test("the context is bound as AES-GCM AAD on a symmetric key") {
    val port = new StubPort
    sym(port).encrypt(keyA, "p".getBytes, Map("tenant" -> "acme")).unsafeRunSync()

    port.encryptCalls.head.getAdditionalAuthenticatedData shouldBe
      AzureKeyVaultRootOfTrust.aad(Map("tenant" -> "acme"))
  }

  test("a mismatched context fails rather than returning plaintext") {
    val port = new StubPort
    val rot  = sym(port)

    val ct = rot.encrypt(keyA, "p".getBytes, Map("tenant" -> "acme")).unsafeRunSync().toOption.get
    rot.decrypt(keyA, ct, Map("tenant" -> "evil")).unsafeRunSync().isLeft shouldBe true
  }

  test("a context on an RSA key is REFUSED, never silently dropped") {
    val port = new StubPort
    val res  = rsa(port).encrypt(keyA, "p".getBytes, Map("tenant" -> "acme")).unsafeRunSync()

    res.left.toOption.get.code shouldBe ErrorCode.InvalidField
    res.left.toOption.get.message should include("RSA-OAEP has no AAD input")
    // Nothing was sent — silently encrypting without binding the context is the failure mode this
    // guard exists to prevent.
    port.encryptCalls shouldBe empty
  }

  test("an empty context on an RSA key is fine") {
    val port = new StubPort
    rsa(port).encrypt(keyA, "p".getBytes, Map.empty).unsafeRunSync().isRight shouldBe true
  }

  test("the AAD encoding matches the other backends: canonical and injective") {
    AzureKeyVaultRootOfTrust.aad(Map("z" -> "1", "a" -> "2")) shouldBe
      AzureKeyVaultRootOfTrust.aad(Map("a" -> "2", "z" -> "1"))
    AzureKeyVaultRootOfTrust.aad(Map("ab" -> "c")) shouldNot be(
      AzureKeyVaultRootOfTrust.aad(Map("a" -> "bc"))
    )
  }

  // ── Sign / verify ─────────────────────────────────────────────────────────

  test("sign sends a SHA-256 digest, not the message") {
    val port = new StubPort
    val msg  = "audit-record".getBytes

    sym(port).sign(keyA, msg, SigAlgorithm.EcdsaSha256).unsafeRunSync()

    port.signCalls.head._2 shouldBe MessageDigest.getInstance("SHA-256").digest(msg)
  }

  test("the SigAlgorithm maps to the matching Azure algorithm") {
    val a = new StubPort; sym(a).sign(keyA, "m".getBytes, SigAlgorithm.EcdsaSha256).unsafeRunSync()
    val b = new StubPort; sym(b).sign(keyA, "m".getBytes, SigAlgorithm.RsaPssSha256).unsafeRunSync()

    a.signCalls.head._1 shouldBe SignatureAlgorithm.ES256
    b.signCalls.head._1 shouldBe SignatureAlgorithm.PS256
  }

  test("verify delegates to Azure server-side rather than fetching a public key") {
    val port = new StubPort
    port.verifyResult = false

    sym(port).verify(keyA, "m".getBytes, Signature("sig".getBytes, SigAlgorithm.EcdsaSha256))
      .unsafeRunSync() shouldBe Right(false)
    port.verifyCalls should have size 1
  }

  test("verify hashes the message before asking Azure") {
    val port = new StubPort
    val msg  = "verify-me".getBytes

    sym(port).verify(keyA, msg, Signature("s".getBytes, SigAlgorithm.EcdsaSha256)).unsafeRunSync()

    port.verifyCalls.head._2 shouldBe MessageDigest.getInstance("SHA-256").digest(msg)
  }

  // ── Rotation and failures ─────────────────────────────────────────────────

  test("rotate is a no-op that reports success rather than pretending to rotate") {
    val port = new StubPort
    sym(port).rotate(keyA).unsafeRunSync() shouldBe Right(keyA)
    port.encryptCalls shouldBe empty
    port.wrapCalls shouldBe empty
  }

  test("every operation degrades to a KmsError rather than throwing") {
    val port = new StubPort
    port.failWith = Some(new RuntimeException("vault unreachable"))
    val rot = sym(port)

    rot.generateDataKey(KeySpec.aes256("k")).unsafeRunSync().isLeft shouldBe true
    rot.unwrap(WrappedKey("WRAPPED:x".getBytes, "r")).unsafeRunSync().isLeft shouldBe true
    rot.sign(keyA, "m".getBytes, SigAlgorithm.EcdsaSha256).unsafeRunSync().isLeft shouldBe true
    rot.verify(keyA, "m".getBytes, Signature("s".getBytes, SigAlgorithm.EcdsaSha256))
      .unsafeRunSync().isLeft shouldBe true
    rot.encrypt(keyA, "p".getBytes, Map.empty).unsafeRunSync().isLeft shouldBe true
    rot.wrap(keyA, "d".getBytes).unsafeRunSync().isLeft shouldBe true
    rot.unwrapDek(keyA, WrappedDek("WRAPPED:x".getBytes)).unsafeRunSync().isLeft shouldBe true
  }
