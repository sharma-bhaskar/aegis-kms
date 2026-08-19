package dev.aegiskms.crypto.vault

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
import dev.aegiskms.crypto.WrappedKey
import io.circe.Json
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64

/** Unit tests for `VaultTransitRootOfTrust` against a hand-rolled `VaultTransitPort` stub.
  *
  * The stub models Transit's actual wire shape — base64 payloads, `vault:v1:` ciphertext prefixes, the `data`
  * envelope already unwrapped by the port — because the things most likely to be wrong here are encoding
  * details, not control flow.
  */
final class VaultTransitRootOfTrustSpec extends AnyFunSuite with Matchers:

  private val config = VaultTransitRootOfTrust.Config(
    address = "https://vault.internal:8200",
    token = "s.token",
    keyName = "invoice-kek",
    signingKeyName = "invoice-signer"
  )

  private val keyA = KeyId.fromString("key-a").toOption.get

  private def b64(b: Array[Byte]) = Base64.getEncoder.encodeToString(b)
  private def unb64(s: String)    = Base64.getDecoder.decode(s)

  /** Records every call and models Transit's encoding: base64 in, `vault:v1:<base64>` out. */
  final private class StubPort extends VaultTransitPort:
    var calls: List[(String, Json)] = Nil
    var failWith: Option[Throwable] = None
    var validResult: Boolean        = true

    /** Omit a field from the next response, to exercise the malformed-response path. */
    var omitField: Option[String] = None

    private def datum(field: String, value: String): Json =
      if omitField.contains(field) then Json.obj() else Json.obj(field -> Json.fromString(value))

    def post(path: String, body: Json): Json =
      failWith.foreach(throw _)
      calls = calls :+ (path, body)
      val plaintextIn  = body.hcursor.get[String]("plaintext").toOption
      val ciphertextIn = body.hcursor.get[String]("ciphertext").toOption
      if path.contains("/datakey/") then
        val bits = body.hcursor.get[Int]("bits").getOrElse(256)
        Json.obj(
          "plaintext"  -> Json.fromString(b64(Array.fill(bits / 8)(7.toByte))),
          "ciphertext" -> Json.fromString(s"vault:v1:${b64(Array.fill(bits / 8)(7.toByte))}")
        )
      else if path.contains("/encrypt/") then
        datum("ciphertext", s"vault:v1:${plaintextIn.getOrElse("")}")
      else if path.contains("/decrypt/") then
        datum("plaintext", ciphertextIn.getOrElse("").stripPrefix("vault:v1:"))
      else if path.contains("/sign/") then
        datum("signature", s"vault:v1:${b64("SIGNED".getBytes)}")
      else if path.contains("/verify/") then Json.obj("valid" -> Json.fromBoolean(validResult))
      else Json.obj()

    def get(path: String): Json =
      failWith.foreach(throw _); calls = calls :+ (path, Json.obj()); Json.obj()

  private def rot(port: VaultTransitPort) = VaultTransitRootOfTrust.withPort(port, config)

  // ── Transit has a real data-key endpoint ──────────────────────────────────

  test("generateDataKey uses Transit's own datakey endpoint, not encrypt") {
    val port = new StubPort

    val wrapped = rot(port).generateDataKey(KeySpec.aes256("k")).unsafeRunSync().toOption.get

    port.calls.head._1 shouldBe "transit/datakey/plaintext/invoice-kek"
    new String(wrapped.bytes, UTF_8) should startWith("vault:v1:")
  }

  test("generateDataKey requests the bit-length matching the spec") {
    val p256 = new StubPort
    rot(p256).generateDataKey(KeySpec.aes256("k")).unsafeRunSync()
    p256.calls.head._2.hcursor.get[Int]("bits").toOption shouldBe Some(256)

    val p128 = new StubPort
    rot(p128).generateDataKey(KeySpec("k", Algorithm.AES, 128, KeyObjectType.SymmetricKey)).unsafeRunSync()
    p128.calls.head._2.hcursor.get[Int]("bits").toOption shouldBe Some(128)
  }

  test("generateDataKey then unwrap round-trips the material") {
    val port = new StubPort
    val r    = rot(port)

    val wrapped = r.generateDataKey(KeySpec.aes256("k")).unsafeRunSync().toOption.get
    r.unwrap(wrapped).unsafeRunSync().toOption.get.bytes.length shouldBe 32
  }

  // ── Ciphertext is a prefixed string, and the prefix must survive ──────────

  test("the vault:v1: prefix survives the round-trip so Vault can pick the key version") {
    val port = new StubPort
    val r    = rot(port)

    val ct = r.encrypt(keyA, "invoice".getBytes, Map.empty).unsafeRunSync().toOption.get
    new String(ct.bytes, UTF_8) should startWith("vault:v1:")

    r.decrypt(keyA, ct, Map.empty).unsafeRunSync().toOption.get shouldBe "invoice".getBytes
  }

  test("plaintext is base64-encoded on the way out, as Transit requires") {
    val port = new StubPort
    rot(port).encrypt(keyA, "hello".getBytes, Map.empty).unsafeRunSync()

    val sent = port.calls.head._2.hcursor.get[String]("plaintext").toOption.get
    unb64(sent) shouldBe "hello".getBytes
  }

  test("wrap then unwrapDek round-trips") {
    val port = new StubPort
    val r    = rot(port)
    val dek  = Array.tabulate(32)(_.toByte)

    val wrapped = r.wrap(keyA, dek).unsafeRunSync().toOption.get
    r.unwrapDek(keyA, wrapped).unsafeRunSync().toOption.get shouldBe dek
  }

  // ── Context → Transit key derivation ──────────────────────────────────────

  test("a context is sent as Transit's derivation context") {
    val port = new StubPort
    rot(port).encrypt(keyA, "p".getBytes, Map("tenant" -> "acme")).unsafeRunSync()

    val ctx = port.calls.head._2.hcursor.get[String]("context").toOption
    ctx should not be empty
    unb64(ctx.get) shouldBe VaultTransitRootOfTrust.canonicalContext(Map("tenant" -> "acme"))
  }

  test("no context field is sent when the caller supplies none") {
    val port = new StubPort
    rot(port).encrypt(keyA, "p".getBytes, Map.empty).unsafeRunSync()

    port.calls.head._2.hcursor.get[String]("context").toOption shouldBe None
  }

  test("the context encoding is canonical and injective, matching the other backends") {
    VaultTransitRootOfTrust.canonicalContext(Map("z" -> "1", "a" -> "2")) shouldBe
      VaultTransitRootOfTrust.canonicalContext(Map("a" -> "2", "z" -> "1"))
    VaultTransitRootOfTrust.canonicalContext(Map("ab" -> "c")) shouldNot be(
      VaultTransitRootOfTrust.canonicalContext(Map("a" -> "bc"))
    )
  }

  test("wrap sends no context — a wrapped DEK is not context-bound") {
    val port = new StubPort
    rot(port).wrap(keyA, "dek".getBytes).unsafeRunSync()

    port.calls.head._2.hcursor.get[String]("context").toOption shouldBe None
  }

  // ── Sign / verify ─────────────────────────────────────────────────────────

  test("signing addresses the separate signing key, not the encryption key") {
    val port = new StubPort
    rot(port).sign(keyA, "m".getBytes, SigAlgorithm.EcdsaSha256).unsafeRunSync()

    port.calls.head._1 shouldBe "transit/sign/invoice-signer"
  }

  test("without a separate signing key it falls back to the encryption key") {
    val port = new StubPort
    val cfg  = config.copy(signingKeyName = "")
    VaultTransitRootOfTrust.withPort(port, cfg).sign(keyA, "m".getBytes, SigAlgorithm.EcdsaSha256)
      .unsafeRunSync()

    port.calls.head._1 shouldBe "transit/sign/invoice-kek"
  }

  test("sign sends the base64 message and asks for sha2-256") {
    val port = new StubPort
    rot(port).sign(keyA, "audit".getBytes, SigAlgorithm.EcdsaSha256).unsafeRunSync()

    val body = port.calls.head._2.hcursor
    unb64(body.get[String]("input").toOption.get) shouldBe "audit".getBytes
    body.get[String]("hash_algorithm").toOption shouldBe Some("sha2-256")
  }

  test("RSA-PSS maps to Transit's pss signature algorithm") {
    val port = new StubPort
    rot(port).sign(keyA, "m".getBytes, SigAlgorithm.RsaPssSha256).unsafeRunSync()

    port.calls.head._2.hcursor.get[String]("signature_algorithm").toOption shouldBe Some("pss")
  }

  test("sign then verify accepts, and Vault's negative verdict is surfaced as false") {
    val port = new StubPort
    val r    = rot(port)

    val sig = r.sign(keyA, "m".getBytes, SigAlgorithm.EcdsaSha256).unsafeRunSync().toOption.get
    r.verify(keyA, "m".getBytes, sig).unsafeRunSync() shouldBe Right(true)

    port.validResult = false
    r.verify(keyA, "m".getBytes, sig).unsafeRunSync() shouldBe Right(false)
  }

  test("the signature string is passed back verbatim so Vault resolves the key version") {
    val port = new StubPort
    val r    = rot(port)

    val sig = r.sign(keyA, "m".getBytes, SigAlgorithm.EcdsaSha256).unsafeRunSync().toOption.get
    r.verify(keyA, "m".getBytes, sig).unsafeRunSync()

    port.calls.last._2.hcursor.get[String]("signature").toOption.get should startWith("vault:v1:")
  }

  test("a 400 on verify is a false verdict, not an infrastructure failure") {
    val port = new StubPort
    port.failWith = Some(VaultTransitPort.VaultHttpError(400, "invalid signature format"))

    rot(port).verify(keyA, "m".getBytes, Signature("bad".getBytes, SigAlgorithm.EcdsaSha256))
      .unsafeRunSync() shouldBe Right(false)
  }

  // ── Rotation ──────────────────────────────────────────────────────────────

  test("rotate calls Transit's native key-rotation endpoint") {
    val port = new StubPort
    rot(port).rotate(keyA).unsafeRunSync() shouldBe Right(keyA)

    port.calls.head._1 shouldBe "transit/keys/invoice-kek/rotate"
  }

  test("a custom mount path is honoured throughout") {
    val port = new StubPort
    VaultTransitRootOfTrust.withPort(port, config.copy(mount = "kms-transit"))
      .encrypt(keyA, "p".getBytes, Map.empty).unsafeRunSync()

    port.calls.head._1 shouldBe "kms-transit/encrypt/invoice-kek"
  }

  // ── Failure handling ──────────────────────────────────────────────────────

  test("a 404 becomes InvalidField — a wrong mount or key name is user error, not an outage") {
    val port = new StubPort
    port.failWith = Some(VaultTransitPort.VaultHttpError(404, "no handler for route"))

    val res = rot(port).encrypt(keyA, "p".getBytes, Map.empty).unsafeRunSync()
    res.left.toOption.get.code shouldBe ErrorCode.InvalidField
  }

  test("a 503 becomes CryptographicFailure — the backend is unavailable, not misconfigured") {
    val port = new StubPort
    port.failWith = Some(VaultTransitPort.VaultHttpError(503, "sealed"))

    rot(port).encrypt(keyA, "p".getBytes, Map.empty).unsafeRunSync()
      .left.toOption.get.code shouldBe ErrorCode.CryptographicFailure
  }

  test("a response missing its expected field is reported, not silently treated as empty") {
    val port = new StubPort
    port.omitField = Some("ciphertext")

    val res = rot(port).encrypt(keyA, "p".getBytes, Map.empty).unsafeRunSync()
    res.left.toOption.get.message should include("did not contain 'ciphertext'")
  }

  test("every operation degrades to a KmsError rather than throwing") {
    val port = new StubPort
    port.failWith = Some(new RuntimeException("connection reset"))
    val r = rot(port)

    r.generateDataKey(KeySpec.aes256("k")).unsafeRunSync().isLeft shouldBe true
    r.unwrap(WrappedKey("vault:v1:x".getBytes, "r")).unsafeRunSync().isLeft shouldBe true
    r.rotate(keyA).unsafeRunSync().isLeft shouldBe true
    r.sign(keyA, "m".getBytes, SigAlgorithm.EcdsaSha256).unsafeRunSync().isLeft shouldBe true
    r.encrypt(keyA, "p".getBytes, Map.empty).unsafeRunSync().isLeft shouldBe true
    r.decrypt(keyA, Ciphertext("vault:v1:x".getBytes), Map.empty).unsafeRunSync().isLeft shouldBe true
    r.wrap(keyA, "d".getBytes).unsafeRunSync().isLeft shouldBe true
    r.unwrapDek(keyA, WrappedDek("vault:v1:x".getBytes)).unsafeRunSync().isLeft shouldBe true
  }
