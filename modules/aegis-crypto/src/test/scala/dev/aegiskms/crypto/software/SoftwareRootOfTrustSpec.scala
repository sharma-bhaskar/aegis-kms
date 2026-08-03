package dev.aegiskms.crypto.software

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import cats.syntax.all.*
import dev.aegiskms.core.{
  Algorithm,
  Ciphertext,
  ErrorCode,
  KeyId,
  KeyObjectType,
  KeySpec,
  SigAlgorithm,
  Signature
}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.nio.file.{Files, Path}

/** Behavioural tests for the JCE-backed software root of trust.
  *
  * Unlike `AwsKmsRootOfTrustSpec`, there is no port to stub — the whole point of this adapter is that it does
  * real cryptography with no external dependency, so these tests exercise the real primitives end to end.
  * They cover the three properties the adapter claims: round-trip correctness, cryptographic separation
  * (between keys, between operation families, and across encryption contexts), and non-destructive rotation.
  */
final class SoftwareRootOfTrustSpec extends AnyFunSuite with Matchers:

  private def ephemeral: SoftwareRootOfTrust =
    SoftwareRootOfTrust.withKeyStore(SoftwareKeyStore.ephemeral())

  private val keyA = KeyId.fromString("key-a").toOption.get
  private val keyB = KeyId.fromString("key-b").toOption.get

  // ── Encrypt / decrypt ──────────────────────────────────────────────────────

  test("encrypt then decrypt round-trips the plaintext under a matching encryption context") {
    val rot     = ephemeral
    val payload = "invoice-2026-total: 4711.00".getBytes("UTF-8")
    val ctx     = Map("tenant" -> "acme", "purpose" -> "billing")

    val ct    = rot.encrypt(keyA, payload, ctx).unsafeRunSync().toOption.get
    val plain = rot.decrypt(keyA, ct, ctx).unsafeRunSync()

    plain.toOption.get shouldBe payload
  }

  test("ciphertext does not contain the plaintext — this is real encryption, not the in-memory stub") {
    val rot     = ephemeral
    val payload = "SUPER-SECRET-MARKER".getBytes("UTF-8")

    val ct = rot.encrypt(keyA, payload, Map.empty).unsafeRunSync().toOption.get

    new String(ct.bytes, "ISO-8859-1") should not include "SUPER-SECRET-MARKER"
  }

  test("encrypting the same plaintext twice yields different ciphertext (fresh GCM nonce per call)") {
    val rot     = ephemeral
    val payload = "same-input".getBytes("UTF-8")

    val first  = rot.encrypt(keyA, payload, Map.empty).unsafeRunSync().toOption.get
    val second = rot.encrypt(keyA, payload, Map.empty).unsafeRunSync().toOption.get

    first.bytes shouldNot be(second.bytes)
  }

  test("decrypt with a different encryption context fails authentication") {
    val rot     = ephemeral
    val payload = "context-bound".getBytes("UTF-8")

    val ct  = rot.encrypt(keyA, payload, Map("tenant" -> "acme")).unsafeRunSync().toOption.get
    val res = rot.decrypt(keyA, ct, Map("tenant" -> "evil-corp")).unsafeRunSync()

    res.left.toOption.get.code shouldBe ErrorCode.CryptographicFailure
  }

  test("context binding is injective — {ab->c} and {a->bc} are not interchangeable") {
    val rot = ephemeral
    val ct  = rot.encrypt(keyA, "p".getBytes, Map("ab" -> "c")).unsafeRunSync().toOption.get

    rot.decrypt(keyA, ct, Map("a" -> "bc")).unsafeRunSync().isLeft shouldBe true
  }

  test("context ordering does not matter — the AAD encoding is canonical") {
    val rot = ephemeral
    val ct  = rot.encrypt(keyA, "p".getBytes, Map("z" -> "1", "a" -> "2")).unsafeRunSync().toOption.get

    rot.decrypt(keyA, ct, Map("a" -> "2", "z" -> "1")).unsafeRunSync().isRight shouldBe true
  }

  test("ciphertext for one KeyId cannot be decrypted as another KeyId") {
    val rot = ephemeral
    val ct  = rot.encrypt(keyA, "tenant-a-data".getBytes, Map.empty).unsafeRunSync().toOption.get

    val res = rot.decrypt(keyB, ct, Map.empty).unsafeRunSync()

    res.left.toOption.get.code shouldBe ErrorCode.CryptographicFailure
  }

  test("a wrapped DEK cannot be opened by the encrypt family — operation families are separated") {
    val rot     = ephemeral
    val wrapped = rot.wrap(keyA, "dek-material".getBytes).unsafeRunSync().toOption.get

    rot.decrypt(keyA, Ciphertext(wrapped.bytes), Map.empty).unsafeRunSync().isLeft shouldBe true
  }

  test("a truncated envelope is reported as a cryptographic failure, not an exception") {
    val rot = ephemeral
    val res = rot.decrypt(keyA, Ciphertext(Array[Byte](1, 2, 3)), Map.empty).unsafeRunSync()

    res.left.toOption.get.code shouldBe ErrorCode.CryptographicFailure
    res.left.toOption.get.message should include("too short")
  }

  test("an unknown envelope format version is rejected with a clear message") {
    val rot   = ephemeral
    val ct    = rot.encrypt(keyA, "p".getBytes, Map.empty).unsafeRunSync().toOption.get
    val bogus = ct.bytes.clone()
    bogus(0) = 99.toByte

    val res = rot.decrypt(keyA, Ciphertext(bogus), Map.empty).unsafeRunSync()

    res.left.toOption.get.message should include("format version")
  }

  test("tampering with the ciphertext body fails the GCM tag check") {
    val rot      = ephemeral
    val ct       = rot.encrypt(keyA, "authentic".getBytes, Map.empty).unsafeRunSync().toOption.get
    val tampered = ct.bytes.clone()
    tampered(tampered.length - 1) = (tampered(tampered.length - 1) ^ 0xff).toByte

    val res = rot.decrypt(keyA, Ciphertext(tampered), Map.empty).unsafeRunSync()

    res.left.toOption.get.message should include("authentication failed")
  }

  test("tampering with the GCM nonce fails the tag check rather than decrypting to garbage") {
    val rot      = ephemeral
    val ct       = rot.encrypt(keyA, "authentic".getBytes, Map.empty).unsafeRunSync().toOption.get
    val tampered = ct.bytes.clone()
    tampered(6) = (tampered(6) ^ 0xff).toByte // first nonce byte, just past the 5-byte header

    rot.decrypt(keyA, Ciphertext(tampered), Map.empty).unsafeRunSync().isLeft shouldBe true
  }

  test("an empty plaintext round-trips — the smallest legal envelope is exactly header+nonce+tag") {
    val rot = ephemeral

    val ct = rot.encrypt(keyA, Array.emptyByteArray, Map.empty).unsafeRunSync().toOption.get

    // 5-byte header + 12-byte nonce + 16-byte tag, and not one byte more.
    ct.bytes.length shouldBe 33
    rot.decrypt(keyA, ct, Map.empty).unsafeRunSync().toOption.get shouldBe Array.emptyByteArray
  }

  test("a multi-block payload round-trips") {
    val rot     = ephemeral
    val payload = Array.tabulate(100_000)(i => (i % 256).toByte)

    val ct = rot.encrypt(keyA, payload, Map.empty).unsafeRunSync().toOption.get
    rot.decrypt(keyA, ct, Map.empty).unsafeRunSync().toOption.get shouldBe payload
  }

  test("a non-ASCII encryption context round-trips and still binds") {
    val rot = ephemeral
    val ctx = Map("tenant" -> "Ökonomie-Ürün", "purpose" -> "請求書")

    val ct = rot.encrypt(keyA, "unicode".getBytes("UTF-8"), ctx).unsafeRunSync().toOption.get

    rot.decrypt(keyA, ct, ctx).unsafeRunSync().toOption.get shouldBe "unicode".getBytes("UTF-8")
    rot.decrypt(keyA, ct, ctx + ("purpose" -> "請求")).unsafeRunSync().isLeft shouldBe true
  }

  /** The restore-an-older-backup case: ciphertext written after a rotation, handed to a keystore that only
    * has the earlier generation. It must say so plainly rather than throwing or silently misbehaving.
    */
  test("ciphertext naming a KEK generation the keystore does not have fails with a clear error") {
    val rot = ephemeral
    val ct  = rot.encrypt(keyA, "from-the-future".getBytes, Map.empty).unsafeRunSync().toOption.get

    val res = rot.decrypt(keyA, Ciphertext(withGeneration(ct.bytes, 99)), Map.empty).unsafeRunSync()

    res.left.toOption.get.code shouldBe ErrorCode.CryptographicFailure
    res.left.toOption.get.message should include("no KEK generation v99")
  }

  test("a negative KEK generation in the header is rejected, not used to index anything") {
    val rot = ephemeral
    val ct  = rot.encrypt(keyA, "p".getBytes, Map.empty).unsafeRunSync().toOption.get

    val res = rot.decrypt(keyA, Ciphertext(withGeneration(ct.bytes, -1)), Map.empty).unsafeRunSync()

    res.left.toOption.get.code shouldBe ErrorCode.CryptographicFailure
  }

  test("an envelope of exactly the minimum length but random content fails authentication") {
    val rot  = ephemeral
    val blob = Array.fill(33)(0.toByte)
    blob(0) = 1.toByte // claim format v1, generation 0

    rot.decrypt(keyA, Ciphertext(blob), Map.empty).unsafeRunSync().isLeft shouldBe true
  }

  // ── Wrap / unwrap DEK ──────────────────────────────────────────────────────

  test("wrap then unwrapDek round-trips DEK material") {
    val rot = ephemeral
    val dek = Array.tabulate(32)(i => i.toByte)

    val wrapped = rot.wrap(keyA, dek).unsafeRunSync().toOption.get
    rot.unwrapDek(keyA, wrapped).unsafeRunSync().toOption.get shouldBe dek
  }

  test("a DEK wrapped for one KeyId cannot be unwrapped for another") {
    val rot     = ephemeral
    val wrapped = rot.wrap(keyA, Array.fill(32)(7.toByte)).unsafeRunSync().toOption.get

    rot.unwrapDek(keyB, wrapped).unsafeRunSync().isLeft shouldBe true
  }

  // ── Data keys ──────────────────────────────────────────────────────────────

  test("generateDataKey produces recoverable material and stamps the KEK generation as rotationId") {
    val rot = ephemeral

    val wrapped = rot.generateDataKey(KeySpec.aes256("invoice-2026")).unsafeRunSync().toOption.get
    val raw     = rot.unwrap(wrapped).unsafeRunSync().toOption.get

    wrapped.rotationId shouldBe "kek-v1"
    raw.bytes.length shouldBe 32
  }

  test("generateDataKey honours the requested AES size") {
    val rot        = ephemeral
    val aes128Spec = KeySpec("k", Algorithm.AES, 128, KeyObjectType.SymmetricKey)

    val wrapped = rot.generateDataKey(aes128Spec).unsafeRunSync().toOption.get
    rot.unwrap(wrapped).unsafeRunSync().toOption.get.bytes.length shouldBe 16
  }

  test("a non-AES spec falls back to 256-bit data key material, matching the AWS adapter") {
    val rot = ephemeral

    val wrapped = rot.generateDataKey(KeySpec.rsa2048("signing")).unsafeRunSync().toOption.get
    rot.unwrap(wrapped).unsafeRunSync().toOption.get.bytes.length shouldBe 32
  }

  test("a data key wrapped by one keystore is not recoverable by another") {
    val mine   = ephemeral
    val theirs = ephemeral

    val wrapped = theirs.generateDataKey(KeySpec.aes256("k")).unsafeRunSync().toOption.get
    mine.unwrap(wrapped).unsafeRunSync().isLeft shouldBe true
  }

  test("two generated data keys have different material") {
    val rot = ephemeral

    val first  = rot.generateDataKey(KeySpec.aes256("a")).unsafeRunSync().toOption.get
    val second = rot.generateDataKey(KeySpec.aes256("b")).unsafeRunSync().toOption.get

    val firstRaw  = rot.unwrap(first).unsafeRunSync().toOption.get.bytes
    val secondRaw = rot.unwrap(second).unsafeRunSync().toOption.get.bytes

    firstRaw shouldNot be(secondRaw)
  }

  // ── Sign / verify ──────────────────────────────────────────────────────────

  for alg <- List(SigAlgorithm.EcdsaSha256, SigAlgorithm.RsaPssSha256) do

    test(s"$alg: sign then verify accepts the signature it produced") {
      val rot = ephemeral
      val msg = "audit-record-4711".getBytes("UTF-8")

      val sig = rot.sign(keyA, msg, alg).unsafeRunSync().toOption.get
      sig.algorithm shouldBe alg
      rot.verify(keyA, msg, sig).unsafeRunSync().toOption.get shouldBe true
    }

    test(s"$alg: verify rejects a signature over a different message") {
      val rot = ephemeral

      val sig = rot.sign(keyA, "original".getBytes, alg).unsafeRunSync().toOption.get
      rot.verify(keyA, "tampered".getBytes, sig).unsafeRunSync().toOption.get shouldBe false
    }

    test(s"$alg: verify returns false rather than erroring on a structurally invalid signature") {
      val rot = ephemeral

      val res = rot.verify(keyA, "msg".getBytes, Signature(Array[Byte](1, 2, 3), alg)).unsafeRunSync()

      res shouldBe Right(false)
    }

  test("a signature made by a different keystore does not verify") {
    val signer   = ephemeral
    val verifier = ephemeral
    val msg      = "cross-instance".getBytes("UTF-8")

    val sig = signer.sign(keyA, msg, SigAlgorithm.EcdsaSha256).unsafeRunSync().toOption.get

    verifier.verify(keyA, msg, sig).unsafeRunSync().toOption.get shouldBe false
  }

  test("verify on a keystore that has never signed generates the keypair rather than erroring") {
    val rot = ephemeral

    // No sign() call has happened, so the EC keypair does not exist yet. Verifying must lazily
    // create it and return a clean `false`, not blow up on a missing alias.
    val res = rot.verify(
      keyA,
      "msg".getBytes,
      Signature(Array.fill(70)(0.toByte), SigAlgorithm.EcdsaSha256)
    ).unsafeRunSync()

    res shouldBe Right(false)
  }

  /** Documents a known limitation rather than a desired property.
    *
    * The envelope families derive a distinct AES key per `KeyId`, so ciphertext for key A cannot be opened as
    * key B. Signing has no equivalent separation: one keypair per algorithm serves the whole keystore, so a
    * signature made for key A verifies under key B. `AwsKmsRootOfTrust` behaves the same way (it signs with
    * the single configured CMK regardless of `KeyId`); per-key backing keys are ROADMAP 3.0.e across all
    * adapters. Pinned here so that change fails this test loudly instead of passing unnoticed.
    */
  test("KNOWN LIMITATION: a signature made for one KeyId also verifies under another") {
    val rot = ephemeral
    val msg = "not-key-bound".getBytes("UTF-8")

    val sig = rot.sign(keyA, msg, SigAlgorithm.EcdsaSha256).unsafeRunSync().toOption.get

    rot.verify(keyB, msg, sig).unsafeRunSync().toOption.get shouldBe true
  }

  test("the two signing algorithms use independent keypairs") {
    val rot = ephemeral
    val msg = "cross-algorithm".getBytes("UTF-8")

    val ecdsaSig = rot.sign(keyA, msg, SigAlgorithm.EcdsaSha256).unsafeRunSync().toOption.get

    // Presenting ECDSA bytes as an RSA-PSS signature must not verify.
    val res = rot.verify(keyA, msg, Signature(ecdsaSig.bytes, SigAlgorithm.RsaPssSha256)).unsafeRunSync()

    res.toOption.get shouldBe false
  }

  // ── Rotation ───────────────────────────────────────────────────────────────

  test("rotate mints a new KEK generation without orphaning material wrapped under the old one") {
    val rot       = ephemeral
    val before    = rot.encrypt(keyA, "pre-rotation".getBytes, Map.empty).unsafeRunSync().toOption.get
    val dekBefore = rot.generateDataKey(KeySpec.aes256("k")).unsafeRunSync().toOption.get

    rot.rotate(keyA).unsafeRunSync().isRight shouldBe true

    // Old ciphertext still opens...
    rot.decrypt(keyA, before, Map.empty).unsafeRunSync().toOption.get shouldBe
      "pre-rotation".getBytes("UTF-8")
    rot.unwrap(dekBefore).unsafeRunSync().isRight shouldBe true

    // ...and new writes carry the new generation.
    val after = rot.generateDataKey(KeySpec.aes256("k")).unsafeRunSync().toOption.get
    after.rotationId shouldBe "kek-v2"
    rot.unwrap(after).unsafeRunSync().isRight shouldBe true
  }

  test("repeated rotations keep every earlier generation openable") {
    val rot = ephemeral

    val v1 = rot.encrypt(keyA, "gen-1".getBytes, Map.empty).unsafeRunSync().toOption.get
    rot.rotate(keyA).unsafeRunSync()
    val v2 = rot.encrypt(keyA, "gen-2".getBytes, Map.empty).unsafeRunSync().toOption.get
    rot.rotate(keyA).unsafeRunSync()
    val v3 = rot.encrypt(keyA, "gen-3".getBytes, Map.empty).unsafeRunSync().toOption.get

    rot.generateDataKey(KeySpec.aes256("k")).unsafeRunSync().toOption.get.rotationId shouldBe "kek-v3"
    rot.decrypt(keyA, v1, Map.empty).unsafeRunSync().toOption.get shouldBe "gen-1".getBytes("UTF-8")
    rot.decrypt(keyA, v2, Map.empty).unsafeRunSync().toOption.get shouldBe "gen-2".getBytes("UTF-8")
    rot.decrypt(keyA, v3, Map.empty).unsafeRunSync().toOption.get shouldBe "gen-3".getBytes("UTF-8")
  }

  // ── Concurrency ────────────────────────────────────────────────────────────

  test("concurrent encrypt/decrypt round-trips are all correct") {
    val rot = ephemeral

    val results = (1 to 64).toList
      .parTraverse { i =>
        val payload = s"payload-$i".getBytes("UTF-8")
        for
          ct    <- rot.encrypt(keyA, payload, Map("n" -> i.toString))
          plain <- rot.decrypt(keyA, ct.toOption.get, Map("n" -> i.toString))
        yield plain.toOption.get.sameElements(payload)
      }
      .unsafeRunSync()

    results.count(identity) shouldBe 64
  }

  test("rotating while encrypts are in flight never orphans a ciphertext") {
    val rot = ephemeral

    // Rotation only ever *adds* a generation, so an encrypt that read generation N before a
    // concurrent rotation can still resolve N afterwards. Interleave the two and decrypt everything.
    val work = (1 to 32).toList.parTraverse { i =>
      for
        _  <- IO.whenA(i % 8 == 0)(rot.rotate(keyA).void)
        ct <- rot.encrypt(keyA, s"p-$i".getBytes("UTF-8"), Map.empty)
      yield ct.toOption.get
    }

    val cts      = work.unsafeRunSync()
    val reopened = cts.parTraverse(ct => rot.decrypt(keyA, ct, Map.empty)).unsafeRunSync()

    reopened.count(_.isRight) shouldBe 32
  }

  test("concurrent first-time signs converge on one keypair") {
    val rot = ephemeral
    val msg = "concurrent-sign".getBytes("UTF-8")

    // Every signature is produced by a racing lazy-init of the same alias; each must verify
    // against the single keypair that ended up persisted.
    val sigs = (1 to 16).toList
      .parTraverse(_ => rot.sign(keyA, msg, SigAlgorithm.EcdsaSha256))
      .unsafeRunSync()
      .map(_.toOption.get)

    val verdicts = sigs.parTraverse(sig => rot.verify(keyA, msg, sig)).unsafeRunSync()
    verdicts.forall(_ == Right(true)) shouldBe true
  }

  test("ciphertext from a foreign keystore does not decrypt") {
    val mine   = ephemeral
    val theirs = ephemeral
    val ct     = theirs.encrypt(keyA, "not-yours".getBytes, Map.empty).unsafeRunSync().toOption.get

    mine.decrypt(keyA, ct, Map.empty).unsafeRunSync().isLeft shouldBe true
  }

  // ── Persistence ────────────────────────────────────────────────────────────

  test("a file-backed keystore survives a restart — key material outlives the process") {
    withTempKeystore { path =>
      val payload = "durable".getBytes("UTF-8")

      val first = SoftwareRootOfTrust.withKeyStore(SoftwareKeyStore.atPath(path, "correct horse"))
      val ct    = first.encrypt(keyA, payload, Map.empty).unsafeRunSync().toOption.get
      val sig   = first.sign(keyA, payload, SigAlgorithm.EcdsaSha256).unsafeRunSync().toOption.get

      // Fresh instance over the same file — as if the server had restarted.
      val second = SoftwareRootOfTrust.withKeyStore(SoftwareKeyStore.atPath(path, "correct horse"))

      second.decrypt(keyA, ct, Map.empty).unsafeRunSync().toOption.get shouldBe payload
      second.verify(keyA, payload, sig).unsafeRunSync().toOption.get shouldBe true
    }
  }

  test("a rotation performed by one instance is visible to the next") {
    withTempKeystore { path =>
      val first = SoftwareRootOfTrust.withKeyStore(SoftwareKeyStore.atPath(path, "pw"))
      val ct    = first.encrypt(keyA, "pre".getBytes, Map.empty).unsafeRunSync().toOption.get
      first.rotate(keyA).unsafeRunSync()

      val second = SoftwareRootOfTrust.withKeyStore(SoftwareKeyStore.atPath(path, "pw"))

      second.generateDataKey(KeySpec.aes256("k")).unsafeRunSync().toOption.get.rotationId shouldBe "kek-v2"
      second.decrypt(keyA, ct, Map.empty).unsafeRunSync().isRight shouldBe true
    }
  }

  test("opening a keystore with the wrong password fails loudly") {
    withTempKeystore { path =>
      SoftwareKeyStore.atPath(path, "right")
      an[Exception] should be thrownBy SoftwareKeyStore.atPath(path, "wrong")
    }
  }

  test("fromConfig with a path creates the keystore file; without one it stays in the heap") {
    withTempKeystore { path =>
      SoftwareRootOfTrust.fromConfig(SoftwareRootOfTrust.Config(Some(path), "pw"))
      Files.exists(path) shouldBe true
    }

    val ephemeralRot = SoftwareRootOfTrust.fromConfig(SoftwareRootOfTrust.Config(None, ""))
    ephemeralRot.encrypt(keyA, "x".getBytes, Map.empty).unsafeRunSync().isRight shouldBe true
  }

  test("fromConfig rejects a file-backed keystore with no password") {
    withTempKeystore { path =>
      an[IllegalArgumentException] should be thrownBy
        SoftwareRootOfTrust.fromConfig(SoftwareRootOfTrust.Config(Some(path), ""))
    }
  }

  /** Rewrite the 4-byte KEK-generation field in an envelope header, leaving everything else intact. Lets the
    * tests present a structurally valid envelope that names a generation the keystore cannot resolve.
    */
  private def withGeneration(blob: Array[Byte], generation: Int): Array[Byte] =
    val out = blob.clone()
    java.nio.ByteBuffer.wrap(out, 1, 4).putInt(generation)
    out

  private def withTempKeystore(f: Path => Any): Unit =
    val dir = Files.createTempDirectory("aegis-software-rot")
    try
      f(dir.resolve("aegis.p12"))
      ()
    finally
      Files.walk(dir).sorted(java.util.Comparator.reverseOrder()).forEach(Files.deleteIfExists(_))
