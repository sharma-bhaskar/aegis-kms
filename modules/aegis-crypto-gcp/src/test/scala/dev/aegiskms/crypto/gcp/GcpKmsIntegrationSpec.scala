package dev.aegiskms.crypto.gcp

import cats.effect.unsafe.implicits.global
import dev.aegiskms.core.{KeyId, KeySpec, SigAlgorithm}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Integration tests against a **real** Google Cloud KMS project.
  *
  * `GcpKmsRootOfTrustSpec` proves the adapter's contract against a stub, which is the right tool for logic
  * but can only ever confirm the adapter agrees with my model of Cloud KMS. This suite is what confirms the
  * model itself — that `GenerateRandomBytes` accepts the location format we build, that AAD binding behaves
  * the way the stub pretends, and that a signature Cloud KMS produces verifies against the public key it
  * hands back.
  *
  * **Skips cleanly when unconfigured**, the same way the Testcontainers suites skip without Docker, so `sbt
  * test` stays green on a workstation with no GCP project. To run it:
  *
  * {{{
  *   export AEGIS_IT_GCP_PROJECT=my-project
  *   export AEGIS_IT_GCP_LOCATION=europe-west2
  *   export AEGIS_IT_GCP_KEY_RING=aegis-it
  *   export AEGIS_IT_GCP_CRYPTO_KEY=aegis-it-kek        # purpose: ENCRYPT_DECRYPT
  *   export AEGIS_IT_GCP_SIGNING_KEY=aegis-it-signer    # optional; purpose: ASYMMETRIC_SIGN, EC_SIGN_P256_SHA256
  *   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
  *   sbt "cryptoGcp / testOnly *GcpKmsIntegrationSpec"
  * }}}
  *
  * The service account needs `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the encryption key, plus
  * `roles/cloudkms.signerVerifier` and `cloudkms.cryptoKeyVersions.viewPublicKey` on the signing key.
  *
  * Deliberately **not** exercising `rotate`: it creates a new CryptoKeyVersion on every run, and
  * CryptoKeyVersions cannot be deleted — only scheduled for destruction — so a test that rotated would
  * accumulate unbounded state in a real project. That path stays stub-covered.
  */
final class GcpKmsIntegrationSpec extends AnyFunSuite with Matchers:

  private def env(name: String): Option[String] =
    sys.env.get(name).map(_.trim).filter(_.nonEmpty)

  private val configOpt: Option[GcpKmsRootOfTrust.Config] =
    for
      project  <- env("AEGIS_IT_GCP_PROJECT")
      location <- env("AEGIS_IT_GCP_LOCATION")
      keyRing  <- env("AEGIS_IT_GCP_KEY_RING")
      key      <- env("AEGIS_IT_GCP_CRYPTO_KEY")
    yield GcpKmsRootOfTrust.Config(
      projectId = project,
      location = location,
      keyRing = keyRing,
      cryptoKey = key,
      signingKey = env("AEGIS_IT_GCP_SIGNING_KEY"),
      signingKeyVersion = env("AEGIS_IT_GCP_SIGNING_KEY_VERSION").getOrElse("1")
    )

  private val skipReason =
    "AEGIS_IT_GCP_* not set; skipping GCP Cloud KMS integration test " +
      "(see the scaladoc on this suite for the required environment)"

  /** Runs `body` against a live adapter, or skips. The client is Resource-managed, so its gRPC channels are
    * released even when an assertion fails mid-test.
    */
  private def withGcp(body: GcpKmsRootOfTrust => Unit): Unit =
    assume(configOpt.isDefined, skipReason)
    GcpKmsRootOfTrust.resource(configOpt.get).use(rot => cats.effect.IO(body(rot))).unsafeRunSync()

  private val keyA = KeyId.fromString("integration-key-a").toOption.get
  private val keyB = KeyId.fromString("integration-key-b").toOption.get

  test("encrypt then decrypt round-trips against real Cloud KMS") {
    withGcp { rot =>
      val payload = "invoice-2026-total: 4711.00".getBytes("UTF-8")
      val ctx     = Map("tenant" -> "acme", "purpose" -> "billing")

      val ct = rot.encrypt(keyA, payload, ctx).unsafeRunSync().toOption.get
      new String(ct.bytes, "ISO-8859-1") should not include "invoice-2026"

      rot.decrypt(keyA, ct, ctx).unsafeRunSync().toOption.get shouldBe payload
    }
  }

  test("the encryption context really is bound as AAD — a mismatch fails at the service") {
    withGcp { rot =>
      val ct = rot.encrypt(keyA, "p".getBytes, Map("tenant" -> "acme")).unsafeRunSync().toOption.get

      rot.decrypt(keyA, ct, Map("tenant" -> "evil-corp")).unsafeRunSync().isLeft shouldBe true
    }
  }

  test("generateDataKey returns recoverable material of the requested size") {
    withGcp { rot =>
      val wrapped = rot.generateDataKey(KeySpec.aes256("integration")).unsafeRunSync().toOption.get
      val raw     = rot.unwrap(wrapped).unsafeRunSync().toOption.get

      raw.bytes.length shouldBe 32
      // Two calls must not return the same material — this is the HSM RNG, not a constant.
      val second = rot.generateDataKey(KeySpec.aes256("integration")).unsafeRunSync().toOption.get
      rot.unwrap(second).unsafeRunSync().toOption.get.bytes shouldNot be(raw.bytes)
    }
  }

  test("wrap then unwrapDek round-trips DEK material") {
    withGcp { rot =>
      val dek     = Array.tabulate(32)(i => (i * 7).toByte)
      val wrapped = rot.wrap(keyA, dek).unsafeRunSync().toOption.get

      rot.unwrapDek(keyA, wrapped).unsafeRunSync().toOption.get shouldBe dek
    }
  }

  test("the KeyId does not scope Cloud KMS ciphertext — a documented limitation, pinned here") {
    withGcp { rot =>
      // Unlike the software backend, which derives a per-KeyId subkey, every Aegis key maps to the same
      // Cloud KMS CryptoKey. Ciphertext therefore crosses KeyIds. Per-key routing is ROADMAP 3.0.e;
      // this test exists so that change is noticed rather than assumed.
      val ct = rot.encrypt(keyA, "cross-key".getBytes, Map.empty).unsafeRunSync().toOption.get

      rot.decrypt(keyB, ct, Map.empty).unsafeRunSync().toOption.get shouldBe "cross-key".getBytes
    }
  }

  test("a signature Cloud KMS produces verifies against the public key it returns") {
    assume(configOpt.exists(_.signingKey.isDefined), "AEGIS_IT_GCP_SIGNING_KEY not set; skipping")
    withGcp { rot =>
      val msg = "audit-record-4711".getBytes("UTF-8")

      val sig = rot.sign(keyA, msg, SigAlgorithm.EcdsaSha256).unsafeRunSync().toOption.get
      rot.verify(keyA, msg, sig).unsafeRunSync().toOption.get shouldBe true
      rot.verify(keyA, "tampered".getBytes, sig).unsafeRunSync().toOption.get shouldBe false
    }
  }

  test("an oversized plaintext is refused locally, before the request leaves the process") {
    withGcp { rot =>
      val big = new Array[Byte](GcpKmsRootOfTrust.MaxPlaintextBytes + 1)

      val res = rot.encrypt(keyA, big, Map.empty).unsafeRunSync()
      res.isLeft shouldBe true
      res.left.toOption.get.message should include("65536")
    }
  }
