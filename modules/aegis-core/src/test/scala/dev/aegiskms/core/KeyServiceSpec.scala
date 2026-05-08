package dev.aegiskms.core

import cats.effect.unsafe.implicits.global
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

final class KeyServiceSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice", Set("admins"))

  test("create then get round-trips a key") {
    val result = (for
      svc     <- KeyService.inMemory
      created <- svc.create(KeySpec.aes256("invoice-signing"), alice)
      fetched <- svc.get(created.toOption.get.id, alice)
    yield (created, fetched)).unsafeRunSync()

    result._1.isRight shouldBe true
    result._2.isRight shouldBe true
    result._2.toOption.get.spec.name shouldBe "invoice-signing"
    result._2.toOption.get.state shouldBe KeyState.PreActive
  }

  test("activate transitions PreActive -> Active") {
    val state = (for
      svc     <- KeyService.inMemory
      created <- svc.create(KeySpec.aes256("rotate-me"), alice)
      id = created.toOption.get.id
      _   <- svc.activate(id, alice)
      got <- svc.get(id, alice)
    yield got.toOption.get.state).unsafeRunSync()

    state shouldBe KeyState.Active
  }

  test("get of an unknown key returns ItemNotFound") {
    val err = (for
      svc <- KeyService.inMemory
      got <- svc.get(KeyId.generate(), alice)
    yield got).unsafeRunSync()

    err.isLeft shouldBe true
    err.swap.toOption.get.code shouldBe ErrorCode.ItemNotFound
  }

  test("destroy removes the key") {
    val after = (for
      svc     <- KeyService.inMemory
      created <- svc.create(KeySpec.aes256("ephemeral"), alice)
      id = created.toOption.get.id
      _   <- svc.destroy(id, alice)
      got <- svc.get(id, alice)
    yield got).unsafeRunSync()

    after.isLeft shouldBe true
    after.swap.toOption.get.code shouldBe ErrorCode.ItemNotFound
  }

  test("sign then verify round-trips for any byte payload (deterministic dev impl)") {
    val payloads = List(
      Array.emptyByteArray,
      "hello".getBytes("UTF-8"),
      Array.tabulate(1024)(i => (i % 256).toByte),
      "🔐 unicode 🔑".getBytes("UTF-8")
    )

    payloads.foreach { msg =>
      val ok = (for
        svc     <- KeyService.inMemory
        created <- svc.create(KeySpec.rsa2048("sig-key"), alice)
        id = created.toOption.get.id
        _      <- svc.activate(id, alice)
        signed <- svc.sign(id, msg, SigAlgorithm.RsaPssSha256, alice)
        sig = signed.toOption.get
        valid <- svc.verify(id, msg, sig, alice)
      yield valid).unsafeRunSync()

      ok.isRight shouldBe true
      ok.toOption.get shouldBe true
    }
  }

  test("verify returns Right(false) when the message is tampered with") {
    val result = (for
      svc     <- KeyService.inMemory
      created <- svc.create(KeySpec.rsa2048("tamper-test"), alice)
      id = created.toOption.get.id
      _      <- svc.activate(id, alice)
      signed <- svc.sign(id, "original".getBytes, SigAlgorithm.RsaPssSha256, alice)
      sig = signed.toOption.get
      tampered <- svc.verify(id, "tampered".getBytes, sig, alice)
    yield tampered).unsafeRunSync()

    result.isRight shouldBe true
    result.toOption.get shouldBe false
  }

  test("sign on a PreActive key returns IllegalOperation") {
    val result = (for
      svc     <- KeyService.inMemory
      created <- svc.create(KeySpec.rsa2048("not-yet-active"), alice)
      id = created.toOption.get.id
      // Deliberately do NOT activate.
      signed <- svc.sign(id, "data".getBytes, SigAlgorithm.RsaPssSha256, alice)
    yield signed).unsafeRunSync()

    result.isLeft shouldBe true
    result.swap.toOption.get.code shouldBe ErrorCode.IllegalOperation
  }

  test("sign on an unknown key returns ItemNotFound") {
    val result = (for
      svc    <- KeyService.inMemory
      signed <- svc.sign(KeyId.generate(), "data".getBytes, SigAlgorithm.RsaPssSha256, alice)
    yield signed).unsafeRunSync()

    result.isLeft shouldBe true
    result.swap.toOption.get.code shouldBe ErrorCode.ItemNotFound
  }

  test("encrypt then decrypt round-trips with the same context") {
    val ctx       = Map("dataset" -> "invoices-q2", "tenant" -> "acme")
    val plaintext = "secret invoice payload".getBytes("UTF-8")

    val opened = (for
      svc     <- KeyService.inMemory
      created <- svc.create(KeySpec.aes256("enc-key"), alice)
      id = created.toOption.get.id
      _  <- svc.activate(id, alice)
      ct <- svc.encrypt(id, plaintext, ctx, alice)
      ctv = ct.toOption.get
      pt <- svc.decrypt(id, ctv, ctx, alice)
    yield pt).unsafeRunSync()

    opened.isRight shouldBe true
    opened.toOption.get shouldBe plaintext
  }

  test("decrypt with a different context returns CryptographicFailure") {
    val opened = (for
      svc     <- KeyService.inMemory
      created <- svc.create(KeySpec.aes256("enc-key"), alice)
      id = created.toOption.get.id
      _  <- svc.activate(id, alice)
      ct <- svc.encrypt(id, "hi".getBytes, Map("a" -> "1"), alice)
      ctv = ct.toOption.get
      pt <- svc.decrypt(id, ctv, Map("a" -> "2"), alice)
    yield pt).unsafeRunSync()

    opened.isLeft shouldBe true
    opened.swap.toOption.get.code shouldBe ErrorCode.CryptographicFailure
  }

  test("encrypt on a PreActive key returns IllegalOperation") {
    val result = (for
      svc     <- KeyService.inMemory
      created <- svc.create(KeySpec.aes256("not-yet-active"), alice)
      id = created.toOption.get.id
      ct <- svc.encrypt(id, "data".getBytes, Map.empty, alice)
    yield ct).unsafeRunSync()

    result.isLeft shouldBe true
    result.swap.toOption.get.code shouldBe ErrorCode.IllegalOperation
  }

  test("decrypt is permitted on a Deactivated key (existing ciphertexts stay readable)") {
    val opened = (for
      svc     <- KeyService.inMemory
      created <- svc.create(KeySpec.aes256("deact"), alice)
      id = created.toOption.get.id
      _  <- svc.activate(id, alice)
      ct <- svc.encrypt(id, "rev".getBytes, Map.empty, alice)
      ctv = ct.toOption.get
      _  <- svc.revoke(id, alice)
      pt <- svc.decrypt(id, ctv, Map.empty, alice)
    yield pt).unsafeRunSync()

    opened.isRight shouldBe true
    new String(opened.toOption.get, "UTF-8") shouldBe "rev"
  }

  test("wrap then unwrap round-trips the DEK bytes") {
    val dek = Array.tabulate(32)(i => (i * 13 + 7).toByte) // representative 32-byte DEK

    val recovered = (for
      svc     <- KeyService.inMemory
      created <- svc.create(KeySpec.aes256("kek"), alice)
      id = created.toOption.get.id
      _ <- svc.activate(id, alice)
      w <- svc.wrap(id, dek, alice)
      wv = w.toOption.get
      out <- svc.unwrap(id, wv, alice)
    yield out).unsafeRunSync()

    recovered.isRight shouldBe true
    recovered.toOption.get shouldBe dek
  }

  test("wrap on a PreActive key returns IllegalOperation") {
    val result = (for
      svc     <- KeyService.inMemory
      created <- svc.create(KeySpec.aes256("not-yet-active"), alice)
      id = created.toOption.get.id
      w <- svc.wrap(id, "dek".getBytes, alice)
    yield w).unsafeRunSync()

    result.isLeft shouldBe true
    result.swap.toOption.get.code shouldBe ErrorCode.IllegalOperation
  }

  test("unwrap is permitted on a Deactivated key (existing wrapped DEKs stay recoverable)") {
    val recovered = (for
      svc     <- KeyService.inMemory
      created <- svc.create(KeySpec.aes256("deact-kek"), alice)
      id = created.toOption.get.id
      _ <- svc.activate(id, alice)
      w <- svc.wrap(id, "dek-bytes".getBytes, alice)
      wv = w.toOption.get
      _   <- svc.revoke(id, alice)
      out <- svc.unwrap(id, wv, alice)
    yield out).unsafeRunSync()

    recovered.isRight shouldBe true
    new String(recovered.toOption.get, "UTF-8") shouldBe "dek-bytes"
  }
