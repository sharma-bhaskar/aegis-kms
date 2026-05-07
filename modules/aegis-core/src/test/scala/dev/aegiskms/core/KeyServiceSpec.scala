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
