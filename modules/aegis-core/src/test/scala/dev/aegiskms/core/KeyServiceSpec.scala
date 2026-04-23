package dev.aegiskms.core

import cats.effect.IO
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
      id       = created.toOption.get.id
      _       <- svc.activate(id, alice)
      got     <- svc.get(id, alice)
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
      id       = created.toOption.get.id
      _       <- svc.destroy(id, alice)
      got     <- svc.get(id, alice)
    yield got).unsafeRunSync()

    after.isLeft shouldBe true
    after.swap.toOption.get.code shouldBe ErrorCode.ItemNotFound
  }
