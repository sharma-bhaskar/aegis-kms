package dev.aegiskms.core

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Compiles + runs the embedded-library snippet from `README.md` so that example can never silently bitrot.
  *
  * If you change the README's "Quickstart — embedding as a library" Scala block, mirror the change here. The
  * body is intentionally identical to what users will copy/paste, minus the `IOApp.Simple` wrapper which is
  * replaced with a direct `unsafeRunSync()` for test execution.
  */
final class ReadmeQuickstartSpec extends AnyFunSuite with Matchers:

  test("README library-embedding example compiles and runs end-to-end") {
    val alice: Principal.Human = Principal.Human("alice", Set("admins"))

    val program: IO[ManagedKey] =
      for
        keys    <- KeyService.inMemory
        created <- keys.create(KeySpec.aes256("invoice-signing"), alice)
        key     <- IO.fromEither(created.left.map(e => RuntimeException(e.message)))
        got     <- keys.get(key.id, alice)
        result  <- IO.fromEither(got.left.map(e => RuntimeException(e.message)))
      yield result

    val result = program.unsafeRunSync()
    result.spec.name shouldBe "invoice-signing"
    result.spec.algorithm shouldBe Algorithm.AES
    result.spec.sizeBits shouldBe 256
    result.owner shouldBe alice
  }
