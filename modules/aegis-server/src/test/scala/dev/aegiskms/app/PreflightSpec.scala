package dev.aegiskms.app

import cats.effect.unsafe.implicits.global
import com.typesafe.config.{Config, ConfigFactory}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Unit tests for the production preflight. Mirrors `PolicyEngineResourceSpec`'s shape: drive each branch of
  * the config cross-check, including the enforce-mode abort a misconfigured production deployment must hit at
  * boot.
  */
final class PreflightSpec extends AnyFunSuite with Matchers:

  private def cfg(hocon: String): Config =
    ConfigFactory.parseString(hocon).withFallback(ConfigFactory.load())

  /** Every dev-grade default replaced with its production-shaped counterpart. */
  private val hardened = """
    aegis.auth.kind                = "hmac"
    aegis.auth.hmac.secret         = "0123456789abcdef0123456789abcdef"
    aegis.policy.kind              = "role-based"
    aegis.crypto.kind              = "aws-kms"
    aegis.persistence.journal.kind = "postgres"
  """

  test("isLoopback accepts localhost / 127.x / ::1 and rejects wildcards + public addresses") {
    Preflight.isLoopback("localhost") shouldBe true
    Preflight.isLoopback("127.0.0.1") shouldBe true
    Preflight.isLoopback("127.0.1.5") shouldBe true
    Preflight.isLoopback("::1") shouldBe true
    Preflight.isLoopback("0.0.0.0") shouldBe false
    Preflight.isLoopback("::") shouldBe false
    Preflight.isLoopback("10.1.2.3") shouldBe false
    Preflight.isLoopback("aegis.example.com") shouldBe false
  }

  test("the stock application.conf defaults produce all four dev-grade findings") {
    val found = Preflight.findings(cfg("")).map(_.path)
    found should contain allOf (
      "aegis.auth.kind",
      "aegis.policy.kind",
      "aegis.crypto.kind",
      "aegis.persistence.journal.kind"
    )
  }

  test("a hardened config produces no findings") {
    Preflight.findings(cfg(hardened)) shouldBe empty
  }

  test("the software root-of-trust is still a finding — real crypto, but keys in the server's heap") {
    val found  = Preflight.findings(cfg("""aegis.crypto.kind = "software" """))
    val crypto = found.find(_.path == "aegis.crypto.kind")
    crypto.map(_.value) shouldBe Some("software")
    crypto.map(_.risk).getOrElse("") should include("heap")
  }

  test("swapping in-memory crypto for software does not clear the other findings") {
    val hocon = """
      aegis.auth.kind                = "hmac"
      aegis.auth.hmac.secret         = "0123456789abcdef0123456789abcdef"
      aegis.policy.kind              = "role-based"
      aegis.crypto.kind              = "software"
      aegis.persistence.journal.kind = "postgres"
    """
    Preflight.findings(cfg(hocon)).map(_.path) shouldBe List("aegis.crypto.kind")
  }

  test("warn mode (the default) lets the dev defaults boot on 0.0.0.0") {
    noException should be thrownBy Preflight.run(cfg("")).unsafeRunSync()
  }

  test("enforce mode aborts the boot when dev-grade settings bind a non-loopback address") {
    val ex = intercept[IllegalStateException] {
      Preflight.run(cfg("""aegis.security.preflight = "enforce" """)).unsafeRunSync()
    }
    ex.getMessage should include("refusing to bind 0.0.0.0")
    ex.getMessage should include("aegis.auth.kind=dev")
  }

  test("enforce mode passes on a loopback bind even with dev-grade settings") {
    val hocon = """
      aegis.security.preflight = "enforce"
      aegis.http.host          = "127.0.0.1"
    """
    noException should be thrownBy Preflight.run(cfg(hocon)).unsafeRunSync()
  }

  test("enforce mode passes on 0.0.0.0 once the config is hardened") {
    val hocon = s"""
      aegis.security.preflight = "enforce"
      $hardened
    """
    noException should be thrownBy Preflight.run(cfg(hocon)).unsafeRunSync()
  }

  test("an unknown preflight mode fails fast, matching the other aegis.*.kind selectors") {
    val ex = intercept[IllegalArgumentException] {
      Preflight.run(cfg("""aegis.security.preflight = "audit" """)).unsafeRunSync()
    }
    ex.getMessage should include("Unknown aegis.security.preflight=audit")
  }
