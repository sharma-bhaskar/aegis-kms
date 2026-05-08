package dev.aegiskms.core

import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import scala.concurrent.duration.*

/** Round-trips `RotationPolicy.render` ↔ `RotationPolicy.fromString` for every variant. The wire-format
  * string ends up in audit rows and CLI output, so the parser and renderer must agree.
  */
final class RotationPolicySpec extends AnyFunSuite with Matchers:

  test("Manual round-trips through render / fromString") {
    val p = RotationPolicy.Manual
    RotationPolicy.fromString(p.render) shouldBe Right(p)
  }

  test("TimeBased round-trips and renders without spaces") {
    val p = RotationPolicy.TimeBased(7.days)
    p.render should not include " "
    RotationPolicy.fromString(p.render) shouldBe Right(p)
  }

  test("OpCountBased round-trips") {
    val p = RotationPolicy.OpCountBased(10000L)
    p.render shouldBe "OpCountBased:10000"
    RotationPolicy.fromString(p.render) shouldBe Right(p)
  }

  test("fromString rejects an unknown policy name with a clear error") {
    val r = RotationPolicy.fromString("Whatever")
    r.isLeft shouldBe true
    r.swap.toOption.get should include("Whatever")
  }

  test("fromString rejects a malformed TimeBased duration") {
    val r = RotationPolicy.fromString("TimeBased:not-a-duration")
    r.isLeft shouldBe true
    r.swap.toOption.get should include("TimeBased")
  }

  test("fromString rejects a malformed OpCountBased count") {
    val r = RotationPolicy.fromString("OpCountBased:abc")
    r.isLeft shouldBe true
    r.swap.toOption.get should include("OpCountBased")
  }
