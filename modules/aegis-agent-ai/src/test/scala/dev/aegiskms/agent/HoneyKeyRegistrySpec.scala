package dev.aegiskms.agent

import dev.aegiskms.core.KeyId
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Unit tests for `HoneyKeyRegistry` (#26). The SPI is small — `isHoney` + `snapshot` — but load-bearing: a
  * regression that returns `false` for every KeyId silently disables the canary detection, which is the
  * entire point of the feature. These tests pin the contract.
  */
final class HoneyKeyRegistrySpec extends AnyFunSuite with Matchers:

  private val k1: KeyId = KeyId.fromString("k-canary-1").toOption.get
  private val k2: KeyId = KeyId.fromString("k-canary-2").toOption.get
  private val k3: KeyId = KeyId.fromString("k-real-3").toOption.get

  test("empty: isHoney returns false for every KeyId; snapshot is empty") {
    HoneyKeyRegistry.empty.isHoney(k1) shouldBe false
    HoneyKeyRegistry.empty.isHoney(k2) shouldBe false
    HoneyKeyRegistry.empty.snapshot shouldBe empty
  }

  test("fromSet: isHoney returns true for registered ids, false for unregistered") {
    val reg = HoneyKeyRegistry.fromSet(Set(k1, k2))
    reg.isHoney(k1) shouldBe true
    reg.isHoney(k2) shouldBe true
    reg.isHoney(k3) shouldBe false
  }

  test("fromSet: snapshot returns the exact set passed in (no reordering or duplication)") {
    val ids = Set(k1, k2)
    HoneyKeyRegistry.fromSet(ids).snapshot shouldBe ids
  }

  test("fromSet(Set.empty) is equivalent to empty (no honey keys registered)") {
    val reg = HoneyKeyRegistry.fromSet(Set.empty)
    reg.isHoney(k1) shouldBe false
    reg.snapshot shouldBe empty
  }
