package dev.aegiskms.app

import cats.effect.unsafe.implicits.global
import dev.aegiskms.core.*
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Tests `MeteredKeyService` against a `SimpleMeterRegistry` (in-memory, no Prometheus dep) so the counter /
  * timer / error-counter contract can be asserted without scraping HTTP.
  */
final class MeteredKeyServiceSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def fixture(): (MeteredKeyService, SimpleMeterRegistry) =
    val registry = new SimpleMeterRegistry()
    val inner    = KeyService.inMemory.unsafeRunSync()
    (new MeteredKeyService(inner, registry), registry)

  /** Micrometer's `Search.tags(String*)` is a Java varargs of alternating key/value strings (`"operation",
    * "Sign", "outcome", "success"`). The helper flattens our pair-typed arg list into that shape and forwards
    * to the right overload via `: _*`.
    */
  private def counterValue(registry: SimpleMeterRegistry, name: String, tags: (String, String)*): Double =
    val flat    = tags.flatMap((k, v) => List(k, v))
    val counter = registry.find(name).tags(flat*).counter()
    if counter == null then 0.0 else counter.count()

  private def timerCount(registry: SimpleMeterRegistry, name: String, tags: (String, String)*): Long =
    val flat  = tags.flatMap((k, v) => List(k, v))
    val timer = registry.find(name).tags(flat*).timer()
    if timer == null then 0L else timer.count()

  test("a successful create increments the per-op counter and records one timer sample") {
    val (svc, registry) = fixture()
    svc.create(KeySpec.aes256("k"), alice).unsafeRunSync()

    counterValue(registry, "aegis_keys_op_total", "operation" -> "Create") shouldBe 1.0
    timerCount(
      registry,
      "aegis_keys_op_duration_seconds",
      "operation" -> "Create",
      "outcome"   -> "success"
    ) shouldBe 1L
    counterValue(registry, "aegis_keys_op_errors_total", "operation" -> "Create") shouldBe 0.0
  }

  test("a failing call (sign on a PreActive key) increments the error counter tagged by code") {
    val (svc, registry) = fixture()
    val created         = svc.create(KeySpec.rsa2048("k"), alice).unsafeRunSync().toOption.get
    // skip activate so sign returns IllegalOperation
    svc.sign(created.id, "x".getBytes, SigAlgorithm.RsaPssSha256, alice).unsafeRunSync()

    counterValue(registry, "aegis_keys_op_total", "operation" -> "Sign") shouldBe 1.0
    timerCount(
      registry,
      "aegis_keys_op_duration_seconds",
      "operation" -> "Sign",
      "outcome"   -> "failure"
    ) shouldBe 1L
    counterValue(
      registry,
      "aegis_keys_op_errors_total",
      "operation" -> "Sign",
      "code"      -> "IllegalOperation"
    ) shouldBe 1.0
  }

  test("multiple calls accumulate on the same counter rather than fragmenting tags") {
    val (svc, registry) = fixture()
    val k               = svc.create(KeySpec.aes256("k"), alice).unsafeRunSync().toOption.get
    svc.activate(k.id, alice).unsafeRunSync()
    svc.activate(k.id, alice).unsafeRunSync() // redundant, still counted

    counterValue(registry, "aegis_keys_op_total", "operation" -> "Activate") shouldBe 2.0
  }

  test("locate is timed even though it doesn't return Either") {
    val (svc, registry) = fixture()
    svc.locate("nope", alice).unsafeRunSync() shouldBe Nil

    counterValue(registry, "aegis_keys_op_total", "operation" -> "Locate") shouldBe 1.0
    timerCount(
      registry,
      "aegis_keys_op_duration_seconds",
      "operation" -> "Locate",
      "outcome"   -> "success"
    ) shouldBe 1L
  }

  test("each new (operation, outcome) pair gets its own timer instance") {
    val (svc, registry) = fixture()
    val k               = svc.create(KeySpec.rsa2048("k"), alice).unsafeRunSync().toOption.get
    svc.activate(k.id, alice).unsafeRunSync()
    svc.sign(k.id, "x".getBytes, SigAlgorithm.RsaPssSha256, alice).unsafeRunSync() // success

    val unknown = KeyId.generate()
    svc.sign(unknown, "x".getBytes, SigAlgorithm.RsaPssSha256, alice).unsafeRunSync() // failure (ItemNotFound)

    timerCount(
      registry,
      "aegis_keys_op_duration_seconds",
      "operation" -> "Sign",
      "outcome"   -> "success"
    ) shouldBe 1L
    timerCount(
      registry,
      "aegis_keys_op_duration_seconds",
      "operation" -> "Sign",
      "outcome"   -> "failure"
    ) shouldBe 1L
  }
