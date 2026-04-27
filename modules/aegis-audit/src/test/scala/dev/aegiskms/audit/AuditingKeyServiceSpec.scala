package dev.aegiskms.audit

import cats.effect.unsafe.implicits.global
import dev.aegiskms.core.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Tests `AuditingKeyService` against an `InMemoryAuditSink`.
  *
  * The decorator wraps the in-memory `KeyService` from `aegis-core` so we exercise the full chain: REST shape
  * → service algebra → audit sink. Failures are required to produce records too — that's how the "Claude
  * attempted to sign with treasury-master" line shows up in `aegis audit`.
  */
final class AuditingKeyServiceSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def fixture(): (AuditingKeyService, InMemoryAuditSink) =
    val sink  = InMemoryAuditSink.make.unsafeRunSync()
    val inner = KeyService.inMemory.unsafeRunSync()
    val audit = AuditingKeyService(inner, sink)
    (audit, sink)

  test("create writes a single Success audit record") {
    val (svc, sink) = fixture()

    svc.create(KeySpec.aes256("invoice-signing"), alice).unsafeRunSync()

    val records = sink.all.unsafeRunSync()
    records.size shouldBe 1
    records.head.operation shouldBe Operation.Create
    records.head.principal shouldBe alice
    records.head.outcome should startWith("Success")
    records.head.resource should include("invoice-signing")
  }

  test("get of an unknown key writes a Failed record with the error code") {
    val (svc, sink) = fixture()

    val unknown = KeyId.generate()
    svc.get(unknown, alice).unsafeRunSync().isLeft shouldBe true

    val records = sink.all.unsafeRunSync()
    records.size shouldBe 1
    records.head.operation shouldBe Operation.Get
    records.head.outcome should startWith("Failed")
    records.head.outcome should include("ItemNotFound")
  }

  test("a sequence of ops produces records in the same order") {
    val (svc, sink) = fixture()

    val created = svc.create(KeySpec.aes256("rotate-me"), alice).unsafeRunSync().toOption.get
    svc.activate(created.id, alice).unsafeRunSync()
    svc.revoke(created.id, alice).unsafeRunSync()
    svc.destroy(created.id, alice).unsafeRunSync()

    val records = sink.all.unsafeRunSync()
    records.map(_.operation) shouldBe List(
      Operation.Create,
      Operation.Activate,
      Operation.Revoke,
      Operation.Destroy
    )
  }

  test("locate writes one record with hit count, even on zero matches") {
    val (svc, sink) = fixture()

    svc.locate("nope", alice).unsafeRunSync() shouldBe Nil
    val records = sink.all.unsafeRunSync()
    records.size shouldBe 1
    records.head.operation shouldBe Operation.Locate
    records.head.outcome shouldBe "Hits=0"
  }

  test("each call gets a fresh correlation id") {
    val (svc, sink) = fixture()
    svc.create(KeySpec.aes256("k1"), alice).unsafeRunSync()
    svc.create(KeySpec.aes256("k2"), alice).unsafeRunSync()

    val records = sink.all.unsafeRunSync()
    records.size shouldBe 2
    records.map(_.correlationId).toSet.size shouldBe 2
  }
