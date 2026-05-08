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

  test("sign emits a Success record carrying the algorithm and message length") {
    val (svc, sink) = fixture()

    val created = svc.create(KeySpec.rsa2048("audit-sign"), alice).unsafeRunSync().toOption.get
    svc.activate(created.id, alice).unsafeRunSync()
    svc.sign(created.id, "hello".getBytes, SigAlgorithm.RsaPssSha256, alice).unsafeRunSync()

    val signRecord = sink.all.unsafeRunSync().find(_.operation == Operation.Sign).get
    signRecord.outcome should startWith("Success")
    signRecord.outcome should include("alg=RsaPssSha256")
    signRecord.outcome should include("msgLen=5")
  }

  test("verify emits a Success record with valid=true/false") {
    val (svc, sink) = fixture()

    val created = svc.create(KeySpec.rsa2048("audit-verify"), alice).unsafeRunSync().toOption.get
    svc.activate(created.id, alice).unsafeRunSync()
    val sig = svc.sign(created.id, "msg".getBytes, SigAlgorithm.RsaPssSha256, alice)
      .unsafeRunSync().toOption.get
    svc.verify(created.id, "msg".getBytes, sig, alice).unsafeRunSync()
    svc.verify(created.id, "tampered".getBytes, sig, alice).unsafeRunSync()

    val verifyRecords = sink.all.unsafeRunSync().filter(_.operation == Operation.Verify)
    verifyRecords.size shouldBe 2
    verifyRecords.head.outcome should include("valid=true")
    verifyRecords(1).outcome should include("valid=false")
  }

  test("encrypt emits a Success record carrying the context keys (not values) and plaintext length") {
    val (svc, sink) = fixture()

    val created = svc.create(KeySpec.aes256("audit-enc"), alice).unsafeRunSync().toOption.get
    svc.activate(created.id, alice).unsafeRunSync()
    svc.encrypt(created.id, "hello".getBytes, Map("dataset" -> "q2", "tenant" -> "acme"), alice)
      .unsafeRunSync()

    val encRecord = sink.all.unsafeRunSync().find(_.operation == Operation.Encrypt).get
    encRecord.outcome should startWith("Success")
    encRecord.outcome should include("ctxKeys=dataset,tenant")
    encRecord.outcome should include("ptLen=5")
    // Critically, the audit must NOT leak the values — only the keys are recorded.
    encRecord.outcome should not include "q2"
    encRecord.outcome should not include "acme"
  }

  test("decrypt with a wrong context emits a Failed record with CryptographicFailure") {
    val (svc, sink) = fixture()

    val created = svc.create(KeySpec.aes256("audit-dec"), alice).unsafeRunSync().toOption.get
    svc.activate(created.id, alice).unsafeRunSync()
    val ct = svc.encrypt(created.id, "hi".getBytes, Map("a" -> "1"), alice)
      .unsafeRunSync().toOption.get
    svc.decrypt(created.id, ct, Map("a" -> "2"), alice).unsafeRunSync()

    val decRecord = sink.all.unsafeRunSync().find(_.operation == Operation.Decrypt).get
    decRecord.outcome should startWith("Failed")
    decRecord.outcome should include("CryptographicFailure")
  }
