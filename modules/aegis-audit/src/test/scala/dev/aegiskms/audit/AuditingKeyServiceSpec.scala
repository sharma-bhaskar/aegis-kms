package dev.aegiskms.audit

import cats.effect.IO
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

  test("wrap emits a Success record carrying the DEK length (not the bytes)") {
    val (svc, sink) = fixture()

    val created = svc.create(KeySpec.aes256("audit-wrap"), alice).unsafeRunSync().toOption.get
    svc.activate(created.id, alice).unsafeRunSync()
    svc.wrap(created.id, "DEKsecretBytes".getBytes, alice).unsafeRunSync()

    val wrapRecord = sink.all.unsafeRunSync().find(_.operation == Operation.Wrap).get
    wrapRecord.outcome should startWith("Success")
    wrapRecord.outcome should include("dekLen=14")
    // Critically, the audit must NOT leak the DEK bytes themselves.
    wrapRecord.outcome should not include "DEKsecretBytes"
  }

  test("unwrap emits a Success record with the recovered length") {
    val (svc, sink) = fixture()

    val created = svc.create(KeySpec.aes256("audit-unwrap"), alice).unsafeRunSync().toOption.get
    svc.activate(created.id, alice).unsafeRunSync()
    val w = svc.wrap(created.id, "dek-bytes".getBytes, alice).unsafeRunSync().toOption.get
    svc.unwrap(created.id, w, alice).unsafeRunSync()

    val unwrapRecord = sink.all.unsafeRunSync().find(_.operation == Operation.Unwrap).get
    unwrapRecord.outcome should startWith("Success")
    unwrapRecord.outcome should include("dekLen=9")
  }

  test("compromise emits a Critical-severity audit record carrying the reason") {
    val (svc, sink) = fixture()

    val created = svc.create(KeySpec.aes256("audit-compromise"), alice).unsafeRunSync().toOption.get
    svc.activate(created.id, alice).unsafeRunSync()
    svc.compromise(created.id, "leaked in S3 audit 2026-05-08", alice).unsafeRunSync()

    val rec = sink.all.unsafeRunSync().find(_.operation == Operation.Compromise).get
    rec.outcome should startWith("severity=Critical")
    rec.outcome should include("Success")
    rec.outcome should include("reason=leaked in S3 audit 2026-05-08")
  }

  test("rotate emits a Success record carrying the new version and the policy") {
    val (svc, sink) = fixture()

    val created = svc.create(KeySpec.aes256("audit-rotate"), alice).unsafeRunSync().toOption.get
    svc.activate(created.id, alice).unsafeRunSync()
    svc.rotate(created.id, RotationPolicy.Manual, alice).unsafeRunSync()

    val rec = sink.all.unsafeRunSync().find(_.operation == Operation.Rotate).get
    rec.outcome should startWith("Success")
    rec.outcome should include("newVersion=2")
    rec.outcome should include("policy=Manual")
  }

  test("rotate on a PreActive key emits a Failed record carrying the policy and IllegalOperation") {
    val (svc, sink) = fixture()

    val created = svc.create(KeySpec.aes256("audit-rotate-fail"), alice).unsafeRunSync().toOption.get
    // skip activate
    svc.rotate(created.id, RotationPolicy.Manual, alice).unsafeRunSync()

    val rec = sink.all.unsafeRunSync().find(_.operation == Operation.Rotate).get
    rec.outcome should startWith("Failed")
    rec.outcome should include("IllegalOperation")
    rec.outcome should include("policy=Manual")
  }

  // ── RiskScorer integration ────────────────────────────────────────────────
  //
  // When the decorator is built with a `RiskScorer`, every audit record (success, denial, and failure
  // alike) must carry `risk.score` + `risk.factors` in its `context` map. This is the load-bearing
  // contract of the W2 wiring: the SIEM exporters and the upcoming decision adapter (#16) both depend
  // on these keys being present.

  /** Stub scorer that returns a fixed `RiskScore`. The method param is `req` (not `request`) to keep the line
    * short; the value param is `s` (not `score`) to avoid clashing with the method name.
    */
  final private class FixedScorer(s: RiskScore) extends RiskScorer[IO]:
    def score(req: RiskScorer.Request): IO[RiskScore] = IO.pure(s)

  private def fixtureWithScorer(score: RiskScore): (AuditingKeyService, InMemoryAuditSink) =
    val sink  = InMemoryAuditSink.make.unsafeRunSync()
    val inner = KeyService.inMemory.unsafeRunSync()
    val audit = AuditingKeyService(inner, sink, Some(new FixedScorer(score)))
    (audit, sink)

  test("scorer-decorated create stamps risk.score + risk.factors into the record context") {
    val rs = RiskScore(
      0.42,
      List(RiskFactor("AgentPrincipal", 0.2, "agent"), RiskFactor("DestructiveOp", 0.1, "destroy"))
    )
    val (svc, sink) = fixtureWithScorer(rs)

    svc.create(KeySpec.aes256("scored"), alice).unsafeRunSync()

    val record = sink.all.unsafeRunSync().head
    record.context.get("risk.score") shouldBe Some("0.42")
    record.context.get("risk.factors") shouldBe Some("AgentPrincipal:0.2;DestructiveOp:0.1")
  }

  test("scorer is invoked on FAILED ops too — denied/notfound calls still carry risk context") {
    val rs = RiskScore(
      0.71,
      List(RiskFactor("ScopeBaseline", 0.5, "new key"), RiskFactor("AgentPrincipal", 0.2, "agent"))
    )
    val (svc, sink) = fixtureWithScorer(rs)

    // Get on a never-created key → KeyService returns ItemNotFound. The audit row is still written
    // and must still carry the score.
    svc.get(KeyId.generate(), alice).unsafeRunSync().isLeft shouldBe true

    val record = sink.all.unsafeRunSync().head
    record.outcome should startWith("Failed")
    record.context("risk.score") shouldBe "0.71"
    record.context("risk.factors") shouldBe "ScopeBaseline:0.5;AgentPrincipal:0.2"
  }

  test("no scorer configured (default arg) → context map stays empty (back-compat)") {
    val (svc, sink) = fixture() // 2-arg constructor — no scorer
    svc.create(KeySpec.aes256("unscored"), alice).unsafeRunSync()

    val record = sink.all.unsafeRunSync().head
    record.context shouldBe empty
  }
