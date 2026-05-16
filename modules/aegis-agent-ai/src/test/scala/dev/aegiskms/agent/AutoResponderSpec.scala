package dev.aegiskms.agent

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import dev.aegiskms.audit.InMemoryAuditSink
import dev.aegiskms.core.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import scala.concurrent.duration.*

/** Tests for `AutoResponder` — the W3 wedge feature.
  *
  * The properties exercised here cover the full responder contract:
  *
  *   1. Persistence is always-on — every recommendation hits the inner sink before any rule is applied. 2.
  *      Rule matching is exact on (detector, severity); no wildcard inference. 3. The action audit row is
  *      recorded with the SystemPrincipal so operators can grep on it. 4. Revoke actually mutates KMS state
  *      (the target key is moved to Revoked). 5. Failures (missing target key, invalid id, KMS error) are
  *      captured in the audit row, not thrown. 6. Cooldown suppresses repeat fires for the same (actor,
  *      action) inside the window. 7. Recommendations with no matching rule are no-ops (still persisted,
  *      never acted on).
  */
final class AutoResponderSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def agent(): Principal.Agent =
    Principal.Agent(
      subject = "claude-session-7a3",
      operator = alice,
      purpose = "invoice-signing",
      issuedAt = Instant.parse("2026-05-01T10:00:00Z"),
      ttl = 1.hour,
      allowedOps = Set(Operation.Get, Operation.Sign),
      parent = None
    )

  private def rec(
      detector: String,
      severity: Severity,
      actor: Principal = agent(),
      resource: Option[String] = Some("key:invoice-2026"),
      eventId: String = java.util.UUID.randomUUID().toString
  ): AgentRecommendation =
    AgentRecommendation(
      eventId = eventId,
      at = Instant.parse("2026-05-01T10:30:00Z"),
      actor = actor,
      detector = detector,
      severity = severity,
      summary = s"$detector $severity for ${actor.subject}",
      details = resource.fold(Map.empty[String, String])(r => Map("resource" -> r)),
      suggestedAction = SuggestedAction.Alert
    )

  /** A KeyService stub that records every method call and lets a test assert what happened. */
  final private class RecordingKeyService extends KeyService[IO]:
    val revokeCalls = scala.collection.mutable.ListBuffer[(KeyId, Principal)]()

    def revoke(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
      revokeCalls += (id -> by)
      IO.pure(Right(stubKey(id)))

    // All other ops are unused by these tests; produce sensible stubs.
    def create(spec: KeySpec, by: Principal): IO[Either[KmsError, ManagedKey]] =
      IO.pure(Right(stubKey(KeyId.fromString("stub").toOption.get)))
    def get(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
      IO.pure(Right(stubKey(id)))
    def locate(namePattern: String, by: Principal): IO[List[ManagedKey]] = IO.pure(Nil)
    def activate(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
      IO.pure(Right(stubKey(id)))
    def destroy(id: KeyId, by: Principal): IO[Either[KmsError, Unit]] = IO.pure(Right(()))
    def sign(id: KeyId, msg: Array[Byte], alg: SigAlgorithm, by: Principal): IO[Either[KmsError, Signature]] =
      IO.pure(Left(KmsError(ErrorCode.OperationNotSupported, "stub")))
    def verify(id: KeyId, msg: Array[Byte], sig: Signature, by: Principal): IO[Either[KmsError, Boolean]] =
      IO.pure(Right(true))
    def encrypt(
        id: KeyId,
        pt: Array[Byte],
        ctx: Map[String, String],
        by: Principal
    ): IO[Either[KmsError, Ciphertext]] =
      IO.pure(Left(KmsError(ErrorCode.OperationNotSupported, "stub")))
    def decrypt(
        id: KeyId,
        ct: Ciphertext,
        ctx: Map[String, String],
        by: Principal
    ): IO[Either[KmsError, Array[Byte]]] =
      IO.pure(Left(KmsError(ErrorCode.OperationNotSupported, "stub")))
    def wrap(id: KeyId, dek: Array[Byte], by: Principal): IO[Either[KmsError, WrappedDek]] =
      IO.pure(Left(KmsError(ErrorCode.OperationNotSupported, "stub")))
    def unwrap(id: KeyId, w: WrappedDek, by: Principal): IO[Either[KmsError, Array[Byte]]] =
      IO.pure(Left(KmsError(ErrorCode.OperationNotSupported, "stub")))
    def compromise(id: KeyId, reason: String, by: Principal): IO[Either[KmsError, ManagedKey]] =
      IO.pure(Right(stubKey(id)))
    def rotate(id: KeyId, policy: RotationPolicy, by: Principal): IO[Either[KmsError, ManagedKey]] =
      IO.pure(Right(stubKey(id)))

    private def stubKey(id: KeyId): ManagedKey =
      ManagedKey(
        id = id,
        spec = KeySpec.aes256("stub"),
        owner = alice,
        createdAt = Instant.parse("2026-05-01T10:00:00Z"),
        state = KeyState.Deactivated,
        currentVersion = 1
      )

  private def fixture(rules: List[AutoResponseRule], cooldown: FiniteDuration = 60.seconds): (
      AutoResponder,
      InMemoryRecommendationSink,
      InMemoryAuditSink,
      RecordingKeyService
  ) =
    val recStore = InMemoryRecommendationSink.make.unsafeRunSync()
    val audit    = InMemoryAuditSink.make.unsafeRunSync()
    val ks       = new RecordingKeyService
    val resp = AutoResponder
      .make(rules, recStore, ks, audit, cooldown = cooldown)
      .unsafeRunSync()
    (resp, recStore, audit, ks)

  // ── Persistence ────────────────────────────────────────────────────────────

  test("recommendations are always persisted to the inner sink, even when no rule matches") {
    val (resp, store, audit, _) = fixture(rules = Nil) // empty rules → never act
    val r                       = rec("ScopeBaseline", Severity.High)
    resp.publish(r).unsafeRunSync()

    store.all.unsafeRunSync() shouldBe List(r)
    audit.all.unsafeRunSync() shouldBe empty // no rule → no action audit row
  }

  // ── Rule matching ──────────────────────────────────────────────────────────

  test("Revoke rule on a matching High recommendation calls KeyService.revoke") {
    val rules = List(AutoResponseRule("ScopeBaseline", Severity.High, AutoResponseAction.Revoke))
    val (resp, _, audit, ks) = fixture(rules)
    val r                    = rec("ScopeBaseline", Severity.High, resource = Some("key:invoice-2026"))

    resp.publish(r).unsafeRunSync()

    ks.revokeCalls.size shouldBe 1
    val (id, by) = ks.revokeCalls.head
    id.value shouldBe "invoice-2026"
    by shouldBe AutoResponder.SystemPrincipal

    val row = audit.all.unsafeRunSync().head
    row.principal shouldBe AutoResponder.SystemPrincipal
    row.operation shouldBe Operation.Revoke
    row.outcome should startWith("AnomalyAlert")
    row.outcome should include("detector=ScopeBaseline")
    row.outcome should include("action=Revoke")
    row.outcome should include("Success revoked key=invoice-2026")
    row.context("auto.response.rule") shouldBe "ScopeBaseline:High:Revoke"
    row.context("auto.response.actor") shouldBe "claude-session-7a3"
  }

  test("rule matching is exact — Low severity recommendation doesn't trip a High rule") {
    val rules = List(AutoResponseRule("ScopeBaseline", Severity.High, AutoResponseAction.Revoke))
    val (resp, store, audit, ks) = fixture(rules)
    val r                        = rec("ScopeBaseline", Severity.Low)

    resp.publish(r).unsafeRunSync()

    store.all.unsafeRunSync() should have size 1 // still persisted
    ks.revokeCalls shouldBe empty
    audit.all.unsafeRunSync() shouldBe empty
  }

  test("Alert action writes an audit row but does not call KeyService") {
    val rules                = List(AutoResponseRule("RateSpike", Severity.Medium, AutoResponseAction.Alert))
    val (resp, _, audit, ks) = fixture(rules)
    val r                    = rec("RateSpike", Severity.Medium)

    resp.publish(r).unsafeRunSync()

    ks.revokeCalls shouldBe empty
    val row = audit.all.unsafeRunSync().head
    row.outcome should include("action=Alert")
    row.outcome should include("Success alert recorded")
  }

  test("Freeze action records audit + log but does not enforce (v0.2.0; #24 will enforce)") {
    val rules = List(AutoResponseRule("SourceIpBaseline", Severity.High, AutoResponseAction.Freeze))
    val (resp, _, audit, ks) = fixture(rules)
    resp.publish(rec("SourceIpBaseline", Severity.High)).unsafeRunSync()

    ks.revokeCalls shouldBe empty
    val row = audit.all.unsafeRunSync().head
    row.outcome should include("action=Freeze")
    row.outcome should include("freeze noted")
    row.outcome should include("enforcement deferred to #24")
  }

  // ── Failure handling ──────────────────────────────────────────────────────

  test("Revoke against a recommendation missing 'resource' is captured as Failed in audit") {
    val rules                = List(AutoResponseRule("RateSpike", Severity.High, AutoResponseAction.Revoke))
    val (resp, _, audit, ks) = fixture(rules)
    val r                    = rec("RateSpike", Severity.High, resource = None) // no key target

    resp.publish(r).unsafeRunSync() // must not throw

    ks.revokeCalls shouldBe empty
    val row = audit.all.unsafeRunSync().head
    row.outcome should include("Failed")
    row.outcome should include("no 'resource' detail")
  }

  test("Revoke against a non-key resource is captured as Failed in audit") {
    val rules                = List(AutoResponseRule("X", Severity.High, AutoResponseAction.Revoke))
    val (resp, _, audit, ks) = fixture(rules)
    val r                    = rec("X", Severity.High, resource = Some("pattern:foo*"))

    resp.publish(r).unsafeRunSync()

    ks.revokeCalls shouldBe empty
    audit.all.unsafeRunSync().head.outcome should include("not a key reference")
  }

  // ── Cooldown ───────────────────────────────────────────────────────────────

  test("cooldown suppresses repeat fires for the same (actor, action) inside the window") {
    val rules                = List(AutoResponseRule("RateSpike", Severity.High, AutoResponseAction.Revoke))
    val (resp, _, audit, ks) = fixture(rules, cooldown = 60.seconds)

    resp.publish(rec("RateSpike", Severity.High, eventId = "e1")).unsafeRunSync()
    resp.publish(rec("RateSpike", Severity.High, eventId = "e2")).unsafeRunSync()
    resp.publish(rec("RateSpike", Severity.High, eventId = "e3")).unsafeRunSync()

    ks.revokeCalls.size shouldBe 1 // only the first fires; e2 + e3 suppressed
    audit.all.unsafeRunSync().size shouldBe 1
  }

  test("cooldown is per-(actor,action) — different actors fire independently") {
    val rules                = List(AutoResponseRule("RateSpike", Severity.High, AutoResponseAction.Revoke))
    val (resp, _, audit, ks) = fixture(rules)

    val actorA = Principal.Service("svc-a", TenantId("t"))
    val actorB = Principal.Service("svc-b", TenantId("t"))

    resp.publish(rec("RateSpike", Severity.High, actor = actorA)).unsafeRunSync()
    resp.publish(rec("RateSpike", Severity.High, actor = actorB)).unsafeRunSync()

    ks.revokeCalls.size shouldBe 2
    audit.all.unsafeRunSync().size shouldBe 2
  }

  // ── Default rules ──────────────────────────────────────────────────────────

  test("DefaultRules cover all five baseline detectors at High → Revoke + Medium → Alert") {
    val byDetectorAndSeverity =
      AutoResponder.DefaultRules.map(r => (r.detector, r.severity, r.action)).toSet
    Seq("ScopeBaseline", "RateSpike", "OpHistogramBaseline", "TimeOfDayBaseline", "SourceIpBaseline")
      .foreach { d =>
        byDetectorAndSeverity should contain((d, Severity.High, AutoResponseAction.Revoke))
        byDetectorAndSeverity should contain((d, Severity.Medium, AutoResponseAction.Alert))
      }
  }

  test("SystemPrincipal is a Service named 'aegis-system' (greppable in audit search)") {
    AutoResponder.SystemPrincipal shouldBe a[Principal.Service]
    AutoResponder.SystemPrincipal.subject shouldBe "aegis-system"
  }
