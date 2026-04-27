package dev.aegiskms.iam

import cats.effect.unsafe.implicits.global
import dev.aegiskms.core.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import scala.concurrent.duration.*

/** Tests for `RoleBasedPolicyEngine`, with an emphasis on the agent-identity model.
  *
  * The two non-trivial behaviors are:
  *   - An agent's `allowedOps` allowlist is enforced on every call (not just at issuance).
  *   - An agent never escalates beyond what the parent human can do, even if the agent's own allowlist is
  *     broader.
  */
final class RoleBasedPolicyEngineSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))
  private val bob: Principal   = Principal.Human("bob@org", Set("auditors"))

  test("Human in admins role can Create when admins is bound to Create") {
    val engine = new RoleBasedPolicyEngine(
      roleBindings = Map("admins" -> Set(Operation.Create)),
      subjectBindings = Map.empty
    )
    engine.permit(alice, Operation.Create, "name:k").unsafeRunSync() shouldBe Decision.Allow
  }

  test("Human without binding is denied") {
    val engine = new RoleBasedPolicyEngine(
      roleBindings = Map("admins" -> Set(Operation.Create)),
      subjectBindings = Map.empty
    )
    val result = engine.permit(bob, Operation.Create, "name:k").unsafeRunSync()
    result shouldBe a[Decision.Deny]
  }

  test("Subject-direct binding works for Service principal") {
    val svc = Principal.Service("svc-edge-cache", TenantId("default"))
    val engine = new RoleBasedPolicyEngine(
      roleBindings = Map.empty,
      subjectBindings = Map("svc-edge-cache" -> Set(Operation.Get))
    )
    engine.permit(svc, Operation.Get, "key:edge-tls").unsafeRunSync() shouldBe Decision.Allow
    engine.permit(svc, Operation.Create, "key:edge-tls").unsafeRunSync() should not be Decision.Allow
  }

  test("Agent within scope AND with a permitted parent is allowed") {
    val engine = new RoleBasedPolicyEngine(
      roleBindings = Map("admins" -> Set(Operation.Create, Operation.Get)),
      subjectBindings = Map.empty
    )
    val agent = Principal.Agent(
      subject = "claude-session-7a3",
      operator = alice,
      purpose = "invoice-signing",
      issuedAt = Instant.now(),
      ttl = 1.hour,
      allowedOps = Set(Operation.Create),
      parent = None
    )
    engine.permit(agent, Operation.Create, "name:k").unsafeRunSync() shouldBe Decision.Allow
  }

  test("Agent calling op outside its allowlist is denied — even if parent could do it") {
    val engine = new RoleBasedPolicyEngine(
      roleBindings = Map("admins" -> Operation.values.toSet),
      subjectBindings = Map.empty
    )
    val agent = Principal.Agent(
      subject = "claude-session-7a3",
      operator = alice,
      purpose = "invoice-signing",
      issuedAt = Instant.now(),
      ttl = 1.hour,
      allowedOps = Set(Operation.Create), // narrow scope
      parent = None
    )
    val deny = engine.permit(agent, Operation.Destroy, "key:treasury-master").unsafeRunSync()
    deny shouldBe a[Decision.Deny]
    deny match
      case Decision.Deny(reason) => reason should include("scope does not include")
      case other                 => fail(s"expected Deny, got $other")
  }

  test("Agent within scope but with a denied parent is denied — no escalation past the human") {
    val engine = new RoleBasedPolicyEngine(
      roleBindings = Map("auditors" -> Set(Operation.Get)), // bob only
      subjectBindings = Map.empty
    )
    val agent = Principal.Agent(
      subject = "claude-session-7a3",
      operator = bob, // can only Get
      purpose = "wider-than-bob",
      issuedAt = Instant.now(),
      ttl = 1.hour,
      allowedOps = Set(Operation.Create), // agent claims it can Create
      parent = None
    )
    val deny = engine.permit(agent, Operation.Create, "key:invoice").unsafeRunSync()
    deny shouldBe a[Decision.Deny]
    deny match
      case Decision.Deny(reason) => reason should include("blocked by parent")
      case other                 => fail(s"expected Deny, got $other")
  }

  test("denyAll engine denies every call") {
    val engine = RoleBasedPolicyEngine.denyAll
    engine.permit(alice, Operation.Create, "name:k").unsafeRunSync() shouldBe a[Decision.Deny]
    engine.permit(alice, Operation.Get, "key:any").unsafeRunSync() shouldBe a[Decision.Deny]
  }
