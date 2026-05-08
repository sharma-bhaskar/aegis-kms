package dev.aegiskms.iam

import cats.effect.unsafe.implicits.global
import dev.aegiskms.core.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant
import scala.concurrent.duration.*

/** Tests for `AuthorizingKeyService` — verifies that policy denies short-circuit before the inner service is
  * touched, and that allowed calls pass through unchanged.
  */
final class AuthorizingKeyServiceSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def fixture(engine: PolicyEngine[cats.effect.IO]): AuthorizingKeyService =
    val inner = KeyService.inMemory.unsafeRunSync()
    AuthorizingKeyService(inner, engine)

  test("denied call returns PermissionDenied without touching the inner service") {
    val svc = fixture(RoleBasedPolicyEngine.denyAll)
    val res = svc.create(KeySpec.aes256("x"), alice).unsafeRunSync()
    res.isLeft shouldBe true
    res.swap.toOption.get.code shouldBe ErrorCode.PermissionDenied
  }

  test("allowed call passes through and returns the underlying result") {
    val engine = RoleBasedPolicyEngine.adminsOnly("admins")
    val svc    = fixture(engine)

    val res = svc.create(KeySpec.aes256("invoice-signing"), alice).unsafeRunSync()
    res.isRight shouldBe true
    res.toOption.get.spec.name shouldBe "invoice-signing"
  }

  test("agent denied because parent has no role returns PermissionDenied") {
    val engine = RoleBasedPolicyEngine.denyAll // alice has no roles
    val svc    = fixture(engine)
    val agent = Principal.Agent(
      subject = "claude-session-7a3",
      operator = alice,
      purpose = "anything",
      issuedAt = Instant.now(),
      ttl = 1.hour,
      allowedOps = Set(Operation.Create),
      parent = None
    )
    val res = svc.create(KeySpec.aes256("x"), agent).unsafeRunSync()
    res.isLeft shouldBe true
    res.swap.toOption.get.code shouldBe ErrorCode.PermissionDenied
    res.swap.toOption.get.message should include("blocked by parent")
  }

  test("agent without Sign in allowedOps is denied even if the parent is permissive") {
    val engine = RoleBasedPolicyEngine.adminsOnly("admins") // alice IS in admins
    val svc    = fixture(engine)
    val agent = Principal.Agent(
      subject = "claude-session-7a3",
      operator = alice,
      purpose = "invoice-signing",
      issuedAt = Instant.now(),
      ttl = 1.hour,
      allowedOps = Set(Operation.Get), // no Sign
      parent = None
    )
    val res = svc.sign(KeyId.generate(), "msg".getBytes, SigAlgorithm.RsaPssSha256, agent).unsafeRunSync()
    res.isLeft shouldBe true
    res.swap.toOption.get.code shouldBe ErrorCode.PermissionDenied
  }

  test("agent with Sign in allowedOps and a permissive parent is allowed through") {
    val engine = RoleBasedPolicyEngine.adminsOnly("admins")
    val svc    = fixture(engine)

    // First create + activate as alice so the inner store has a key to sign with.
    val created = svc.create(KeySpec.rsa2048("agent-sign"), alice).unsafeRunSync()
    created.isRight shouldBe true
    val id = created.toOption.get.id
    svc.activate(id, alice).unsafeRunSync()

    val agent = Principal.Agent(
      subject = "claude-session-7a3",
      operator = alice,
      purpose = "invoice-signing",
      issuedAt = Instant.now(),
      ttl = 1.hour,
      allowedOps = Set(Operation.Get, Operation.Sign, Operation.Verify),
      parent = None
    )
    val res = svc.sign(id, "msg".getBytes, SigAlgorithm.RsaPssSha256, agent).unsafeRunSync()
    res.isRight shouldBe true
  }

  test("encrypt is denied when the agent's allowedOps doesn't include Encrypt") {
    val engine = RoleBasedPolicyEngine.adminsOnly("admins")
    val svc    = fixture(engine)
    val agent = Principal.Agent(
      subject = "claude-session-7a3",
      operator = alice,
      purpose = "verify-only",
      issuedAt = Instant.now(),
      ttl = 1.hour,
      allowedOps = Set(Operation.Get), // no Encrypt
      parent = None
    )
    val res = svc.encrypt(KeyId.generate(), "x".getBytes, Map.empty, agent).unsafeRunSync()
    res.isLeft shouldBe true
    res.swap.toOption.get.code shouldBe ErrorCode.PermissionDenied
  }

  test("encrypt + decrypt pass through when the principal has the role and the ops") {
    val engine = RoleBasedPolicyEngine.adminsOnly("admins")
    val svc    = fixture(engine)

    val created = svc.create(KeySpec.aes256("enc-key"), alice).unsafeRunSync()
    created.isRight shouldBe true
    val id = created.toOption.get.id
    svc.activate(id, alice).unsafeRunSync()

    val ct = svc.encrypt(id, "secret".getBytes, Map("a" -> "1"), alice).unsafeRunSync()
    ct.isRight shouldBe true

    val pt = svc.decrypt(id, ct.toOption.get, Map("a" -> "1"), alice).unsafeRunSync()
    pt.isRight shouldBe true
    new String(pt.toOption.get, "UTF-8") shouldBe "secret"
  }
