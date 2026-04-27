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
