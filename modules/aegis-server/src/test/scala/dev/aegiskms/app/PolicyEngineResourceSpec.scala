package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import com.typesafe.config.{Config, ConfigFactory}
import dev.aegiskms.core.{Decision, Operation, Principal}
import dev.aegiskms.iam.{PolicyEngine, RoleBasedPolicyEngine}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Unit tests for `Server.buildPolicyEngine` (#77). Mirrors the shape of `RootOfTrustResourceSpec`: exercise
  * each branch of the config-driven selection, including the fail-fast paths a misconfigured production
  * deployment would hit at boot.
  */
final class PolicyEngineResourceSpec extends AnyFunSuite with Matchers:

  given IORuntime = IORuntime.global

  // Reflectively invoke the private builder. Same pattern as RootOfTrustResourceSpec — the builder
  // is private to keep operators out of Server internals, but tests need access.
  private val builder = Server.getClass.getDeclaredMethod(
    "buildPolicyEngine",
    classOf[Config]
  )
  builder.setAccessible(true)
  private def invoke(c: Config): PolicyEngine[IO] =
    builder.invoke(Server, c).asInstanceOf[IO[PolicyEngine[IO]]].unsafeRunSync()

  private def cfg(hocon: String): Config =
    ConfigFactory.parseString(hocon).withFallback(ConfigFactory.load())

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))
  private val bob: Principal   = Principal.Human("bob@org", Set("readers"))

  test("kind=dev yields DevPolicyEngine — every Human is allowed") {
    val engine = invoke(cfg("""aegis.policy.kind = "dev" """))
    engine shouldBe a[DevPolicyEngine]
    engine.permit(alice, Operation.Sign, "key:k1").unsafeRunSync() shouldBe Decision.Allow
    engine.permit(bob, Operation.Destroy, "key:k2").unsafeRunSync() shouldBe Decision.Allow
  }

  test("kind defaults to dev when no override is set (application.conf default)") {
    invoke(cfg("")) shouldBe a[DevPolicyEngine]
  }

  test("kind=role-based with role bindings yields a RoleBasedPolicyEngine matching the bindings") {
    val hocon  = """
      aegis.policy {
        kind = "role-based"
        role-based {
          role-bindings    = { admins = ["Sign", "Get"], readers = ["Get"] }
          subject-bindings = {}
        }
      }
    """
    val engine = invoke(cfg(hocon))
    engine shouldBe a[RoleBasedPolicyEngine]
    // alice ∈ admins — Sign + Get allowed; Destroy denied.
    engine.permit(alice, Operation.Sign, "k").unsafeRunSync() shouldBe Decision.Allow
    engine.permit(alice, Operation.Get, "k").unsafeRunSync() shouldBe Decision.Allow
    engine.permit(alice, Operation.Destroy, "k").unsafeRunSync() shouldBe a[Decision.Deny]
    // bob ∈ readers — Get allowed; Sign denied.
    engine.permit(bob, Operation.Get, "k").unsafeRunSync() shouldBe Decision.Allow
    engine.permit(bob, Operation.Sign, "k").unsafeRunSync() shouldBe a[Decision.Deny]
  }

  test("kind=role-based with subject bindings only is honored (no roles required)") {
    val hocon  = """
      aegis.policy {
        kind = "role-based"
        role-based {
          role-bindings    = {}
          subject-bindings = { "bob@org" = ["Destroy"] }
        }
      }
    """
    val engine = invoke(cfg(hocon))
    engine.permit(bob, Operation.Destroy, "k").unsafeRunSync() shouldBe Decision.Allow
    engine.permit(alice, Operation.Destroy, "k").unsafeRunSync() shouldBe a[Decision.Deny]
  }

  test(
    "kind=role-based with both maps empty fails fast at boot (silent allow-all would be a security hole)"
  ) {
    val ex = intercept[IllegalArgumentException] {
      invoke(cfg("""aegis.policy.kind = "role-based" """))
    }
    ex.getMessage should include("role-based")
    ex.getMessage should include("at least one binding")
  }

  test("kind=role-based with an unknown operation name fails fast (catches typos like 'sgn' for 'Sign')") {
    val hocon = """
      aegis.policy {
        kind = "role-based"
        role-based {
          role-bindings    = { admins = ["Sign", "Sgn"] }
          subject-bindings = {}
        }
      }
    """
    val ex    = intercept[IllegalArgumentException](invoke(cfg(hocon)))
    ex.getMessage should include("unknown operation 'Sgn'")
    ex.getMessage should include("aegis.policy.role-based.role-bindings.admins")
  }

  test("unknown kind fails fast with a clear error message") {
    val ex = intercept[IllegalArgumentException] {
      invoke(cfg("""aegis.policy.kind = "opa" """))
    }
    ex.getMessage should include("Unknown aegis.policy.kind=opa")
    ex.getMessage should include("'dev'")
    ex.getMessage should include("'role-based'")
  }
