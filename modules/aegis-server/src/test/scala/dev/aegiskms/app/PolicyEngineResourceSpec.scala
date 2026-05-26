package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import com.typesafe.config.{Config, ConfigFactory}
import dev.aegiskms.core.{Decision, Operation, Principal}
import dev.aegiskms.iam.{PolicyEngine, RoleBasedPolicyEngine}
import org.scalatest.Inside.*
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

  test("kind=role-based: agent recursion through parent — wedge's load-bearing security property") {
    // The agent identity model's load-bearing promise: "an agent never escalates beyond what the
    // human who issued its credential could do." Under role-based, that means an agent under alice
    // (admins → Sign only) cannot Destroy even if its own allowedOps includes Destroy, AND cannot
    // do anything its own allowedOps excludes. We test BOTH gates via the wired engine.
    val hocon  = """
      aegis.policy {
        kind = "role-based"
        role-based {
          role-bindings    = { admins = ["Sign"] }
          subject-bindings = {}
        }
      }
    """
    val engine = invoke(cfg(hocon))

    // Construct an agent under alice. The agent's own allowedOps is BROADER than alice's role —
    // includes Destroy. Recursion must still deny Destroy because alice can't Destroy.
    val agent = Principal.Agent(
      subject = "claude-session-7a3",
      operator = alice,
      purpose = "test",
      issuedAt = java.time.Instant.parse("2026-05-26T10:00:00Z"),
      ttl = scala.concurrent.duration.Duration("1h"),
      allowedOps = Set(Operation.Sign, Operation.Destroy),
      parent = None
    )

    // 1. Sign: agent's allowedOps includes it AND alice can Sign → Allow.
    engine.permit(agent, Operation.Sign, "k").unsafeRunSync() shouldBe Decision.Allow

    // 2. Destroy: agent's allowedOps includes it BUT alice cannot Destroy → Deny with "blocked by
    //    parent" reason. This is the load-bearing escalation prevention.
    val destroyDecision = engine.permit(agent, Operation.Destroy, "k").unsafeRunSync()
    destroyDecision shouldBe a[Decision.Deny]
    inside(destroyDecision) { case Decision.Deny(reason) =>
      reason should include("blocked by parent")
      reason should include(alice.subject)
    }

    // 3. Get: agent's allowedOps does NOT include it → Deny with "scope does not include" reason.
    //    This is the per-agent allowlist gate; parent recursion never even runs.
    val getDecision = engine.permit(agent, Operation.Get, "k").unsafeRunSync()
    getDecision shouldBe a[Decision.Deny]
    inside(getDecision) { case Decision.Deny(reason) =>
      reason should include("scope does not include")
      reason should include("claude-session-7a3")
    }
  }
