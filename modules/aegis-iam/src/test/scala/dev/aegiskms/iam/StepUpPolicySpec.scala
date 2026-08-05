package dev.aegiskms.iam

import dev.aegiskms.core.{Operation, Principal, TenantId}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.{Duration, Instant}
import scala.concurrent.duration.DurationInt

/** Tests for step-up authentication (#102).
  *
  * The theme throughout is **fail closed**. Every ambiguous input — no `amr`, no `auth_time`, a non-human
  * caller, a clock anomaly — must be refused, because the alternative is a mechanism that looks like it
  * protects the kill-switch while quietly letting everything through.
  */
final class StepUpPolicySpec extends AnyFunSuite with Matchers:

  private val now    = Instant.parse("2026-08-04T12:00:00Z")
  private val policy = StepUpPolicy()

  private def human(
      amr: Set[String] = Set("mfa"),
      authTime: Option[Instant] = Some(now.minusSeconds(60))
  ) = Principal.Human("alice@org", Set("operators"), amr, authTime)

  // ── Satisfied ─────────────────────────────────────────────────────────────

  test("a recent MFA login satisfies the policy") {
    policy.check(human(), now).isRight shouldBe true
  }

  test("any one of the accepted methods is enough") {
    StepUpPolicy.DefaultMethods.foreach { m =>
      withClue(s"method $m: ")(policy.check(human(amr = Set(m)), now).isRight shouldBe true)
    }
  }

  test("extra unrecognised methods alongside an accepted one are fine") {
    policy.check(human(amr = Set("pwd", "mfa", "something-custom")), now).isRight shouldBe true
  }

  test("authentication exactly at the freshness boundary is still accepted") {
    val boundary = human(authTime = Some(now.minus(StepUpPolicy.DefaultMaxAge)))
    policy.check(boundary, now).isRight shouldBe true
  }

  // ── Refused ───────────────────────────────────────────────────────────────

  test("a password-only credential is refused — pwd is not a step-up") {
    val res = policy.check(human(amr = Set("pwd")), now)
    res.isLeft shouldBe true
    res.left.toOption.get.reason should include("requires re-authentication")
  }

  test("a credential with no amr at all is refused, not assumed strong") {
    policy.check(human(amr = Set.empty), now).isLeft shouldBe true
  }

  test("a strong method that happened too long ago is refused") {
    val stale = human(authTime = Some(now.minusSeconds(StepUpPolicy.DefaultMaxAge.toSeconds + 1)))
    val res   = policy.check(stale, now)
    res.isLeft shouldBe true
    res.left.toOption.get.reason should include("re-authenticate")
  }

  test("a credential with no auth_time is refused — freshness cannot be established") {
    val res = policy.check(human(authTime = None), now)
    res.isLeft shouldBe true
    res.left.toOption.get.reason should include("auth_time")
  }

  test("an auth_time in the future is refused rather than treated as maximally fresh") {
    val skewed = human(authTime = Some(now.plusSeconds(3600)))
    val res    = policy.check(skewed, now)
    res.isLeft shouldBe true
    res.left.toOption.get.reason should include("future")
  }

  test("small forward clock skew is tolerated") {
    policy.check(human(authTime = Some(now.plusSeconds(30))), now).isRight shouldBe true
  }

  test("a service principal can never satisfy step-up") {
    val svc = Principal.Service("ci-runner", TenantId("acme"))
    val res = policy.check(svc, now)
    res.isLeft shouldBe true
    res.left.toOption.get.reason should include("service principals")
  }

  test("an agent can never satisfy step-up") {
    val agent = Principal.Agent(
      subject = "agent-7a3",
      operator = human(),
      purpose = "test",
      issuedAt = now,
      ttl = 1.hour,
      allowedOps = Set(Operation.Sign),
      parent = None
    )
    val res = policy.check(agent, now)
    res.isLeft shouldBe true
    res.left.toOption.get.reason should include("agents cannot")
  }

  // ── Configurability ───────────────────────────────────────────────────────

  test("a custom method set is honoured") {
    val strict = StepUpPolicy(requiredMethods = Set("hwk"))
    strict.check(human(amr = Set("mfa")), now).isLeft shouldBe true
    strict.check(human(amr = Set("hwk")), now).isRight shouldBe true
  }

  test("a custom max-age is honoured") {
    val tight = StepUpPolicy(maxAge = Duration.ofSeconds(30))
    tight.check(human(authTime = Some(now.minusSeconds(60))), now).isLeft shouldBe true
    tight.check(human(authTime = Some(now.minusSeconds(10))), now).isRight shouldBe true
  }

  // ── Challenge rendering ───────────────────────────────────────────────────

  test("the challenge renders as a parseable RFC 7235 header naming scheme, methods, and max-age") {
    val challenge = policy.check(human(amr = Set("pwd")), now).left.toOption.get
    val header    = challenge.headerValue

    header should startWith("aegis-stepup ")
    header should include("""realm="aegis"""")
    header should include("acr=")
    header should include(s"max_age=${StepUpPolicy.DefaultMaxAge.toSeconds}")
  }

  test("the challenge lists methods in a stable sorted order") {
    val c = StepUpChallenge("why", Set("otp", "mfa", "hwk"), Duration.ofMinutes(5))
    c.headerValue should include("""acr="hwk mfa otp"""")
  }

  test("quotes in the reason are escaped so they cannot inject extra auth-params") {
    val c      = StepUpChallenge("""bad" , injected="yes""", Set("mfa"), Duration.ofMinutes(5))
    val header = c.headerValue

    // Every quote from the reason survives as an escaped quote inside the quoted-string, so a parser
    // never sees the reason terminate early and `injected` never becomes a real auth-param.
    header should include("""reason="bad\" , injected=\"yes"""")
    // And the parameters we actually intend are all still present and intact.
    header should include("""realm="aegis"""")
    header should include("""acr="mfa"""")
    header should include("max_age=300")
  }

  test("backslashes in the reason are escaped too") {
    val c = StepUpChallenge("""back\slash""", Set("mfa"), Duration.ofMinutes(5))
    c.headerValue should include("""back\\slash""")
  }

  test("the challenge converts to a StepUpRequired KmsError carrying the reason") {
    val c = StepUpChallenge("do MFA", Set("mfa"), Duration.ofMinutes(5))
    c.asError.code shouldBe dev.aegiskms.core.ErrorCode.StepUpRequired
    c.asError.message shouldBe "do MFA"
  }
