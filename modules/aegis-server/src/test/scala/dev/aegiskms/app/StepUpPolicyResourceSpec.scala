package dev.aegiskms.app

import com.typesafe.config.ConfigFactory
import dev.aegiskms.iam.StepUpPolicy
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Unit tests for `Server.stepUpPolicyFrom` — the config → policy mapping that gates the kill-switch.
  *
  * Mirrors `RootOfTrustResourceSpec`'s reflective approach for the same reason: the builder is private so
  * operators can't reach past `Server.boot`, but the selection logic still needs pinning. A misparse here
  * silently weakens the strongest gate in the system.
  */
final class StepUpPolicyResourceSpec extends AnyFunSuite with Matchers:

  private val method = Server.getClass.getDeclaredMethod(
    "stepUpPolicyFrom",
    classOf[com.typesafe.config.Config]
  )
  method.setAccessible(true)

  private def invoke(hocon: String): StepUpPolicy =
    val cfg = ConfigFactory.parseString(hocon).withFallback(ConfigFactory.load())
    method.invoke(Server, cfg).asInstanceOf[StepUpPolicy]

  test("the shipped defaults produce the standard policy") {
    val p = invoke("")
    p.requiredMethods shouldBe StepUpPolicy.DefaultMethods
    p.maxAge.toSeconds shouldBe 300
  }

  test("the default method set excludes pwd — a password is not a step-up") {
    invoke("").requiredMethods should not contain "pwd"
  }

  test("a custom method list is honoured") {
    val p = invoke("""aegis.security.step-up.methods = ["hwk"]""")
    p.requiredMethods shouldBe Set("hwk")
  }

  test("a custom max-age is honoured") {
    invoke("aegis.security.step-up.max-age-seconds = 120").maxAge.toSeconds shouldBe 120
  }

  test("an empty method list falls back to the defaults rather than accepting everything") {
    // An empty required-method set would make `amr.intersect(required)` empty for every caller, which
    // reads as "always refuse" — but a misconfiguration should not silently disable the endpoint either.
    // Falling back to the documented defaults is the predictable behaviour.
    invoke("""aegis.security.step-up.methods = []""").requiredMethods shouldBe StepUpPolicy.DefaultMethods
  }

  test("methods and max-age can be overridden together") {
    val p = invoke("""
      aegis.security.step-up.methods = ["otp", "hwk"]
      aegis.security.step-up.max-age-seconds = 60
    """)
    p.requiredMethods shouldBe Set("otp", "hwk")
    p.maxAge.toSeconds shouldBe 60
  }
