package dev.aegiskms.cli

import dev.aegiskms.sdk.WireFormats.*
import dev.aegiskms.sdk.{AegisHttpClient, HttpPort}
import io.circe.syntax.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant

/** Tests for `aegis agent revoke` (#102).
  *
  * The parser tests carry real weight here: this command destroys credentials, so a mistyped flag must fail
  * locally rather than reach the server and sweep the wrong fleet.
  */
final class CliAgentRevokeSpec extends AnyFunSuite with Matchers:

  private val cfg = CliConfig("http://localhost:8443", Some("alice@org"))

  private def body(killed: List[KilledAgentDto], alreadyRevoked: Int = 0, expired: Int = 0): String =
    RevokeAgentsResponseDto("alice@org", killed, alreadyRevoked, expired).asJson.noSpaces

  private val sample =
    KilledAgentDto("agent-7a3", "claude-invoice-batch", Instant.parse("2026-08-04T13:00:00Z"))

  private def captureFactory(
      cap: HttpPort.Request => Unit,
      responseBody: String,
      status: Int = 200
  ): CliConfig => AegisHttpClient =
    cfg =>
      new AegisHttpClient(
        new HttpPort:
          def execute(req: HttpPort.Request): HttpPort.Response = {
            cap(req); HttpPort.Response(status, responseBody)
          }
        ,
        cfg.serverUrl,
        cfg.principal
      )

  // ── Parsing ───────────────────────────────────────────────────────────────

  test("--parent is required — the command must never default to the caller's own fleet") {
    Cli.parseAgentRevoke(Nil).isLeft shouldBe true
    Cli.parseAgentRevoke(List("--parent", "")).isLeft shouldBe true
  }

  test("--parent alone is a valid invocation") {
    Cli.parseAgentRevoke(List("--parent", "alice@org")) shouldBe Right(("alice@org", None))
  }

  test("--issued-after is carried through as supplied") {
    Cli.parseAgentRevoke(List("--parent", "alice@org", "--issued-after", "2026-08-04T11:00:00Z")) shouldBe
      Right(("alice@org", Some("2026-08-04T11:00:00Z")))
  }

  // ── Wire ──────────────────────────────────────────────────────────────────

  test("the request POSTs the parent to /v1/agents/revoke") {
    var captured: Option[HttpPort.Request] = None
    Cli.run(
      List("agent", "revoke", "--parent", "alice@org"),
      cfg,
      captureFactory(req => captured = Some(req), body(List(sample)))
    )

    val req = captured.get
    req.method shouldBe "POST"
    req.url should endWith("/v1/agents/revoke")
    req.body.get should include("alice@org")
  }

  test("a malformed --issued-after is rejected locally, without contacting the server") {
    var called = false
    val r = Cli.run(
      List("agent", "revoke", "--parent", "alice@org", "--issued-after", "yesterday"),
      cfg,
      captureFactory(_ => called = true, body(Nil))
    )

    r.exitCode should not be 0
    r.stderr should include("ISO-8601")
    called shouldBe false
  }

  test("a missing --parent prints usage without contacting the server") {
    var called = false
    val r      = Cli.run(List("agent", "revoke"), cfg, captureFactory(_ => called = true, body(Nil)))

    r.exitCode should not be 0
    r.stderr should include("Usage: aegis agent revoke")
    called shouldBe false
  }

  // ── Rendering ─────────────────────────────────────────────────────────────

  test("the summary distinguishes what was killed from what was already dead") {
    val r = Cli.run(
      List("agent", "revoke", "--parent", "alice@org"),
      cfg,
      captureFactory(_ => (), body(List(sample), alreadyRevoked = 11, expired = 3))
    )

    r.exitCode shouldBe 0
    r.stdout should include("revoked 1")
    r.stdout should include("already revoked 11")
    r.stdout should include("expired 3")
    r.stdout should include("agent-7a3")
  }

  test("a sweep that found nothing live says so instead of printing an empty list") {
    val r = Cli.run(
      List("agent", "revoke", "--parent", "alice@org"),
      cfg,
      captureFactory(_ => (), body(Nil, alreadyRevoked = 2))
    )

    r.stdout should include("nothing live to revoke")
  }

  // ── Errors ────────────────────────────────────────────────────────────────

  test("a step-up 401 surfaces the server's reason so the operator knows to re-authenticate") {
    val errBody = KmsErrorDto(
      "StepUpRequired",
      "this operation requires re-authentication with one of: hwk, mfa, otp"
    ).asJson.noSpaces
    val r = Cli.run(
      List("agent", "revoke", "--parent", "alice@org"),
      cfg,
      captureFactory(_ => (), errBody, status = 401)
    )

    r.exitCode should not be 0
    r.stderr should include("re-authentication")
  }

  test("a 501 from an unconfigured server explains what to enable") {
    val errBody = KmsErrorDto(
      "FeatureNotSupported",
      "agent kill-switch is not enabled on this server (set aegis.audit.kind=postgres)"
    ).asJson.noSpaces
    val r = Cli.run(
      List("agent", "revoke", "--parent", "alice@org"),
      cfg,
      captureFactory(_ => (), errBody, status = 501)
    )

    r.exitCode should not be 0
    r.stderr should include("aegis.audit.kind=postgres")
  }
