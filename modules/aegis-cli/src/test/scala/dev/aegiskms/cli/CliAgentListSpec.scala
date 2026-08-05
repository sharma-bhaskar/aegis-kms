package dev.aegiskms.cli

import dev.aegiskms.sdk.WireFormats.*
import dev.aegiskms.sdk.{AegisHttpClient, HttpPort}
import io.circe.syntax.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant

/** Tests for `aegis agent list` (#101) — flag parsing, query-string construction, and the rendered table.
  *
  * The rendering assertions matter more than they look: this is the surface an operator reads during an
  * incident, so "never" for an unused credential and a visible `activeCount` are contract, not decoration.
  */
final class CliAgentListSpec extends AnyFunSuite with Matchers:

  private val cfg = CliConfig("http://localhost:8443", Some("alice@org"))

  private val issued  = Instant.parse("2026-08-04T11:50:00Z")
  private val expires = Instant.parse("2026-08-04T12:50:00Z")

  private def agent(
      agentId: String = "agent-7a3",
      status: String = "Active",
      lastSeenAt: Option[Instant] = None
  ) = AgentSummaryDto(
    agentId = agentId,
    label = "claude-invoice-batch",
    parent = "alice@org",
    scopes = List("Get", "Sign"),
    issuedAt = issued,
    expiresAt = expires,
    lastSeenAt = lastSeenAt,
    status = status
  )

  private def body(agents: List[AgentSummaryDto], activeCount: Int = 0): String =
    ListAgentsResponseDto(agents, limit = 100, offset = 0, activeCount = activeCount).asJson.noSpaces

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

  // ── Flag parsing ──────────────────────────────────────────────────────────

  test("a bare 'agent list' sends no filters at all") {
    Cli.parseAgentList(Nil) shouldBe Right((None, None, None, None))
  }

  test("all four flags parse") {
    Cli.parseAgentList(
      List("--parent", "alice@org", "--status", "Revoked", "--limit", "25", "--offset", "50")
    ) shouldBe Right((Some("alice@org"), Some("Revoked"), Some(25), Some(50)))
  }

  test("--status is normalised to canonical casing so the server sees a known value") {
    Cli.parseAgentList(List("--status", "expired")).map(_._2) shouldBe Right(Some("Expired"))
  }

  test("an unknown --status is rejected locally, naming the valid values") {
    val r = Cli.parseAgentList(List("--status", "zombie"))
    r.isLeft shouldBe true
    r.left.toOption.get should include("Active, Expired, Revoked")
    r.left.toOption.get should include("zombie")
  }

  test("--limit must be a positive integer") {
    Cli.parseAgentList(List("--limit", "0")).isLeft shouldBe true
    Cli.parseAgentList(List("--limit", "abc")).isLeft shouldBe true
  }

  test("--offset may be zero but not negative") {
    Cli.parseAgentList(List("--offset", "0")).map(_._4) shouldBe Right(Some(0))
    Cli.parseAgentList(List("--offset", "-1")).isLeft shouldBe true
  }

  // ── Wire ──────────────────────────────────────────────────────────────────

  test("filters are forwarded as query parameters on GET /v1/agents") {
    var captured: Option[HttpPort.Request] = None
    Cli.run(
      List("agent", "list", "--parent", "alice@org", "--status", "Active", "--limit", "10"),
      cfg,
      captureFactory(req => captured = Some(req), body(Nil))
    )

    val req = captured.get
    req.method shouldBe "GET"
    req.url should include("/v1/agents")
    req.url should include("parent=alice%40org")
    req.url should include("status=Active")
    req.url should include("limit=10")
  }

  test("a bare 'agent list' hits /v1/agents with no query string") {
    var captured: Option[HttpPort.Request] = None
    Cli.run(List("agent", "list"), cfg, captureFactory(req => captured = Some(req), body(Nil)))

    captured.get.url should endWith("/v1/agents")
  }

  // ── Rendering ─────────────────────────────────────────────────────────────

  test("the table shows agent id, status, parent, and scopes") {
    val r = Cli.run(
      List("agent", "list"),
      cfg,
      captureFactory(_ => (), body(List(agent()), activeCount = 1))
    )

    r.exitCode shouldBe 0
    r.stdout should include("AGENT ID")
    r.stdout should include("agent-7a3")
    r.stdout should include("Active")
    r.stdout should include("alice@org")
    r.stdout should include("Get,Sign")
  }

  test("an agent that was never used renders 'never', not a blank column") {
    val r = Cli.run(
      List("agent", "list"),
      cfg,
      captureFactory(_ => (), body(List(agent(lastSeenAt = None)), activeCount = 1))
    )

    r.stdout should include("never")
  }

  test("a used agent renders its last-seen timestamp") {
    val seen = Instant.parse("2026-08-04T11:58:00Z")
    val r = Cli.run(
      List("agent", "list"),
      cfg,
      captureFactory(_ => (), body(List(agent(lastSeenAt = Some(seen))), activeCount = 1))
    )

    r.stdout should include(seen.toString)
    r.stdout should not include "never"
  }

  test("the footer reports how many were shown and how many are active overall") {
    val agents = List(agent("agent-1"), agent("agent-2"))
    val r = Cli.run(
      List("agent", "list"),
      cfg,
      captureFactory(_ => (), body(agents, activeCount = 7))
    )

    r.stdout should include("2 shown")
    r.stdout should include("7 active overall")
  }

  test("an empty result says so plainly and still reports the active total") {
    val r = Cli.run(
      List("agent", "list", "--status", "Revoked"),
      cfg,
      captureFactory(_ => (), body(Nil, activeCount = 4))
    )

    r.exitCode shouldBe 0
    r.stdout should include("No agents matched")
    r.stdout should include("4 active")
  }

  // ── Errors ────────────────────────────────────────────────────────────────

  test("a 501 from an unconfigured server surfaces the server's explanation") {
    val errBody = KmsErrorDto(
      "FeatureNotSupported",
      "agent registry is not enabled on this server (set aegis.audit.kind=postgres)"
    ).asJson.noSpaces
    val r = Cli.run(List("agent", "list"), cfg, captureFactory(_ => (), errBody, status = 501))

    r.exitCode should not be 0
    r.stderr should include("aegis.audit.kind=postgres")
  }

  test("a bad --status prints the usage text rather than calling the server") {
    var called = false
    val r = Cli.run(
      List("agent", "list", "--status", "zombie"),
      cfg,
      captureFactory(_ => called = true, body(Nil))
    )

    r.exitCode should not be 0
    r.stderr should include("Usage: aegis agent list")
    called shouldBe false
  }
