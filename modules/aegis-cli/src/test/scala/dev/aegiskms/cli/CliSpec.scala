package dev.aegiskms.cli

import dev.aegiskms.sdk.WireFormats.*
import dev.aegiskms.sdk.{AegisHttpClient, HttpPort}
import io.circe.syntax.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.Instant

/** Tests for `Cli.run` — the top-level argument parser + dispatcher.
  *
  * We feed the real `run` function arg lists exactly as a user would type them, with a stub config and a stub
  * HTTP client factory. The tests assert exit codes and stdout/stderr text so the user-visible contract is
  * locked in.
  */
final class CliSpec extends AnyFunSuite with Matchers:

  private val cfg = CliConfig("http://localhost:8443", Some("alice@org"))

  private val sampleKey =
    ManagedKeyDto(
      id = "abc",
      spec = KeySpecDto("k", "AES", 256, "SymmetricKey"),
      createdAt = Instant.parse("2026-04-25T03:00:00Z"),
      state = "PreActive"
    )

  /** Build an `AegisHttpClient` that serves the given canned (status,body) for every request, so we don't
    * care which url the parser ends up dispatching to — we only verify that *some* request was made and the
    * response was rendered.
    */
  private def fakeClientFactory(status: Int, body: String): CliConfig => AegisHttpClient =
    cfg =>
      new AegisHttpClient(
        new HttpPort:
          def execute(req: HttpPort.Request): HttpPort.Response = HttpPort.Response(status, body)
        ,
        cfg.serverUrl,
        cfg.principal
      )

  /** A factory that captures the request the parser dispatches, so assertions about parsed flags can verify
    * what made it onto the wire. `status` defaults to 200 (the right code for `keys get`); pass 201 for `keys
    * create` since `AegisHttpClient.createKey` only treats 201 Created as success.
    */
  private def captureFactory(
      cap: HttpPort.Request => Unit,
      body: String,
      status: Int = 200
  ): CliConfig => AegisHttpClient =
    cfg =>
      new AegisHttpClient(
        new HttpPort:
          def execute(req: HttpPort.Request): HttpPort.Response = {
            cap(req); HttpPort.Response(status, body)
          }
        ,
        cfg.serverUrl,
        cfg.principal
      )

  test("no args prints help with exit 0") {
    val r = Cli.run(Nil, cfg, fakeClientFactory(200, sampleKey.asJson.noSpaces))
    r.exitCode shouldBe 0
    r.stdout should include("Usage:")
    r.stdout should include("aegis keys create")
  }

  test("'aegis version' returns the version string") {
    val r = Cli.run(List("version"), cfg, fakeClientFactory(200, sampleKey.asJson.noSpaces))
    r.stdout shouldBe s"aegis ${BuildInfo.version}"
  }

  test("'keys create --alg AES-256 --name foo' parses the combined alg-size form") {
    var captured: Option[HttpPort.Request] = None
    val r = Cli.run(
      List("keys", "create", "--alg", "AES-256", "--name", "invoice-2026"),
      cfg,
      captureFactory(req => captured = Some(req), sampleKey.asJson.noSpaces, status = 201)
    )
    r.exitCode shouldBe 0
    captured.get.method shouldBe "POST"
    captured.get.url should endWith("/v1/keys")
    captured.get.body.get should include("\"sizeBits\":256")
    captured.get.body.get should include("\"name\":\"invoice-2026\"")
  }

  test("'keys create --alg AES --size 256' parses the split form") {
    var captured: Option[HttpPort.Request] = None
    val r = Cli.run(
      List("keys", "create", "--alg", "AES", "--size", "256", "--name", "k"),
      cfg,
      captureFactory(req => captured = Some(req), sampleKey.asJson.noSpaces, status = 201)
    )
    r.exitCode shouldBe 0
    captured.get.body.get should include("\"sizeBits\":256")
    captured.get.body.get should include("\"algorithm\":\"AES\"")
  }

  test("'keys create' missing --name reports a usage error to stderr with exit 1") {
    val r = Cli.run(
      List("keys", "create", "--alg", "AES-256"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--name")
  }

  test("'keys get <id>' issues a GET to /v1/keys/<id>") {
    var captured: Option[HttpPort.Request] = None
    val _ = Cli.run(
      List("keys", "get", "abc"),
      cfg,
      captureFactory(req => captured = Some(req), sampleKey.asJson.noSpaces)
    )
    captured.get.method shouldBe "GET"
    captured.get.url should endWith("/v1/keys/abc")
  }

  test("'keys activate <id>' POSTs to /v1/keys/<id>/activate") {
    var captured: Option[HttpPort.Request] = None
    val _ = Cli.run(
      List("keys", "activate", "abc"),
      cfg,
      captureFactory(req => captured = Some(req), sampleKey.asJson.noSpaces)
    )
    captured.get.method shouldBe "POST"
    captured.get.url should endWith("/v1/keys/abc/activate")
  }

  test("'keys destroy <id>' DELETEs and exits 0 on 204") {
    var captured: Option[HttpPort.Request] = None
    val r = Cli.run(
      List("keys", "destroy", "abc"),
      cfg,
      cfg =>
        new AegisHttpClient(
          new HttpPort:
            def execute(req: HttpPort.Request): HttpPort.Response = {
              captured = Some(req); HttpPort.Response(204, "")
            }
          ,
          cfg.serverUrl,
          cfg.principal
        )
    )
    r.exitCode shouldBe 0
    captured.get.method shouldBe "DELETE"
  }

  test("unknown subcommand under 'keys' produces a structured error with usage") {
    val r = Cli.run(
      List("keys", "wat"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("unknown keys subcommand")
    r.stderr should include("aegis keys create")
  }

  test("'advisor scan' with knobs GETs /v1/advisor/scan carrying the parsed query params") {
    val report = AdvisorScanResponseDto(
      windowStart = Instant.parse("2026-03-03T00:00:00Z"),
      windowEnd = Instant.parse("2026-06-01T00:00:00Z"),
      scannedRecords = 0,
      truncated = false,
      unusedKeys = Nil,
      broadScopeAgents = Nil,
      activeAnomalies = Nil,
      riskiestAgents = Nil
    )
    var captured: Option[HttpPort.Request] = None
    val r = Cli.run(
      List("advisor", "scan", "--unused-days", "60", "--top", "3"),
      cfg,
      captureFactory(req => captured = Some(req), report.asJson.noSpaces)
    )
    r.exitCode shouldBe 0
    captured.get.method shouldBe "GET"
    captured.get.url should include("/v1/advisor/scan")
    captured.get.url should include("unusedDays=60")
    captured.get.url should include("top=3")
  }

  test("'advisor scan' with a non-numeric knob reports a usage error and exits 1") {
    val r = Cli.run(
      List("advisor", "scan", "--top", "lots"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--top must be a positive integer")
  }

  test("'advisor explain <id>' GETs /v1/advisor/explain/<id> with the parsed knobs") {
    val report = AdvisorExplainResponseDto(
      agentId = "claude-session-7a3",
      windowStart = Instant.parse("2026-03-03T00:00:00Z"),
      windowEnd = Instant.parse("2026-06-01T00:00:00Z"),
      summary = ExplainSummaryDto(0, Nil, 0, None, None),
      events = Nil,
      narrative = None,
      truncated = false
    )
    var captured: Option[HttpPort.Request] = None
    val r = Cli.run(
      List("advisor", "explain", "claude-session-7a3", "--max-events", "50"),
      cfg,
      captureFactory(req => captured = Some(req), report.asJson.noSpaces)
    )
    r.exitCode shouldBe 0
    captured.get.method shouldBe "GET"
    captured.get.url should include("/v1/advisor/explain/claude-session-7a3")
    captured.get.url should include("maxEvents=50")
  }

  test("'advisor explain' without an agent id reports a usage error and exits 1") {
    val r = Cli.run(
      List("advisor", "explain"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("<agent-id> is required")
  }

  // ── #79: agent issue ──────────────────────────────────────────────────────

  test("'agent issue' missing --label reports a usage error and exits 1") {
    val r = Cli.run(
      List("agent", "issue", "--scopes", "Sign", "--ttl", "60"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--label")
  }

  test("'agent issue' missing --scopes reports a usage error and exits 1") {
    val r = Cli.run(
      List("agent", "issue", "--label", "demo", "--ttl", "60"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--scopes")
  }

  test("'agent issue' missing --ttl reports a usage error and exits 1") {
    val r = Cli.run(
      List("agent", "issue", "--label", "demo", "--scopes", "Sign"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--ttl")
  }

  test("'agent issue' rejects a non-numeric --ttl with a clear error") {
    val r = Cli.run(
      List("agent", "issue", "--label", "demo", "--scopes", "Sign", "--ttl", "abc"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--ttl")
    r.stderr should include("abc")
  }

  test("'agent issue' rejects a non-positive --ttl with a clear error") {
    val r = Cli.run(
      List("agent", "issue", "--label", "demo", "--scopes", "Sign", "--ttl", "0"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--ttl")
  }

  test("'agent issue --label … --scopes … --ttl …' POSTs to /v1/agents/issue with parsed scopes") {
    var captured: Option[HttpPort.Request] = None
    val responseBody =
      IssueAgentResponseDto(
        agentId = "agent-7a3",
        jwt = "eyJ.fake.jwt",
        jti = "0000-jti",
        expiresAt = Instant.parse("2026-05-25T10:00:00Z")
      ).asJson.noSpaces
    val r = Cli.run(
      List(
        "agent",
        "issue",
        "--label",
        "claude-invoice-batch",
        "--scopes",
        "Sign, Get , Encrypt",
        "--ttl",
        "3600",
        "--parent",
        "alice@org"
      ),
      cfg,
      captureFactory(req => captured = Some(req), responseBody, status = 201)
    )
    r.exitCode shouldBe 0
    captured.get.method shouldBe "POST"
    captured.get.url should endWith("/v1/agents/issue")
    val body = captured.get.body.get
    body should include("\"label\":\"claude-invoice-batch\"")
    body should include("\"ttlSeconds\":3600")
    body should include("\"parent\":\"alice@org\"")
    // Scopes are split + trimmed, so the server sees a clean list rather than a single string.
    body should include("\"scopes\":[\"Sign\",\"Get\",\"Encrypt\"]")
    r.stdout should include("agentId:   agent-7a3")
    r.stdout should include("jti:       0000-jti")
    r.stdout should include("jwt:       eyJ.fake.jwt")
  }

  test("'agent issue' parser test: scopes are split, trimmed, and empty tokens dropped") {
    val r = Cli.parseAgentIssue(
      List("--label", "x", "--scopes", "Sign,, Get ,", "--ttl", "60")
    )
    r shouldBe Right(("x", List("Sign", "Get"), 60L, None))
  }

  test("'agent issue' renders server 403 with a PermissionDenied exit code (5)") {
    val errBody =
      KmsErrorDto("PermissionDenied", "only Humans may issue agent tokens").asJson.noSpaces
    val r = Cli.run(
      List("agent", "issue", "--label", "x", "--scopes", "Sign", "--ttl", "60"),
      cfg,
      fakeClientFactory(403, errBody)
    )
    r.exitCode shouldBe 5
    r.stderr should include("PermissionDenied")
  }

  // ── #79: audit tail ───────────────────────────────────────────────────────

  test("'audit tail' parser test: all flags default to None and watch=false") {
    val r = Cli.parseAuditTail(Nil)
    r shouldBe Right(
      Cli.AuditTailFilter(None, None, None, None, None, None, None, watch = false)
    )
  }

  test("'audit tail' parser test: --limit / --offset must parse as integers") {
    Cli.parseAuditTail(List("--limit", "abc")).isLeft shouldBe true
    Cli.parseAuditTail(List("--limit", "-1")).isLeft shouldBe true
    Cli.parseAuditTail(List("--offset", "-1")).isLeft shouldBe true
    Cli.parseAuditTail(List("--limit", "50", "--offset", "100")).map(f =>
      (f.limit, f.offset)
    ) shouldBe Right((Some(50), Some(100)))
  }

  test("'audit tail' parser test: --watch is recognised as a boolean flag") {
    val r = Cli.parseAuditTail(List("--watch", "--actor", "alice@org"))
    r.map(_.watch) shouldBe Right(true)
    r.map(_.actor) shouldBe Right(Some("alice@org"))
  }

  test("'audit tail --actor alice --op Sign' issues a GET /v1/audit with url-encoded query params") {
    var captured: Option[HttpPort.Request] = None
    val responseBody = AuditQueryResponseDto(
      records = List(
        AuditRecordDto(
          at = Instant.parse("2026-05-25T09:00:00Z"),
          actor = "alice@org",
          actorKind = "Human",
          operation = "Sign",
          resource = "key:abc",
          outcome = "Allowed",
          correlationId = "corr-1",
          context = Map("source.ip" -> "10.0.0.1")
        )
      ),
      limit = 100,
      offset = 0,
      hasMore = false
    ).asJson.noSpaces
    val r = Cli.run(
      List("audit", "tail", "--actor", "alice@org", "--op", "Sign", "--limit", "50"),
      cfg,
      captureFactory(req => captured = Some(req), responseBody, status = 200)
    )
    r.exitCode shouldBe 0
    captured.get.method shouldBe "GET"
    captured.get.url should include("/v1/audit?")
    captured.get.url should include("actor=alice%40org")
    captured.get.url should include("op=Sign")
    captured.get.url should include("limit=50")
    r.stdout should include("actor:      alice@org (Human)")
    r.stdout should include("operation:  Sign")
    r.stdout should include("source.ip=10.0.0.1")
  }

  test("'agent issue' happy path without --parent omits the parent field on the wire") {
    var captured: Option[HttpPort.Request] = None
    val responseBody =
      IssueAgentResponseDto(
        agentId = "agent-no-parent",
        jwt = "eyJ.fake",
        jti = "j-1",
        expiresAt = Instant.parse("2026-05-25T11:00:00Z")
      ).asJson.noSpaces
    val r = Cli.run(
      List("agent", "issue", "--label", "demo", "--scopes", "Sign", "--ttl", "60"),
      cfg,
      captureFactory(req => captured = Some(req), responseBody, status = 201)
    )
    r.exitCode shouldBe 0
    // `parent: Option[String]` is encoded as `"parent":null` by default circe — we want the
    // server to apply its caller-subject default, so make sure we either omit the field or
    // send null (both shapes are fine; we just lock in current behavior).
    val body = captured.get.body.get
    body should (include("\"parent\":null").or(not include "\"parent\":"))
    r.stdout should include("agentId:   agent-no-parent")
  }

  test("'audit tail' renders multiple records separated by '---' with a record-count footer") {
    val now = Instant.parse("2026-05-25T09:00:00Z")
    val responseBody = AuditQueryResponseDto(
      records = List(
        AuditRecordDto(now, "alice@org", "Human", "Sign", "key:a", "Allowed", "c-1", Map.empty),
        AuditRecordDto(
          now.plusSeconds(1),
          "agent-7a3",
          "Agent",
          "Get",
          "key:b",
          "Denied",
          "c-2",
          Map("reason" -> "stepUpRequired")
        )
      ),
      limit = 100,
      offset = 0,
      hasMore = false
    ).asJson.noSpaces
    val r = Cli.run(List("audit", "tail"), cfg, fakeClientFactory(200, responseBody))
    r.exitCode shouldBe 0
    r.stdout should include("alice@org (Human)")
    r.stdout should include("agent-7a3 (Agent)")
    r.stdout should include("operation:  Get")
    r.stdout should include("reason=stepUpRequired")
    // Two records → exactly one separator between them (the footer adds one more).
    r.stdout.split("\n---\n").length shouldBe 3
    r.stdout should include("2 record(s)")
  }

  test("'audit tail' surfaces hasMore=true in the footer so users know to paginate") {
    val responseBody = AuditQueryResponseDto(
      records = List(
        AuditRecordDto(
          Instant.parse("2026-05-25T09:00:00Z"),
          "alice@org",
          "Human",
          "Sign",
          "key:a",
          "Allowed",
          "c-1",
          Map.empty
        )
      ),
      limit = 1,
      offset = 0,
      hasMore = true
    ).asJson.noSpaces
    val r = Cli.run(List("audit", "tail", "--limit", "1"), cfg, fakeClientFactory(200, responseBody))
    r.exitCode shouldBe 0
    r.stdout should include("hasMore=true")
  }

  // ── #79: watch-mode helper (`extractMaxAt`) ───────────────────────────────

  test("extractMaxAt returns None on the empty-state footer (so --since doesn't regress)") {
    Cli.extractMaxAt("(no records; offset=0, limit=100)") shouldBe None
  }

  test("extractMaxAt picks the max ISO timestamp across multiple records, ignoring order") {
    // Two records on one page; the later `at:` value should win even though it appears first.
    val rendered =
      """at:         2026-05-25T09:00:05Z
        |actor:      alice@org (Human)
        |operation:  Sign
        |---
        |at:         2026-05-25T09:00:01Z
        |actor:      bob@org (Human)
        |operation:  Get""".stripMargin
    Cli.extractMaxAt(rendered) shouldBe Some("2026-05-25T09:00:05Z")
  }

  test("extractMaxAt ignores non-at lines (actor:, operation:, footer)") {
    val rendered =
      """at:         2026-05-25T09:00:00Z
        |actor:      alice (Human)
        |operation:  Sign
        |context:    at=annotation (a red herring)""".stripMargin
    // The `context: at=annotation` line starts with `context:`, not `at:` — must not be picked up.
    Cli.extractMaxAt(rendered) shouldBe Some("2026-05-25T09:00:00Z")
  }

  test("'audit tail' on an empty page prints a friendly empty-state line, not a blank") {
    val responseBody = AuditQueryResponseDto(Nil, 100, 0, hasMore = false).asJson.noSpaces
    val r = Cli.run(
      List("audit", "tail"),
      cfg,
      fakeClientFactory(200, responseBody)
    )
    r.exitCode shouldBe 0
    r.stdout should include("(no records")
  }

  test("entirely unknown command produces an error and includes the help block") {
    val r = Cli.run(List("totally", "made", "up"), cfg, fakeClientFactory(200, sampleKey.asJson.noSpaces))
    r.exitCode shouldBe 1
    r.stderr should include("unknown command")
    r.stderr should include("Usage:")
  }

  test("login parser: '--principal alice' is the canonical form documented in the README") {
    // Regression for the bug where the parser only read `--user` and silently saved a None
    // principal even though the README documented `--principal`.
    val r = Cli.parseLogin(List("--server", "http://localhost:9999", "--principal", "alice"))
    r shouldBe Right(("http://localhost:9999", Some("alice")))
  }

  test("login parser: '--user alice' still works as a deprecated alias") {
    // Back-compat: scripts written against the old help text continue working.
    val r = Cli.parseLogin(List("--server", "http://localhost:9999", "--user", "alice"))
    r shouldBe Right(("http://localhost:9999", Some("alice")))
  }

  test("login parser: '--principal' wins when both flags are supplied") {
    val r = Cli.parseLogin(
      List("--server", "http://localhost:9999", "--principal", "alice", "--user", "bob")
    )
    r shouldBe Right(("http://localhost:9999", Some("alice")))
  }

  test("login parser: missing --server is a clear error") {
    val r = Cli.parseLogin(List("--principal", "alice"))
    r.isLeft shouldBe true
    r.left.toOption.get should include("--server")
  }

  test("'keys sign' missing --message reports a usage error and exits 1") {
    val r = Cli.run(
      List("keys", "sign", "--id", "abc"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--message")
  }

  test("'keys sign --id <id> --message <text>' POSTs to /sign with the algorithm default") {
    var captured: Option[HttpPort.Request] = None
    val responseBody                       = SignResponse("c2ln", "RsaPssSha256").asJson.noSpaces
    val r = Cli.run(
      List("keys", "sign", "--id", "abc", "--message", "hello"),
      cfg,
      captureFactory(req => captured = Some(req), responseBody, status = 200)
    )
    r.exitCode shouldBe 0
    captured.get.method shouldBe "POST"
    captured.get.url should endWith("/v1/keys/abc/sign")
    captured.get.body.get should include("\"algorithm\":\"RsaPssSha256\"")
  }

  test("'keys verify' missing --signature reports a usage error and exits 1") {
    val r = Cli.run(
      List("keys", "verify", "--id", "abc", "--message", "x"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--signature")
  }

  test("'keys verify' renders valid:true on a server 'valid:true' response") {
    val responseBody = VerifyResponse(true, "RsaPssSha256").asJson.noSpaces
    val r = Cli.run(
      List("keys", "verify", "--id", "abc", "--message", "hi", "--signature", "c2ln"),
      cfg,
      fakeClientFactory(200, responseBody)
    )
    r.exitCode shouldBe 0
    r.stdout should include("valid: true")
  }

  test("'keys encrypt' missing --plaintext reports a usage error and exits 1") {
    val r = Cli.run(
      List("keys", "encrypt", "--id", "abc"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--plaintext")
  }

  test("'keys encrypt --id <id> --plaintext <text> --context k=v' POSTs to /encrypt with the context map") {
    var captured: Option[HttpPort.Request] = None
    val responseBody =
      EncryptResponse("Y2lwaGVy", Map("dataset" -> "q2")).asJson.noSpaces
    val r = Cli.run(
      List(
        "keys",
        "encrypt",
        "--id",
        "abc",
        "--plaintext",
        "hello",
        "--context",
        "dataset=q2"
      ),
      cfg,
      captureFactory(req => captured = Some(req), responseBody, status = 200)
    )
    r.exitCode shouldBe 0
    captured.get.method shouldBe "POST"
    captured.get.url should endWith("/v1/keys/abc/encrypt")
    captured.get.body.get should include("\"context\":{\"dataset\":\"q2\"}")
    r.stdout should include("ciphertext: Y2lwaGVy")
  }

  test("'keys encrypt' rejects malformed --context entries with a clear error") {
    val r = Cli.run(
      List("keys", "encrypt", "--id", "abc", "--plaintext", "x", "--context", "no-equals"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--context")
  }

  test("'keys decrypt --id <id> --ciphertext <b64>' POSTs to /decrypt and renders the plaintext") {
    var captured: Option[HttpPort.Request] = None
    val ptB64                              = java.util.Base64.getEncoder.encodeToString("hello".getBytes)
    val responseBody                       = DecryptResponse(ptB64, Map.empty).asJson.noSpaces
    val r = Cli.run(
      List("keys", "decrypt", "--id", "abc", "--ciphertext", "Y2lwaGVy"),
      cfg,
      captureFactory(req => captured = Some(req), responseBody, status = 200)
    )
    r.exitCode shouldBe 0
    captured.get.url should endWith("/v1/keys/abc/decrypt")
    r.stdout should include(s"plaintext: $ptB64")
  }

  test("'keys wrap' missing --dek reports a usage error and exits 1") {
    val r = Cli.run(
      List("keys", "wrap", "--id", "abc"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--dek")
  }

  test("'keys wrap --id <id> --dek <text>' POSTs to /wrap and prints the wrapped blob") {
    var captured: Option[HttpPort.Request] = None
    val responseBody                       = WrapResponse("d3JhcHBlZA==").asJson.noSpaces
    val r = Cli.run(
      List("keys", "wrap", "--id", "abc", "--dek", "secret-dek"),
      cfg,
      captureFactory(req => captured = Some(req), responseBody, status = 200)
    )
    r.exitCode shouldBe 0
    captured.get.method shouldBe "POST"
    captured.get.url should endWith("/v1/keys/abc/wrap")
    captured.get.body.get should include("\"dekBase64\":")
    r.stdout should include("wrapped: d3JhcHBlZA==")
  }

  test("'keys unwrap --id <id> --wrapped <b64>' POSTs to /unwrap and renders the DEK as base64") {
    var captured: Option[HttpPort.Request] = None
    val dekB64                             = java.util.Base64.getEncoder.encodeToString("secret-dek".getBytes)
    val responseBody                       = UnwrapResponse(dekB64).asJson.noSpaces
    val r = Cli.run(
      List("keys", "unwrap", "--id", "abc", "--wrapped", "d3JhcHBlZA=="),
      cfg,
      captureFactory(req => captured = Some(req), responseBody, status = 200)
    )
    r.exitCode shouldBe 0
    captured.get.url should endWith("/v1/keys/abc/unwrap")
    r.stdout should include(s"dek: $dekB64")
  }

  test("'keys compromise' missing --reason reports a usage error and exits 1") {
    val r = Cli.run(
      List("keys", "compromise", "--id", "abc"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--reason")
  }

  test("'keys compromise' empty --reason is rejected (audit trail must have a justification)") {
    val r = Cli.run(
      List("keys", "compromise", "--id", "abc", "--reason", ""),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--reason")
  }

  test("'keys compromise --id <id> --reason <text>' POSTs to /compromise with the reason in the body") {
    var captured: Option[HttpPort.Request] = None
    val compromisedKey                     = sampleKey.copy(state = "Compromised")
    val r = Cli.run(
      List("keys", "compromise", "--id", "abc", "--reason", "leaked in S3 audit"),
      cfg,
      captureFactory(req => captured = Some(req), compromisedKey.asJson.noSpaces, status = 200)
    )
    r.exitCode shouldBe 0
    captured.get.method shouldBe "POST"
    captured.get.url should endWith("/v1/keys/abc/compromise")
    captured.get.body.get should include("\"reason\":\"leaked in S3 audit\"")
    r.stdout should include("compromised abc")
    r.stdout should include("state:  Compromised")
  }

  test("'keys rotate' missing --id reports a usage error and exits 1") {
    val r = Cli.run(
      List("keys", "rotate"),
      cfg,
      fakeClientFactory(200, sampleKey.asJson.noSpaces)
    )
    r.exitCode shouldBe 1
    r.stderr should include("--id")
  }

  test("'keys rotate --id <id>' defaults policy to Manual and POSTs to /rotate") {
    var captured: Option[HttpPort.Request] = None
    val rotatedKey                         = sampleKey.copy(state = "Active", currentVersion = 2)
    val r = Cli.run(
      List("keys", "rotate", "--id", "abc"),
      cfg,
      captureFactory(req => captured = Some(req), rotatedKey.asJson.noSpaces, status = 200)
    )
    r.exitCode shouldBe 0
    captured.get.method shouldBe "POST"
    captured.get.url should endWith("/v1/keys/abc/rotate")
    captured.get.body.get should include("\"policy\":\"Manual\"")
    r.stdout should include("rotated abc")
    r.stdout should include("version: 2")
    r.stdout should include("policy:  Manual")
  }

  test("'keys rotate --id <id> --policy TimeBased:7days' carries the policy on the wire") {
    var captured: Option[HttpPort.Request] = None
    val rotatedKey                         = sampleKey.copy(state = "Active", currentVersion = 2)
    val r = Cli.run(
      List("keys", "rotate", "--id", "abc", "--policy", "TimeBased:7days"),
      cfg,
      captureFactory(req => captured = Some(req), rotatedKey.asJson.noSpaces, status = 200)
    )
    r.exitCode shouldBe 0
    captured.get.body.get should include("\"policy\":\"TimeBased:7days\"")
  }
