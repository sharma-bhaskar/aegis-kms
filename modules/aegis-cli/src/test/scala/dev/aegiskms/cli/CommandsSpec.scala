package dev.aegiskms.cli

import dev.aegiskms.cli.WireFormats.*
import io.circe.syntax.*
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.nio.file.Files
import java.time.Instant

/** Tests for `Commands` — the pure command handlers. We assert exact stdout/stderr text + exit codes,
  * matching the contract scripts and humans rely on. The HTTP boundary is faked with a tiny in-memory port so
  * we don't need to spin up a server.
  */
final class CommandsSpec extends AnyFunSuite with Matchers:

  private val sampleKey =
    ManagedKeyDto(
      id = "11111111-2222-3333-4444-555555555555",
      spec = KeySpecDto("invoice-2026", "AES", 256, "SymmetricKey"),
      createdAt = Instant.parse("2026-04-25T03:00:00Z"),
      state = "PreActive"
    )

  private def stubPort(handler: HttpPort.Request => HttpPort.Response): HttpPort =
    new HttpPort:
      def execute(req: HttpPort.Request): HttpPort.Response = handler(req)

  private def clientReturning(status: Int, body: String): AegisHttpClient =
    new AegisHttpClient(stubPort(_ => HttpPort.Response(status, body)), "http://x", Some("alice@org"))

  test("version emits the canonical version string with exit 0") {
    val r = Commands.version
    r.stdout shouldBe "aegis 0.1.0-SNAPSHOT"
    r.exitCode shouldBe 0
  }

  test("login persists config to the supplied path and reports the values it saved") {
    val tmp = Files.createTempFile("aegis-test-", ".json")
    try
      val r = Commands.login("https://kms.example.com", Some("alice@org"), tmp)
      r.exitCode shouldBe 0
      r.stdout should include("Server: https://kms.example.com")
      r.stdout should include("Principal: alice@org")
      // file actually persisted
      val saved = CliConfig.load(tmp)
      saved.serverUrl shouldBe "https://kms.example.com"
      saved.principal shouldBe Some("alice@org")
    finally
      val _ = Files.deleteIfExists(tmp)
  }

  test("login without a principal still saves and reports the absence in human-friendly text") {
    val tmp = Files.createTempFile("aegis-test-", ".json")
    try
      val r = Commands.login("http://localhost:8443", None, tmp)
      r.exitCode shouldBe 0
      r.stdout should include("(no principal")
    finally
      val _ = Files.deleteIfExists(tmp)
  }

  test("keys create renders the resulting key in the human-readable block format") {
    val client = clientReturning(201, sampleKey.asJson.noSpaces)
    val r      = Commands.keysCreate(client, "AES", 256, "invoice-2026")
    r.exitCode shouldBe 0
    r.stdout should include("id:        " + sampleKey.id)
    r.stdout should include("name:      invoice-2026")
    r.stdout should include("algorithm: AES-256")
    r.stdout should include("state:     PreActive")
  }

  test("keys get renders the key when the server returns 200") {
    val client = clientReturning(200, sampleKey.asJson.noSpaces)
    val r      = Commands.keysGet(client, sampleKey.id)
    r.exitCode shouldBe 0
    r.stdout should include(sampleKey.id)
  }

  test("keys get on a missing id exits 4 (not-found) with the server's error message") {
    val errBody = KmsErrorDto("ItemNotFound", "no such key").asJson.noSpaces
    val client  = clientReturning(404, errBody)
    val r       = Commands.keysGet(client, "missing")
    r.exitCode shouldBe 4
    r.stderr should include("ItemNotFound")
    r.stderr should include("no such key")
  }

  test("keys activate on a denied call exits 5 (permission) with the server's reason") {
    val errBody = KmsErrorDto("PermissionDenied", "subject not granted Activate").asJson.noSpaces
    val client  = clientReturning(403, errBody)
    val r       = Commands.keysActivate(client, sampleKey.id)
    r.exitCode shouldBe 5
    r.stderr should include("PermissionDenied")
  }

  test("keys destroy emits a single-line confirmation on 204") {
    val client = clientReturning(204, "")
    val r      = Commands.keysDestroy(client, sampleKey.id)
    r.exitCode shouldBe 0
    r.stdout shouldBe s"destroyed ${sampleKey.id}"
  }

  test("keys create on a server 500 with non-JSON body exits 1 with the snippet visible") {
    val client = clientReturning(500, "boom")
    val r      = Commands.keysCreate(client, "AES", 256, "k")
    r.exitCode shouldBe 1
    r.stderr should include("500")
    r.stderr should include("boom")
  }

  test("agent/audit/advisor placeholders exit non-zero with a clear 'not yet wired' message") {
    Commands.agentIssue.exitCode should not be 0
    Commands.agentIssue.stderr should include("PR A1")
    Commands.auditTail.stderr should include("PR F2.b")
    Commands.advisorScan.stderr should include("PR W4")
  }
