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
    r.stdout shouldBe s"aegis ${BuildInfo.version}"
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

  test("advisor scan is still a placeholder and exits non-zero with a clear message") {
    // `agent issue` and `audit tail` are real in #79; only `advisor scan` (PR W4) remains a stub.
    Commands.advisorScan.exitCode should not be 0
    Commands.advisorScan.stderr should include("PR W4")
  }

  test("keys sign prints the base64 signature and algorithm on success") {
    val responseBody = SignResponse("c2lnLWJ5dGVz", "RsaPssSha256").asJson.noSpaces
    val client       = clientReturning(200, responseBody)
    val r            = Commands.keysSign(client, sampleKey.id, "hello", "RsaPssSha256")
    r.exitCode shouldBe 0
    r.stdout should include("signature: c2lnLWJ5dGVz")
    r.stdout should include("algorithm: RsaPssSha256")
  }

  test("keys verify on a valid signature emits 'valid: true' with exit 0") {
    val responseBody = VerifyResponse(true, "RsaPssSha256").asJson.noSpaces
    val client       = clientReturning(200, responseBody)
    val r            = Commands.keysVerify(client, sampleKey.id, "hello", "c2ln", "RsaPssSha256")
    r.exitCode shouldBe 0
    r.stdout should include("valid: true")
  }

  test("keys verify on an invalid signature exits 3 with 'valid: false'") {
    val responseBody = VerifyResponse(false, "RsaPssSha256").asJson.noSpaces
    val client       = clientReturning(200, responseBody)
    val r            = Commands.keysVerify(client, sampleKey.id, "hello", "c2ln", "RsaPssSha256")
    r.exitCode shouldBe 3
    r.stderr should include("valid: false")
  }

  test("keys sign --message @file reads the bytes off disk") {
    val tmp = Files.createTempFile("aegis-msg-", ".bin")
    try
      Files.write(tmp, "from-file".getBytes("UTF-8"))
      val responseBody = SignResponse("c2ln", "RsaPssSha256").asJson.noSpaces
      val client       = clientReturning(200, responseBody)
      val r            = Commands.keysSign(client, sampleKey.id, s"@${tmp.toAbsolutePath}", "RsaPssSha256")
      r.exitCode shouldBe 0
      r.stdout should include("signature:")
    finally
      val _ = Files.deleteIfExists(tmp)
  }

  test("keys encrypt prints the base64 ciphertext and the context that was supplied") {
    val responseBody =
      EncryptResponse("Y2lwaGVy", Map("dataset" -> "q2", "tenant" -> "acme")).asJson.noSpaces
    val client = clientReturning(200, responseBody)
    val r = Commands.keysEncrypt(
      client,
      sampleKey.id,
      "hello",
      Map("dataset" -> "q2", "tenant" -> "acme")
    )
    r.exitCode shouldBe 0
    r.stdout should include("ciphertext: Y2lwaGVy")
    r.stdout should include("context: dataset=q2,tenant=acme")
  }

  test("keys decrypt on success prints the plaintext as base64") {
    val ptB64        = java.util.Base64.getEncoder.encodeToString("hello".getBytes("UTF-8"))
    val responseBody = DecryptResponse(ptB64, Map.empty).asJson.noSpaces
    val client       = clientReturning(200, responseBody)
    val r            = Commands.keysDecrypt(client, sampleKey.id, "Y2lwaGVy", Map.empty)
    r.exitCode shouldBe 0
    r.stdout should include(s"plaintext: $ptB64")
  }

  test("keys decrypt on a CryptographicFailure exits 1 with the server's reason") {
    val errBody = """{"code":"CryptographicFailure","message":"context mismatch"}"""
    val client  = clientReturning(500, errBody)
    val r       = Commands.keysDecrypt(client, sampleKey.id, "Y2lwaGVy", Map("a" -> "wrong"))
    r.exitCode shouldBe 1
    r.stderr should include("CryptographicFailure")
  }

  test("keys wrap prints the base64 wrapped blob on success") {
    val responseBody = WrapResponse("d3JhcHBlZA==").asJson.noSpaces
    val client       = clientReturning(200, responseBody)
    val r            = Commands.keysWrap(client, sampleKey.id, "secret-dek")
    r.exitCode shouldBe 0
    r.stdout should include("wrapped: d3JhcHBlZA==")
  }

  test("keys unwrap on success prints the DEK as base64") {
    val dekB64       = java.util.Base64.getEncoder.encodeToString("secret-dek".getBytes("UTF-8"))
    val responseBody = UnwrapResponse(dekB64).asJson.noSpaces
    val client       = clientReturning(200, responseBody)
    val r            = Commands.keysUnwrap(client, sampleKey.id, "d3JhcHBlZA==")
    r.exitCode shouldBe 0
    r.stdout should include(s"dek: $dekB64")
  }

  test("keys wrap on a denied call exits 5 (permission) with the server's reason") {
    val errBody = KmsErrorDto("PermissionDenied", "subject not granted Wrap").asJson.noSpaces
    val client  = clientReturning(403, errBody)
    val r       = Commands.keysWrap(client, sampleKey.id, "dek")
    r.exitCode shouldBe 5
    r.stderr should include("PermissionDenied")
  }

  test("keys compromise prints the resulting state and the reason on success") {
    val compromisedKey = sampleKey.copy(state = "Compromised")
    val client         = clientReturning(200, compromisedKey.asJson.noSpaces)
    val r              = Commands.keysCompromise(client, sampleKey.id, "leaked in S3 audit")
    r.exitCode shouldBe 0
    r.stdout should include(s"compromised ${sampleKey.id}")
    r.stdout should include("reason: leaked in S3 audit")
    r.stdout should include("state:  Compromised")
  }

  test("keys compromise on an already-Destroyed key exits non-zero with IllegalOperation") {
    val errBody = KmsErrorDto("IllegalOperation", "Key is Destroyed").asJson.noSpaces
    val client  = clientReturning(500, errBody)
    val r       = Commands.keysCompromise(client, sampleKey.id, "too late")
    r.exitCode shouldBe 1
    r.stderr should include("IllegalOperation")
  }

  test("keys rotate prints the new version and the policy on success") {
    val rotatedKey = sampleKey.copy(state = "Active", currentVersion = 2)
    val client     = clientReturning(200, rotatedKey.asJson.noSpaces)
    val r          = Commands.keysRotate(client, sampleKey.id, "Manual")
    r.exitCode shouldBe 0
    r.stdout should include(s"rotated ${sampleKey.id}")
    r.stdout should include("version: 2")
    r.stdout should include("policy:  Manual")
  }

  test("keys rotate on a non-Active source state exits 1 with IllegalOperation") {
    val errBody =
      KmsErrorDto("IllegalOperation", "Key is PreActive, must be Active").asJson.noSpaces
    val client = clientReturning(500, errBody)
    val r      = Commands.keysRotate(client, sampleKey.id, "Manual")
    r.exitCode shouldBe 1
    r.stderr should include("IllegalOperation")
  }
