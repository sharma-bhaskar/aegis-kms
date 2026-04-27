package dev.aegiskms.cli

import dev.aegiskms.cli.WireFormats.*
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
    r.stdout shouldBe "aegis 0.1.0-SNAPSHOT"
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

  test("placeholder commands still surface a clear non-zero exit so scripts notice") {
    val factory = fakeClientFactory(200, sampleKey.asJson.noSpaces)
    Cli.run(List("agent", "issue"), cfg, factory).exitCode should not be 0
    Cli.run(List("audit", "tail"), cfg, factory).exitCode should not be 0
    Cli.run(List("advisor", "scan"), cfg, factory).exitCode should not be 0
  }

  test("entirely unknown command produces an error and includes the help block") {
    val r = Cli.run(List("totally", "made", "up"), cfg, fakeClientFactory(200, sampleKey.asJson.noSpaces))
    r.exitCode shouldBe 1
    r.stderr should include("unknown command")
    r.stderr should include("Usage:")
  }
