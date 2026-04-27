package dev.aegiskms.cli

import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.nio.file.{Files, Paths}

/** Tests for `CliConfig`. We exercise the real filesystem in a tmp dir — the operations are simple and
  * mocking the JDK's NIO would be more brittle than just letting it run.
  */
final class ConfigSpec extends AnyFunSuite with Matchers:

  test("save then load round-trips serverUrl and principal") {
    val tmp = Files.createTempFile("aegis-cfg-", ".json")
    try
      CliConfig.save(CliConfig("https://kms.example", Some("alice@org")), tmp)
      val loaded = CliConfig.load(tmp)
      loaded.serverUrl shouldBe "https://kms.example"
      loaded.principal shouldBe Some("alice@org")
    finally
      val _ = Files.deleteIfExists(tmp)
  }

  test("load on a missing file falls back to localhost defaults instead of throwing") {
    val missing = Paths.get(System.getProperty("java.io.tmpdir"), "nope-" + System.nanoTime + ".json")
    Files.exists(missing) shouldBe false
    val cfg = CliConfig.load(missing)
    cfg.serverUrl shouldBe "http://localhost:8443"
    cfg.principal shouldBe None
  }

  test("save creates parent directories that don't exist yet") {
    val nested = Paths.get(
      System.getProperty("java.io.tmpdir"),
      s"aegis-test-${System.nanoTime}",
      "deep",
      "config.json"
    )
    try
      CliConfig.save(CliConfig("https://x", None), nested)
      Files.exists(nested) shouldBe true
      CliConfig.load(nested).serverUrl shouldBe "https://x"
    finally
      val _ = Files.deleteIfExists(nested)
      val _ = Files.deleteIfExists(nested.getParent)
      val _ = Files.deleteIfExists(nested.getParent.getParent)
  }

  test("a corrupt config file falls through to defaults rather than crashing") {
    val tmp = Files.createTempFile("aegis-cfg-", ".json")
    try
      Files.write(tmp, "this is not json".getBytes)
      val cfg = CliConfig.load(tmp)
      // No file-derived value: falls through to the hard-coded default URL and no principal.
      cfg.serverUrl shouldBe "http://localhost:8443"
      cfg.principal shouldBe None
    finally
      val _ = Files.deleteIfExists(tmp)
  }
