package dev.aegiskms.persistence

import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Validation tests for the `*JournalConfig` case classes — the `require(...)` lines in each constructor are
  * load-bearing fail-fast guards that production embedders rely on. If a future refactor removed one (e.g.
  * relaxed `jdbcUrl.nonEmpty` to `jdbcUrl != null`) the boot path would accept misconfigured input and
  * surface the failure later as a confusing JDBC error. These tests pin the contract.
  *
  * Lives in the persistence module so the library tier has its own validation coverage independent of the
  * server-tier HOCON loaders.
  */
final class JournalConfigSpec extends AnyFunSuite with Matchers:

  // ── PostgresJournalConfig ────────────────────────────────────────────────

  test("PostgresJournalConfig: empty jdbcUrl is rejected") {
    intercept[IllegalArgumentException] {
      PostgresJournalConfig(jdbcUrl = "", username = "u", password = "p", poolSize = 8)
    }.getMessage should include("jdbcUrl")
  }

  test("PostgresJournalConfig: non-positive poolSize is rejected") {
    intercept[IllegalArgumentException] {
      PostgresJournalConfig(jdbcUrl = "jdbc:postgresql://h/d", username = "u", password = "", poolSize = 0)
    }.getMessage should include("poolSize")
    intercept[IllegalArgumentException] {
      PostgresJournalConfig(jdbcUrl = "jdbc:postgresql://h/d", username = "u", password = "", poolSize = -3)
    }.getMessage should include("poolSize")
  }

  // ── MysqlJournalConfig (#49) ─────────────────────────────────────────────

  test("MysqlJournalConfig: empty jdbcUrl is rejected") {
    intercept[IllegalArgumentException] {
      MysqlJournalConfig(jdbcUrl = "", username = "u", password = "p", poolSize = 8)
    }.getMessage should include("jdbcUrl")
  }

  test("MysqlJournalConfig: non-positive poolSize is rejected") {
    intercept[IllegalArgumentException] {
      MysqlJournalConfig(jdbcUrl = "jdbc:mysql://h/d", username = "u", password = "", poolSize = 0)
    }.getMessage should include("poolSize")
  }

  // ── SqliteJournalConfig (#50) ────────────────────────────────────────────

  test("SqliteJournalConfig: empty jdbcUrl is rejected") {
    intercept[IllegalArgumentException] {
      SqliteJournalConfig(jdbcUrl = "")
    }.getMessage should include("jdbcUrl")
  }

  test(
    "SqliteJournalConfig: non-positive poolSize is rejected (operators can still misconfigure even though impl forces 1)"
  ) {
    intercept[IllegalArgumentException] {
      SqliteJournalConfig(jdbcUrl = "jdbc:sqlite::memory:", poolSize = 0)
    }.getMessage should include("poolSize")
  }

  test("SqliteJournalConfig: poolSize defaults to 1") {
    SqliteJournalConfig(jdbcUrl = "jdbc:sqlite::memory:").poolSize shouldBe 1
  }
