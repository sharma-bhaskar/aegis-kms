package dev.aegiskms.persistence

/** Connection settings for [[MysqlEventJournal]] (#49).
  *
  * Mirrors [[PostgresJournalConfig]] in shape (same JDBC connection knobs) but is a distinct type so the boot
  * wiring can branch on it without ambiguity and so MySQL-only options (e.g. server-side prepared statement
  * caching) can be added later without polluting the Postgres config.
  *
  * The library tier intentionally has no dependency on typesafe-config so embedders can construct this from
  * any source. `aegis-server` provides a HOCON loader at boot.
  */
final case class MysqlJournalConfig(
    jdbcUrl: String,
    username: String,
    password: String,
    poolSize: Int
):
  require(jdbcUrl.nonEmpty, "jdbcUrl must not be empty")
  require(poolSize > 0, s"poolSize must be positive, was $poolSize")
