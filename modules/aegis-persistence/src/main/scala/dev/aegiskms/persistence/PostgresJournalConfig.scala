package dev.aegiskms.persistence

/** Connection settings for [[PostgresEventJournal]].
  *
  * The library tier intentionally has no dependency on typesafe-config so embedders can construct this from
  * any source. `aegis-server` provides a HOCON loader at boot.
  */
final case class PostgresJournalConfig(
    jdbcUrl: String,
    username: String,
    password: String,
    poolSize: Int
):
  require(jdbcUrl.nonEmpty, "jdbcUrl must not be empty")
  require(poolSize > 0, s"poolSize must be positive, was $poolSize")
