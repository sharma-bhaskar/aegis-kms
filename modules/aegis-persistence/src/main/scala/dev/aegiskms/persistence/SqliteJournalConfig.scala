package dev.aegiskms.persistence

/** Connection settings for [[SqliteEventJournal]] (#50).
  *
  * SQLite is file-based (or `:memory:` for embedded / test use), so this config is intentionally narrower
  * than the Postgres/MySQL ones — no username or password (SQLite has no auth model; file-system permissions
  * are the access boundary).
  *
  * `poolSize` defaults to **1** because SQLite serialises writes internally; a larger pool risks SQLITE_BUSY
  * errors under concurrent appends and provides no concurrency benefit. Operators with read-heavy workloads
  * who want a larger pool can override, but the safe default reflects how SQLite is actually used.
  *
  * Example URLs:
  *   - `jdbc:sqlite::memory:` — in-process, lost on shutdown (test default)
  *   - `jdbc:sqlite:/var/lib/aegis/journal.db` — file-backed durable journal
  *   - `jdbc:sqlite:file:aegis?mode=memory&cache=shared` — shared in-memory across connections
  */
final case class SqliteJournalConfig(
    jdbcUrl: String,
    poolSize: Int = 1
):
  require(jdbcUrl.nonEmpty, "jdbcUrl must not be empty")
  require(poolSize > 0, s"poolSize must be positive, was $poolSize")
