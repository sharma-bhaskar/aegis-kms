package dev.aegiskms.persistence

import dev.aegiskms.core.{KeyId, KmsError, ManagedKey}

/** SPI for a durable key-metadata store.
  *
  * Default Aegis-KMS ships a Doobie-based Postgres implementation; MySQL is supported as a secondary driver.
  * Community backends (CockroachDB, SQLite, ...) should implement this trait.
  */
trait PersistenceStore[F[_]]:
  def insert(key: ManagedKey): F[Either[KmsError, Unit]]
  def find(id: KeyId): F[Option[ManagedKey]]
  def update(key: ManagedKey): F[Either[KmsError, Unit]]
  def delete(id: KeyId): F[Either[KmsError, Unit]]
  def locate(pattern: String): F[List[ManagedKey]]
