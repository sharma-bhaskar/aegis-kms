package dev.aegiskms.crypto.software

import dev.aegiskms.core.SigAlgorithm

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.nio.file.{Files, Path, StandardCopyOption}
import java.security.spec.{ECGenParameterSpec, PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, KeyPairGenerator, KeyStore, PrivateKey, PublicKey, SecureRandom}
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/** JDK `KeyStore`-backed key material for [[SoftwareRootOfTrust]].
  *
  * Holds three kinds of entry, all as PKCS#12 `SecretKeyEntry` records:
  *
  *   - `aegis-kek-v<N>` — the AES-256 key-encryption key, one entry per rotation generation. `rotate` mints
  *     `v(N+1)` and leaves every earlier generation in place, so ciphertext produced before a rotation stays
  *     decryptable (the generation number is carried in the ciphertext header).
  *   - `aegis-sig-<alg>-private` / `-public` — PKCS#8 / X.509 encodings of the signing keypair, wrapped in a
  *     `SecretKeySpec` so no self-signed certificate has to be manufactured. PKCS#12 `PrivateKeyEntry`
  *     requires a certificate chain, and building one without a third-party library means reaching into
  *     `sun.security.x509`, which is not exported on JDK 17+. Storing the encoded blobs sidesteps that
  *     entirely and keeps this module dependency-free.
  *
  * Signing keypairs are generated lazily on first use — a deployment that only does envelope operations never
  * pays the RSA-3072 keygen cost, and the test suite only pays it in the tests that sign.
  *
  * **This class holds raw key material in the JVM heap.** That is a deliberate violation of the
  * [[dev.aegiskms.crypto.RootOfTrust]] contract's "no plaintext key material outside the secure boundary"
  * rule, and it is why [[SoftwareRootOfTrust]] is dev/test-only. See that class's scaladoc.
  *
  * All mutating operations synchronize on the underlying `KeyStore`; the persisted file is rewritten via a
  * temporary file and an atomic move so a crash mid-save cannot leave a truncated keystore behind.
  */
final class SoftwareKeyStore private (
    store: KeyStore,
    password: Array[Char],
    path: Option[Path]
):

  private val random = new SecureRandom()

  private def protection = new KeyStore.PasswordProtection(password)

  /** Highest KEK generation currently in the keystore. */
  def currentKekVersion: Int = store.synchronized {
    SoftwareKeyStore.highestKekVersion(store).getOrElse(
      throw new IllegalStateException("keystore contains no KEK entry")
    )
  }

  /** The KEK for a specific generation. Fails when the generation is absent — that means ciphertext was
    * produced against a keystore this one is not a descendant of.
    */
  def kek(version: Int): SecretKey =
    store.synchronized {
      Option(store.getEntry(SoftwareKeyStore.kekAlias(version), protection)) match
        case Some(e: KeyStore.SecretKeyEntry) => e.getSecretKey
        case _ =>
          throw new IllegalArgumentException(
            s"no KEK generation v$version in this keystore (current is v$currentKekVersion) — " +
              "this ciphertext was produced against different key material"
          )
    }

  /** Mint the next KEK generation and persist. Returns the new generation number. Earlier generations are
    * retained so previously wrapped material remains recoverable.
    */
  def rotateKek(): Int =
    store.synchronized {
      val next = currentKekVersion + 1
      store.setEntry(SoftwareKeyStore.kekAlias(next), SoftwareKeyStore.freshKek(random), protection)
      persist()
      next
    }

  /** The signing keypair for `alg`, generating and persisting it on first request. */
  def signingKeyPair(alg: SigAlgorithm): (PrivateKey, PublicKey) =
    store.synchronized {
      val (privAlias, pubAlias) = SoftwareKeyStore.sigAliases(alg)
      (encodedEntry(privAlias), encodedEntry(pubAlias)) match
        case (Some(privBytes), Some(pubBytes)) =>
          val factory = KeyFactory.getInstance(SoftwareKeyStore.keyFactoryAlgorithm(alg))
          (
            factory.generatePrivate(new PKCS8EncodedKeySpec(privBytes)),
            factory.generatePublic(new X509EncodedKeySpec(pubBytes))
          )
        case _ =>
          val pair = SoftwareKeyStore.generateSigningKeyPair(alg, random)
          store.setEntry(privAlias, SoftwareKeyStore.blobEntry(pair.getPrivate.getEncoded), protection)
          store.setEntry(pubAlias, SoftwareKeyStore.blobEntry(pair.getPublic.getEncoded), protection)
          persist()
          (pair.getPrivate, pair.getPublic)
    }

  private def encodedEntry(alias: String): Option[Array[Byte]] =
    Option(store.getEntry(alias, protection)).collect { case e: KeyStore.SecretKeyEntry =>
      e.getSecretKey.getEncoded
    }

  /** Write the keystore back to disk, if this instance is file-backed. Ephemeral keystores are a no-op. */
  private def persist(): Unit =
    path.foreach { target =>
      val tmp = target.resolveSibling(s"${target.getFileName}.tmp")
      val out = new ByteArrayOutputStream()
      store.store(out, password)
      Files.write(tmp, out.toByteArray)
      Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
    }

object SoftwareKeyStore:

  /** PKCS#12 is the JDK's default keystore format and the only standard one that stores secret keys. */
  private val StoreType = "PKCS12"

  private val KekSizeBits = 256
  private val RsaSizeBits = 3072
  private val EcCurve     = "secp256r1"

  private val KekAliasPrefix = "aegis-kek-v"

  /** Open a file-backed keystore, creating it (with a first-generation KEK) if it does not exist.
    *
    * The file is created with owner-only permissions where the filesystem supports POSIX permissions. It
    * still contains raw key material protected only by `password` — treat it exactly as you would a private
    * key.
    */
  def atPath(path: Path, password: String): SoftwareKeyStore =
    val chars = password.toCharArray
    val store = KeyStore.getInstance(StoreType)
    if Files.exists(path) then
      val bytes = Files.readAllBytes(path)
      store.load(new ByteArrayInputStream(bytes), chars)
      if highestKekVersion(store).isEmpty then
        throw new IllegalStateException(
          s"keystore at $path has no $KekAliasPrefix* entry — it was not created by Aegis"
        )
      new SoftwareKeyStore(store, chars, Some(path))
    else
      store.load(null, chars)
      store.setEntry(kekAlias(1), freshKek(new SecureRandom()), new KeyStore.PasswordProtection(chars))
      Option(path.getParent).foreach(Files.createDirectories(_))
      val ks = new SoftwareKeyStore(store, chars, Some(path))
      ks.persist()
      restrictPermissions(path)
      ks

  /** Open an in-heap keystore with a freshly generated KEK. Nothing is written to disk, so every key wrapped
    * against it becomes unrecoverable when the JVM exits. Intended for tests and throwaway demos.
    */
  def ephemeral(): SoftwareKeyStore =
    val chars = java.util.UUID.randomUUID().toString.toCharArray
    val store = KeyStore.getInstance(StoreType)
    store.load(null, chars)
    store.setEntry(kekAlias(1), freshKek(new SecureRandom()), new KeyStore.PasswordProtection(chars))
    new SoftwareKeyStore(store, chars, None)

  private def kekAlias(version: Int): String = s"$KekAliasPrefix$version"

  private def sigAliases(alg: SigAlgorithm): (String, String) =
    val base = alg match
      case SigAlgorithm.RsaPssSha256 => "aegis-sig-rsa"
      case SigAlgorithm.EcdsaSha256  => "aegis-sig-ec"
    (s"$base-private", s"$base-public")

  private def keyFactoryAlgorithm(alg: SigAlgorithm): String = alg match
    case SigAlgorithm.RsaPssSha256 => "RSA"
    case SigAlgorithm.EcdsaSha256  => "EC"

  private def generateSigningKeyPair(alg: SigAlgorithm, random: SecureRandom): java.security.KeyPair =
    alg match
      case SigAlgorithm.RsaPssSha256 =>
        val gen = KeyPairGenerator.getInstance("RSA")
        gen.initialize(RsaSizeBits, random)
        gen.generateKeyPair()
      case SigAlgorithm.EcdsaSha256 =>
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(new ECGenParameterSpec(EcCurve), random)
        gen.generateKeyPair()

  private def freshKek(random: SecureRandom): KeyStore.SecretKeyEntry =
    val bytes = new Array[Byte](KekSizeBits / 8)
    random.nextBytes(bytes)
    new KeyStore.SecretKeyEntry(new SecretKeySpec(bytes, "AES"))

  /** Wrap an opaque encoded blob (PKCS#8 or X.509) as a storable secret key.
    *
    * The algorithm string is cosmetic — nothing ever asks this entry to perform a cipher operation, and the
    * bytes are handed straight back to a `KeyFactory` on read. It has to be `"AES"` rather than something
    * honest like `"RAW"` because the JDK's PKCS#12 writer resolves the entry's algorithm name to an OID
    * (`AlgorithmId.get`) before DER-encoding it, and only names with a registered OID survive that. Neither
    * side validates the length against the named algorithm, so an arbitrary-length blob round-trips intact.
    */
  private def blobEntry(bytes: Array[Byte]): KeyStore.SecretKeyEntry =
    new KeyStore.SecretKeyEntry(new SecretKeySpec(bytes, "AES"))

  private def highestKekVersion(store: KeyStore): Option[Int] =
    import scala.jdk.CollectionConverters.*
    store.aliases().asScala
      .collect { case a if a.startsWith(KekAliasPrefix) => a.drop(KekAliasPrefix.length).toIntOption }
      .flatten
      .maxOption

  /** Best-effort `chmod 600`. Silently skipped on filesystems without POSIX permissions (Windows, some
    * container volume mounts) — the keystore password is the real protection either way.
    */
  private def restrictPermissions(path: Path): Unit =
    try
      import scala.jdk.CollectionConverters.*
      import java.nio.file.attribute.PosixFilePermission
      Files.setPosixFilePermissions(
        path,
        Set(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE).asJava
      )
      ()
    catch case _: UnsupportedOperationException => ()
