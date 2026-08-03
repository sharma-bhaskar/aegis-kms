package dev.aegiskms.app

import cats.effect.IO
import com.typesafe.config.Config
import org.slf4j.LoggerFactory

/** Production preflight: catches the "shipped the workstation defaults to production" failure mode.
  *
  * The default configuration is deliberately demo-friendly — dev auth, allow-all policy, fake crypto,
  * non-durable journal — and binds `0.0.0.0` so the Docker image works out of the box. That combination on a
  * network-reachable interface is exactly the misconfiguration a key-management service must not run with
  * silently. At boot we cross-check the bind address against every dev-grade setting and either print one
  * unmissable banner (`aegis.security.preflight=warn`, the default) or refuse to start (`enforce`).
  *
  * Production deployments should set `AEGIS_SECURITY_PREFLIGHT=enforce`: a crashed pod is cheaper than an
  * open KMS. Loopback binds are always exempt — every check here is about *network-reachable* exposure.
  */
object Preflight:

  private val logger = LoggerFactory.getLogger(getClass)

  /** One dev-grade setting that is unsafe on a network-reachable bind. */
  final case class Finding(path: String, value: String, risk: String)

  /** True for binds only reachable from the host itself. `0.0.0.0` / `::` are NOT loopback — they are the
    * all-interfaces wildcards.
    */
  def isLoopback(host: String): Boolean =
    val h = host.trim.toLowerCase
    h == "localhost" || h == "::1" || h == "[::1]" || h.startsWith("127.")

  /** Pure scan of the wire-facing config for dev-grade settings. Empty when the configuration is
    * production-shaped; the caller decides whether findings warn or abort based on the preflight mode.
    */
  def findings(config: Config): List[Finding] =
    List(
      Option.when(config.getString("aegis.auth.kind") == "dev")(
        Finding(
          "aegis.auth.kind",
          "dev",
          "any client can impersonate any principal via the X-Aegis-User header"
        )
      ),
      Option.when(config.getString("aegis.policy.kind") == "dev")(
        Finding(
          "aegis.policy.kind",
          "dev",
          "DevPolicyEngine grants every Human and Service full access to every key"
        )
      ),
      Option.when(config.getString("aegis.crypto.kind") == "in-memory")(
        Finding(
          "aegis.crypto.kind",
          "in-memory",
          "deterministic-MAC dev backend — not real cryptography; never protects production data"
        )
      ),
      // `software` does real AES-GCM / RSA-PSS / ECDSA, so it is a much smaller finding than `in-memory` —
      // but the KEK and signing keys sit in this JVM's heap rather than behind a KMS or HSM boundary, which
      // is exactly the property a network-reachable key-management service must not have.
      Option.when(config.getString("aegis.crypto.kind") == "software")(
        Finding(
          "aegis.crypto.kind",
          "software",
          "key material lives in the server's heap — a heap dump or RCE exposes every key it ever wrapped"
        )
      ),
      Option.when(config.getString("aegis.persistence.journal.kind") == "in-memory")(
        Finding(
          "aegis.persistence.journal.kind",
          "in-memory",
          "key state is lost on restart — keys wrapped against this instance become unrecoverable"
        )
      )
    ).flatten

  /** Run the preflight as the first step of `Server.boot`. Loopback binds and clean configs pass silently;
    * otherwise `warn` prints the banner and continues, `enforce` raises and aborts the boot. An unknown mode
    * fails fast — consistent with every other `aegis.*.kind` selector.
    */
  def run(config: Config): IO[Unit] =
    val host = config.getString("aegis.http.host")
    val mode = config.getString("aegis.security.preflight")
    mode match
      case "warn" | "enforce" =>
        val found = findings(config)
        if isLoopback(host) || found.isEmpty then
          IO(logger.info(s"preflight: ok (host=$host, mode=$mode, dev-grade settings: ${found.size})"))
        else
          val lines = found.map(f => s"  - ${f.path}=${f.value} — ${f.risk}").mkString("\n")
          if mode == "enforce" then
            IO.raiseError(new IllegalStateException(
              s"preflight (enforce): refusing to bind $host with dev-grade settings:\n$lines\n" +
                "Fix the settings above, bind a loopback address, or set AEGIS_SECURITY_PREFLIGHT=warn " +
                "if this exposure is intentional (demos only)."
            ))
          else
            IO(logger.warn(
              s"""
                 |╔═══════════════════════════════════════════════════════════════════════════════╗
                 |  PREFLIGHT: binding $host with dev-grade settings — NOT SAFE FOR PRODUCTION
                 |$lines
                 |  Set AEGIS_SECURITY_PREFLIGHT=enforce to make this configuration refuse to boot.
                 |╚═══════════════════════════════════════════════════════════════════════════════╝""".stripMargin
            ))
      case other =>
        IO.raiseError(new IllegalArgumentException(
          s"Unknown aegis.security.preflight=$other (expected 'warn' or 'enforce')"
        ))
