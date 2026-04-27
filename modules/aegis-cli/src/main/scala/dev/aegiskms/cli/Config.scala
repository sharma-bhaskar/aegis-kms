package dev.aegiskms.cli

import io.circe.*
import io.circe.generic.semiauto.*
import io.circe.parser.*
import io.circe.syntax.*

import java.nio.file.{Files, Path, Paths}
import scala.util.Try

/** Persistent CLI config. Stored at `$HOME/.aegis/config.json` so a user can run `aegis login` once and have
  * subsequent commands target the right server with the right principal subject.
  *
  * This is intentionally minimal — the real auth flow (OIDC + JWT) lands in PR F3.b. For now `principal` is
  * just the dev-mode `X-Aegis-User` subject that the server's allowlist policy matches against.
  */
final case class CliConfig(serverUrl: String, principal: Option[String])

object CliConfig:

  given Encoder[CliConfig] = deriveEncoder
  given Decoder[CliConfig] = deriveDecoder

  /** The default config location. Honours `AEGIS_CONFIG` if set so tests can route to a sandboxed file. */
  def defaultPath: Path =
    sys.env.get("AEGIS_CONFIG").map(Paths.get(_)).getOrElse {
      val home = sys.props.getOrElse("user.home", ".")
      Paths.get(home, ".aegis", "config.json")
    }

  /** Resolved config, with fallbacks so commands work even before `aegis login` has run:
    *   1. `AEGIS_SERVER` / `AEGIS_USER` env vars (handy in CI / docker) 2. The persisted config file 3. The
    *      hard-coded default of `http://localhost:8443` and no principal
    */
  def load(path: Path = defaultPath): CliConfig =
    val fromFile: Option[CliConfig] = Try {
      if Files.exists(path) then
        val raw = new String(Files.readAllBytes(path))
        decode[CliConfig](raw).toOption
      else None
    }.toOption.flatten

    val baseUrl = sys.env.get("AEGIS_SERVER")
      .orElse(fromFile.map(_.serverUrl))
      .getOrElse("http://localhost:8443")

    val principal = sys.env.get("AEGIS_USER")
      .orElse(fromFile.flatMap(_.principal))

    CliConfig(baseUrl, principal)

  /** Persist a config. Creates the parent directory if missing. */
  def save(cfg: CliConfig, path: Path = defaultPath): Unit =
    val parent = path.getParent
    if parent != null && !Files.exists(parent) then Files.createDirectories(parent)
    val _ = Files.write(path, cfg.asJson.spaces2.getBytes)
