package dev.aegiskms.cli

import dev.aegiskms.cli.AegisHttpClient.{ClientError, renderError}
import dev.aegiskms.cli.WireFormats.{KeySpecDto, ManagedKeyDto}

import java.nio.file.Path

/** Pure command handlers. Each one returns a [[CommandResult]] with stdout/stderr text and an exit code so
  * the entry point can write the strings and propagate the code. Keeping them pure lets us assert exact
  * output in tests without capturing process stdout.
  *
  * Some commands (`login`, `version`) don't touch the server. Others take an `AegisHttpClient` so tests can
  * inject one backed by a stub `HttpPort`.
  */
object Commands:

  final case class CommandResult(stdout: String = "", stderr: String = "", exitCode: Int = 0):
    def withExit(code: Int): CommandResult = copy(exitCode = code)

  object CommandResult:
    val ok: CommandResult                                    = CommandResult()
    def out(text: String): CommandResult                     = CommandResult(stdout = text)
    def err(text: String, code: Int = 1): CommandResult      = CommandResult(stderr = text, exitCode = code)

  // ── version ────────────────────────────────────────────────────────────────

  def version: CommandResult = CommandResult.out("aegis 0.1.0-SNAPSHOT")

  // ── login ──────────────────────────────────────────────────────────────────

  /** Persist the server URL + principal into the config file so subsequent commands inherit them. We do not
    * yet exchange credentials for a token — that's the F3.b OIDC story; for the demo CLI a principal subject
    * is enough.
    */
  def login(serverUrl: String, principal: Option[String], path: Path = CliConfig.defaultPath): CommandResult =
    val cfg = CliConfig(serverUrl, principal)
    CliConfig.save(cfg, path)
    val who = principal.getOrElse("(no principal — server defaults will apply)")
    CommandResult.out(s"Saved config to $path\nServer: $serverUrl\nPrincipal: $who")

  // ── keys create ────────────────────────────────────────────────────────────

  def keysCreate(client: AegisHttpClient, alg: String, sizeBits: Int, name: String): CommandResult =
    val spec = KeySpecDto(name = name, algorithm = alg, sizeBits = sizeBits, objectType = "SymmetricKey")
    client.createKey(spec) match
      case Right(key) => CommandResult.out(formatKey(key))
      case Left(err)  => CommandResult.err(renderError(err))

  // ── keys get ───────────────────────────────────────────────────────────────

  def keysGet(client: AegisHttpClient, id: String): CommandResult =
    client.getKey(id) match
      case Right(key) => CommandResult.out(formatKey(key))
      case Left(err)  => CommandResult.err(renderError(err), exitCodeFor(err))

  // ── keys activate ──────────────────────────────────────────────────────────

  def keysActivate(client: AegisHttpClient, id: String): CommandResult =
    client.activateKey(id) match
      case Right(key) => CommandResult.out(formatKey(key))
      case Left(err)  => CommandResult.err(renderError(err), exitCodeFor(err))

  // ── keys destroy ───────────────────────────────────────────────────────────

  def keysDestroy(client: AegisHttpClient, id: String): CommandResult =
    client.destroyKey(id) match
      case Right(_)  => CommandResult.out(s"destroyed $id")
      case Left(err) => CommandResult.err(renderError(err), exitCodeFor(err))

  // ── placeholders for agent-native commands (backends arrive in later PRs) ──

  /** `aegis agent issue` — issues a scoped agent token. Real implementation lands once the agent-token
    * issuance endpoint exists (PR A1). This stub at least makes the command discoverable in `--help` and
    * produces a clear "not yet wired up" message instead of an obscure 404.
    */
  def agentIssue: CommandResult =
    CommandResult.err(
      "agent issue: not yet wired up — the agent-token issuance endpoint ships in PR A1.",
      code = 2
    )

  /** `aegis audit tail` — streams the audit feed. Awaiting an audit-streaming endpoint (PR F2.b). */
  def auditTail: CommandResult =
    CommandResult.err(
      "audit tail: not yet wired up — server-side audit streaming ships in PR F2.b.",
      code = 2
    )

  /** `aegis advisor scan` — runs the LLM advisor against recent audit data. Awaits PR W4. */
  def advisorScan: CommandResult =
    CommandResult.err(
      "advisor scan: not yet wired up — the LLM advisor ships in PR W4.",
      code = 2
    )

  // ── Helpers ────────────────────────────────────────────────────────────────

  private def formatKey(key: ManagedKeyDto): String =
    s"""id:        ${key.id}
       |name:      ${key.spec.name}
       |algorithm: ${key.spec.algorithm}-${key.spec.sizeBits}
       |type:      ${key.spec.objectType}
       |state:     ${key.state}
       |createdAt: ${key.createdAt}""".stripMargin

  /** Map server errors to exit codes: 4 for not-found, 5 for permission, 1 for everything else. Mirrors the
    * convention used by tools like `kubectl` so shell-script integrations can branch on the code.
    */
  private def exitCodeFor(err: ClientError): Int = err match
    case ClientError.Server(_, "ItemNotFound", _)     => 4
    case ClientError.Server(_, "PermissionDenied", _) => 5
    case _                                            => 1
