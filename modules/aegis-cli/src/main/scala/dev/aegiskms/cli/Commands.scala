package dev.aegiskms.cli

import dev.aegiskms.cli.AegisHttpClient.{ClientError, renderError}
import dev.aegiskms.cli.WireFormats.{
  CompromiseRequest,
  DecryptRequest,
  DecryptResponse,
  EncryptRequest,
  EncryptResponse,
  KeySpecDto,
  ManagedKeyDto,
  RotateRequest,
  SignRequest,
  SignResponse,
  UnwrapRequest,
  UnwrapResponse,
  VerifyRequest,
  VerifyResponse,
  WrapRequest,
  WrapResponse
}

import java.nio.file.{Files, Path}
import java.util.Base64

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
    val ok: CommandResult                               = CommandResult()
    def out(text: String): CommandResult                = CommandResult(stdout = text)
    def err(text: String, code: Int = 1): CommandResult = CommandResult(stderr = text, exitCode = code)

  // ── version ────────────────────────────────────────────────────────────────

  def version: CommandResult = CommandResult.out(s"aegis ${BuildInfo.version}")

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

  // ── keys sign ──────────────────────────────────────────────────────────────

  /** `aegis keys sign --id <id> --message <text|@file> [--alg RsaPssSha256]`. The message can be supplied
    * inline (taken as UTF-8 bytes) or read from a file path prefixed with `@`. The signature is printed as
    * base64.
    */
  def keysSign(client: AegisHttpClient, id: String, message: String, alg: String): CommandResult =
    readMessage(message) match
      case Left(msg) => CommandResult.err(s"keys sign: $msg")
      case Right(bytes) =>
        val req = SignRequest(Base64.getEncoder.encodeToString(bytes), alg)
        client.signKey(id, req) match
          case Right(SignResponse(sigB64, algo)) =>
            CommandResult.out(s"signature: $sigB64\nalgorithm: $algo")
          case Left(err) => CommandResult.err(renderError(err), exitCodeFor(err))

  // ── keys verify ────────────────────────────────────────────────────────────

  /** `aegis keys verify --id <id> --message <text|@file> --signature <b64> [--alg RsaPssSha256]`. */
  def keysVerify(
      client: AegisHttpClient,
      id: String,
      message: String,
      signatureB64: String,
      alg: String
  ): CommandResult =
    readMessage(message) match
      case Left(msg) => CommandResult.err(s"keys verify: $msg")
      case Right(bytes) =>
        val req = VerifyRequest(Base64.getEncoder.encodeToString(bytes), signatureB64, alg)
        client.verifyKey(id, req) match
          case Right(VerifyResponse(true, algo))  => CommandResult.out(s"valid: true ($algo)")
          case Right(VerifyResponse(false, algo)) => CommandResult.err(s"valid: false ($algo)", code = 3)
          case Left(err)                          => CommandResult.err(renderError(err), exitCodeFor(err))

  /** Read the message argument: `@/path/to/file` reads from disk, anything else is taken as a literal UTF-8
    * string. Mirrors how curl handles `--data @file`.
    */
  private def readMessage(arg: String): Either[String, Array[Byte]] =
    if arg.startsWith("@") then
      val path = Path.of(arg.drop(1))
      try Right(Files.readAllBytes(path))
      catch case e: Exception => Left(s"could not read $path: ${e.getMessage}")
    else Right(arg.getBytes("UTF-8"))

  // ── keys encrypt ───────────────────────────────────────────────────────────

  /** `aegis keys encrypt --id <id> --plaintext <text|@file> [--context k=v,k2=v2]`. The plaintext can be
    * supplied inline (UTF-8) or read from a file path prefixed with `@`. The ciphertext is printed as base64.
    */
  def keysEncrypt(
      client: AegisHttpClient,
      id: String,
      plaintext: String,
      context: Map[String, String]
  ): CommandResult =
    readMessage(plaintext) match
      case Left(msg) => CommandResult.err(s"keys encrypt: $msg")
      case Right(bytes) =>
        val req = EncryptRequest(Base64.getEncoder.encodeToString(bytes), context)
        client.encryptKey(id, req) match
          case Right(EncryptResponse(ctB64, ctx)) =>
            val ctxLine = if ctx.isEmpty then "" else s"\ncontext: ${formatContext(ctx)}"
            CommandResult.out(s"ciphertext: $ctB64$ctxLine")
          case Left(err) => CommandResult.err(renderError(err), exitCodeFor(err))

  // ── keys decrypt ───────────────────────────────────────────────────────────

  /** `aegis keys decrypt --id <id> --ciphertext <base64> [--context k=v,k2=v2]`. The plaintext is printed as
    * base64 (it may not be valid UTF-8) plus a best-effort UTF-8 rendering when it decodes cleanly.
    */
  def keysDecrypt(
      client: AegisHttpClient,
      id: String,
      ciphertextB64: String,
      context: Map[String, String]
  ): CommandResult =
    val req = DecryptRequest(ciphertextB64, context)
    client.decryptKey(id, req) match
      case Right(DecryptResponse(ptB64, _)) =>
        CommandResult.out(s"plaintext: $ptB64")
      case Left(err) => CommandResult.err(renderError(err), exitCodeFor(err))

  private def formatContext(ctx: Map[String, String]): String =
    ctx.toSeq.sortBy(_._1).map((k, v) => s"$k=$v").mkString(",")

  // ── keys wrap ──────────────────────────────────────────────────────────────

  /** `aegis keys wrap --id <id> --dek <text|@file>`. The DEK can be inline (UTF-8) or read from a file path
    * prefixed with `@` (the common case — a 32-byte AES-256 DEK won't be valid UTF-8). The wrapped blob is
    * printed as base64.
    */
  def keysWrap(client: AegisHttpClient, id: String, dek: String): CommandResult =
    readMessage(dek) match
      case Left(msg) => CommandResult.err(s"keys wrap: $msg")
      case Right(bytes) =>
        val req = WrapRequest(Base64.getEncoder.encodeToString(bytes))
        client.wrapKey(id, req) match
          case Right(WrapResponse(wrappedB64)) =>
            CommandResult.out(s"wrapped: $wrappedB64")
          case Left(err) => CommandResult.err(renderError(err), exitCodeFor(err))

  // ── keys unwrap ────────────────────────────────────────────────────────────

  /** `aegis keys unwrap --id <id> --wrapped <b64>`. Prints the recovered DEK as base64 (it may not be valid
    * UTF-8 — DEKs are random bytes).
    */
  def keysUnwrap(client: AegisHttpClient, id: String, wrappedB64: String): CommandResult =
    val req = UnwrapRequest(wrappedB64)
    client.unwrapKey(id, req) match
      case Right(UnwrapResponse(dekB64)) =>
        CommandResult.out(s"dek: $dekB64")
      case Left(err) => CommandResult.err(renderError(err), exitCodeFor(err))

  // ── keys compromise ────────────────────────────────────────────────────────

  /** `aegis keys compromise --id <id> --reason "..."`. Marks a key as compromised — irreversible. The reason
    * is mandatory and ends up on the audit row at `severity=Critical`.
    */
  def keysCompromise(client: AegisHttpClient, id: String, reason: String): CommandResult =
    val req = CompromiseRequest(reason)
    client.compromiseKey(id, req) match
      case Right(key) =>
        CommandResult.out(s"compromised ${key.id}\nreason: $reason\nstate:  ${key.state}")
      case Left(err) => CommandResult.err(renderError(err), exitCodeFor(err))

  // ── keys rotate ────────────────────────────────────────────────────────────

  /** `aegis keys rotate --id <id> [--policy <policy>]`. Bumps the key's currentVersion. Defaults to `Manual`;
    * supply `TimeBased:7days` or `OpCountBased:10000` to record an automatic rotation.
    */
  def keysRotate(client: AegisHttpClient, id: String, policy: String): CommandResult =
    val req = RotateRequest(policy)
    client.rotateKey(id, req) match
      case Right(key) =>
        CommandResult.out(
          s"rotated ${key.id}\nversion: ${key.currentVersion}\nstate:   ${key.state}\npolicy:  $policy"
        )
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
       |version:   ${key.currentVersion}
       |createdAt: ${key.createdAt}""".stripMargin

  /** Map server errors to exit codes: 4 for not-found, 5 for permission, 1 for everything else. Mirrors the
    * convention used by tools like `kubectl` so shell-script integrations can branch on the code.
    */
  private def exitCodeFor(err: ClientError): Int = err match
    case ClientError.Server(_, "ItemNotFound", _)     => 4
    case ClientError.Server(_, "PermissionDenied", _) => 5
    case _                                            => 1
