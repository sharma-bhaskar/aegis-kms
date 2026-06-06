package dev.aegiskms.cli

import dev.aegiskms.cli.AegisHttpClient.{ClientError, renderError}
import dev.aegiskms.cli.WireFormats.{
  AdvisorScanResponseDto,
  AuditRecordDto,
  CompromiseRequest,
  DecryptRequest,
  DecryptResponse,
  EncryptRequest,
  EncryptResponse,
  IssueAgentRequestDto,
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

  // ── Agent issuance (#18 backend, #79 CLI) ────────────────────────────────

  /** `aegis agent issue --label … --scopes Sign,Get --ttl 3600 [--parent …]` — mint a short-lived agent JWT
    * against `POST /v1/agents/issue`. The output is shell-substitution friendly: each field on its own line
    * so a user can `eval $(aegis agent issue … | grep '^export')` if they want, or copy individual values.
    */
  def agentIssue(
      client: AegisHttpClient,
      label: String,
      scopes: List[String],
      ttlSeconds: Long,
      parent: Option[String]
  ): CommandResult =
    val req = IssueAgentRequestDto(label, scopes, ttlSeconds, parent)
    client.issueAgent(req) match
      case Right(resp) =>
        CommandResult.out(
          s"""agentId:   ${resp.agentId}
             |jti:       ${resp.jti}
             |expiresAt: ${resp.expiresAt}
             |jwt:       ${resp.jwt}""".stripMargin
        )
      case Left(err) => CommandResult.err(renderError(err), exitCodeFor(err))

  // ── Audit-read (#20 backend, #79 CLI) ─────────────────────────────────────

  /** `aegis audit tail [--since …] [--actor …] [--key …] [--op …] [--limit n] [--offset n] [--watch]`
    *
    * Single-shot mode (default): one `GET /v1/audit` call, print the page, exit. Watch mode is orchestrated
    * by `Cli.scala` (it loops, calling this method repeatedly with an updated `--since` to emulate `tail
    * -f`); the `Commands` layer stays a pure single-call shape so it remains unit-testable.
    */
  def auditTail(
      client: AegisHttpClient,
      since: Option[String],
      until: Option[String],
      actor: Option[String],
      key: Option[String],
      op: Option[String],
      limit: Option[Int],
      offset: Option[Int]
  ): CommandResult =
    client.queryAudit(since, until, actor, key, op, limit, offset) match
      case Right(page) =>
        if page.records.isEmpty then
          CommandResult.out(s"(no records; offset=${page.offset}, limit=${page.limit})")
        else
          val body = page.records.map(formatAuditRecord).mkString("\n---\n")
          val footer =
            s"\n---\n(${page.records.size} record(s); offset=${page.offset}, limit=${page.limit}, hasMore=${page.hasMore})"
          CommandResult.out(body + footer)
      case Left(err) => CommandResult.err(renderError(err), exitCodeFor(err))

  // ── AI advisor scan (#28) ─────────────────────────────────────────────────

  /** `aegis advisor scan [--lookback-days N] [--unused-days N] [--broad-scope N] [--top N]`
    *
    * Deterministic, read-only triage of recent audit activity: idle keys, broad-scope agents, active
    * anomalies, and the riskiest agents. Calls `GET /v1/advisor/scan`; all tuning knobs are optional and fall
    * back to server defaults (lookback 90d, unused 30d, broad-scope 5 ops, top 5 agents).
    */
  def advisorScan(
      client: AegisHttpClient,
      lookbackDays: Option[Int],
      unusedDays: Option[Int],
      broadScope: Option[Int],
      top: Option[Int]
  ): CommandResult =
    client.advisorScan(lookbackDays, unusedDays, broadScope, top) match
      case Right(report) => CommandResult.out(formatAdvisorReport(report))
      case Left(err)     => CommandResult.err(renderError(err), exitCodeFor(err))

  /** Render an advisor-scan report as a sectioned terminal summary. Each section prints its findings or an
    * explicit "none", so a clean window reads as "no findings" rather than an ambiguous blank.
    */
  private def formatAdvisorReport(r: AdvisorScanResponseDto): String =
    def section(title: String, lines: List[String]): String =
      val body = if lines.isEmpty then "  none" else lines.map("  • " + _).mkString("\n")
      s"$title\n$body"

    val header =
      s"advisor scan — window ${r.windowStart} → ${r.windowEnd} (${r.scannedRecords} record(s) scanned)" +
        (if r.truncated then
           s"\n  ⚠ partial window: hit the ${r.scannedRecords}-record scan cap; findings may be incomplete"
         else "")

    val unused = section(
      "Unused keys:",
      r.unusedKeys.map(k => f"${k.keyId}%-28s idle ${k.idleDays}d (last seen ${k.lastSeen})")
    )
    val broad = section(
      "Broad-scope agents:",
      r.broadScopeAgents.map(a => f"${a.agent}%-28s ${a.operations.mkString(", ")}")
    )
    val anomalies = section(
      "Active anomalies:",
      r.activeAnomalies.map(a => f"${a.at}  ${a.actor}%-20s ${a.operation}%-10s ${a.outcome}")
    )
    val riskiest = section(
      "Riskiest agents:",
      r.riskiestAgents.map(a =>
        f"${a.agent}%-28s score ${a.score}%.1f (failed ${a.failedOps}, distinct ops ${a.distinctOps})"
      )
    )

    List(header, unused, broad, anomalies, riskiest).mkString("\n\n")

  /** Render a single audit record for terminal output. Multi-line; the leading field labels are
    * column-aligned so a glance picks out the actor / operation / outcome quickly.
    */
  private def formatAuditRecord(r: AuditRecordDto): String =
    val ctxLine =
      if r.context.isEmpty then ""
      else
        "\ncontext:    " + r.context.toSeq
          .sortBy(_._1)
          .map { case (k, v) => s"$k=$v" }
          .mkString(", ")
    s"""at:         ${r.at}
       |actor:      ${r.actor} (${r.actorKind})
       |operation:  ${r.operation}
       |resource:   ${r.resource}
       |outcome:    ${r.outcome}
       |corrId:     ${r.correlationId}$ctxLine""".stripMargin

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
