package dev.aegiskms.cli

import dev.aegiskms.cli.Commands.CommandResult

/** The `aegis` admin CLI entry point.
  *
  * Argument parsing is hand-rolled rather than scopt/decline because the surface is small (single command +
  * subcommand + a handful of flags) and pulling in a parser library doubles the CLI's startup time without
  * buying us much. The shape mirrors `kubectl`-style `<noun> <verb> <id>` so it's familiar.
  *
  * `parse` returns a [[Commands.CommandResult]] without side effects, which makes it trivially unit-testable.
  * Only `main` performs IO: it prints the result and exits.
  */
object Cli:

  /** Pure parse + dispatch. Tests call this directly. */
  def run(args: List[String], cfg: => CliConfig, makeClient: CliConfig => AegisHttpClient): CommandResult =
    args match
      case Nil                         => help
      case "version" :: Nil            => Commands.version
      case "--help" :: _ | "help" :: _ => help

      case "login" :: rest =>
        parseLogin(rest) match
          case Right((server, principal)) => Commands.login(server, principal)
          case Left(msg)                  => CommandResult.err(s"$msg\n\n${loginHelp}")

      case "keys" :: subcmd :: rest =>
        keysCommand(subcmd, rest, cfg, makeClient)

      case "agent" :: "issue" :: rest =>
        parseAgentIssue(rest) match
          case Right((label, scopes, ttl, parent)) =>
            Commands.agentIssue(makeClient(cfg), label, scopes, ttl, parent)
          case Left(msg) => CommandResult.err(s"$msg\n\n${agentIssueHelp}")

      case "audit" :: "tail" :: rest =>
        parseAuditTail(rest) match
          case Right(filter) =>
            if filter.watch then
              // Watch mode is the only place `Cli` does real-time IO (it polls every 2 s,
              // shifting `since` forward on each tick). We accept the impurity here because
              // the alternative — pushing the loop into `Commands` — would either pollute
              // every command with a streaming hook or require a second abstraction layer.
              runAuditWatch(makeClient(cfg), filter)
            else
              Commands.auditTail(
                makeClient(cfg),
                filter.since,
                filter.until,
                filter.actor,
                filter.key,
                filter.op,
                filter.limit,
                filter.offset
              )
          case Left(msg) => CommandResult.err(s"$msg\n\n${auditTailHelp}")

      case "advisor" :: "scan" :: _ => Commands.advisorScan

      case unknown =>
        CommandResult.err(s"unknown command: ${unknown.mkString(" ")}\n\n${help.stdout}")

  /** Default `main`: read config from disk, build a JDK-backed client, run, exit. */
  def main(args: Array[String]): Unit =
    val res = run(
      args.toList,
      cfg = CliConfig.load(),
      makeClient = c => new AegisHttpClient(HttpPort.jdk(), c.serverUrl, c.principal)
    )
    if res.stdout.nonEmpty then println(res.stdout)
    if res.stderr.nonEmpty then System.err.println(res.stderr)
    sys.exit(res.exitCode)

  // ── Subcommand parsing ─────────────────────────────────────────────────────

  private def keysCommand(
      sub: String,
      rest: List[String],
      cfg: => CliConfig,
      makeClient: CliConfig => AegisHttpClient
  ): CommandResult =
    sub match
      case "create" =>
        parseKeysCreate(rest) match
          case Right((alg, size, name)) =>
            Commands.keysCreate(makeClient(cfg), alg, size, name)
          case Left(msg) => CommandResult.err(s"$msg\n\n${keysCreateHelp}")

      case "get" =>
        rest match
          case id :: _ if id.nonEmpty => Commands.keysGet(makeClient(cfg), id)
          case _ => CommandResult.err("keys get: missing <id>\n\nUsage: aegis keys get <id>")

      case "activate" =>
        rest match
          case id :: _ if id.nonEmpty => Commands.keysActivate(makeClient(cfg), id)
          case _ => CommandResult.err("keys activate: missing <id>\n\nUsage: aegis keys activate <id>")

      case "destroy" =>
        rest match
          case id :: _ if id.nonEmpty => Commands.keysDestroy(makeClient(cfg), id)
          case _ => CommandResult.err("keys destroy: missing <id>\n\nUsage: aegis keys destroy <id>")

      case "sign" =>
        parseKeysSign(rest) match
          case Right((id, msg, alg)) => Commands.keysSign(makeClient(cfg), id, msg, alg)
          case Left(msg)             => CommandResult.err(s"$msg\n\n${keysSignHelp}")

      case "verify" =>
        parseKeysVerify(rest) match
          case Right((id, msg, sig, alg)) => Commands.keysVerify(makeClient(cfg), id, msg, sig, alg)
          case Left(msg)                  => CommandResult.err(s"$msg\n\n${keysVerifyHelp}")

      case "encrypt" =>
        parseKeysEncrypt(rest) match
          case Right((id, pt, ctx)) => Commands.keysEncrypt(makeClient(cfg), id, pt, ctx)
          case Left(msg)            => CommandResult.err(s"$msg\n\n${keysEncryptHelp}")

      case "decrypt" =>
        parseKeysDecrypt(rest) match
          case Right((id, ct, ctx)) => Commands.keysDecrypt(makeClient(cfg), id, ct, ctx)
          case Left(msg)            => CommandResult.err(s"$msg\n\n${keysDecryptHelp}")

      case "wrap" =>
        parseKeysWrap(rest) match
          case Right((id, dek)) => Commands.keysWrap(makeClient(cfg), id, dek)
          case Left(msg)        => CommandResult.err(s"$msg\n\n${keysWrapHelp}")

      case "unwrap" =>
        parseKeysUnwrap(rest) match
          case Right((id, wrapped)) => Commands.keysUnwrap(makeClient(cfg), id, wrapped)
          case Left(msg)            => CommandResult.err(s"$msg\n\n${keysUnwrapHelp}")

      case "compromise" =>
        parseKeysCompromise(rest) match
          case Right((id, reason)) => Commands.keysCompromise(makeClient(cfg), id, reason)
          case Left(msg)           => CommandResult.err(s"$msg\n\n${keysCompromiseHelp}")

      case "rotate" =>
        parseKeysRotate(rest) match
          case Right((id, policy)) => Commands.keysRotate(makeClient(cfg), id, policy)
          case Left(msg)           => CommandResult.err(s"$msg\n\n${keysRotateHelp}")

      case other =>
        CommandResult.err(s"unknown keys subcommand: $other\n\n${keysHelp}")

  /** Parse `aegis login --server <url> [--principal <subject>]`. `--user` is accepted as a deprecated alias
    * for `--principal` so any scripts that grew up against the older help text still work.
    *
    * Visibility is package-private rather than `private` so [[CliSpec]] can pin the contract without routing
    * the test through `CliConfig.save` and the user's real home directory.
    */
  private[cli] def parseLogin(args: List[String]): Either[String, (String, Option[String])] =
    val flags = parseFlags(args)
    flags.get("--server") match
      case None => Left("login: --server <url> is required")
      case Some(url) =>
        val principal = flags.get("--principal").orElse(flags.get("--user"))
        Right((url, principal))

  /** Parse `aegis keys create --alg AES-256 --name <name>` (also accepts `--alg AES --size 256`). */
  private def parseKeysCreate(args: List[String]): Either[String, (String, Int, String)] =
    val flags = parseFlags(args)
    val name  = flags.get("--name").toRight("keys create: --name <name> is required")

    // Two valid spellings:
    //   --alg AES-256          (combined; mirrors how users actually talk about it)
    //   --alg AES --size 256   (split form for non-AES algorithms)
    val algAndSize: Either[String, (String, Int)] = flags.get("--alg") match
      case None => Left("keys create: --alg is required")
      case Some(combined) if combined.contains("-") =>
        combined.split("-", 2).toList match
          case alg :: sizeStr :: Nil =>
            sizeStr.toIntOption.toRight(s"keys create: invalid size in --alg: $sizeStr")
              .map(size => (alg, size))
          case _ => Left(s"keys create: malformed --alg value: $combined")
      case Some(alg) =>
        flags.get("--size") match
          case Some(s) => s.toIntOption.toRight(s"keys create: --size must be an integer, got $s")
              .map(size => (alg, size))
          case None => Left("keys create: --size is required when --alg has no size suffix")

    for
      n  <- name
      as <- algAndSize
    yield (as._1, as._2, n)

  /** Parse `aegis keys sign --id <id> --message <text|@file> [--alg RsaPssSha256]`. */
  private def parseKeysSign(args: List[String]): Either[String, (String, String, String)] =
    val flags = parseFlags(args)
    val alg   = flags.getOrElse("--alg", "RsaPssSha256")
    for
      id  <- flags.get("--id").toRight("keys sign: --id <id> is required")
      msg <- flags.get("--message").toRight("keys sign: --message <text|@file> is required")
    yield (id, msg, alg)

  /** Parse `aegis keys verify --id <id> --message <text|@file> --signature <b64> [--alg RsaPssSha256]`. */
  private def parseKeysVerify(args: List[String]): Either[String, (String, String, String, String)] =
    val flags = parseFlags(args)
    val alg   = flags.getOrElse("--alg", "RsaPssSha256")
    for
      id  <- flags.get("--id").toRight("keys verify: --id <id> is required")
      msg <- flags.get("--message").toRight("keys verify: --message <text|@file> is required")
      sig <- flags.get("--signature").toRight("keys verify: --signature <base64> is required")
    yield (id, msg, sig, alg)

  /** Parse `aegis keys encrypt --id <id> --plaintext <text|@file> [--context k=v,k2=v2]`. */
  private[cli] def parseKeysEncrypt(
      args: List[String]
  ): Either[String, (String, String, Map[String, String])] =
    val flags = parseFlags(args)
    for
      id  <- flags.get("--id").toRight("keys encrypt: --id <id> is required")
      pt  <- flags.get("--plaintext").toRight("keys encrypt: --plaintext <text|@file> is required")
      ctx <- parseContext(flags.get("--context")).left.map(m => s"keys encrypt: $m")
    yield (id, pt, ctx)

  /** Parse `aegis keys decrypt --id <id> --ciphertext <b64> [--context k=v,k2=v2]`. */
  private[cli] def parseKeysDecrypt(
      args: List[String]
  ): Either[String, (String, String, Map[String, String])] =
    val flags = parseFlags(args)
    for
      id  <- flags.get("--id").toRight("keys decrypt: --id <id> is required")
      ct  <- flags.get("--ciphertext").toRight("keys decrypt: --ciphertext <base64> is required")
      ctx <- parseContext(flags.get("--context")).left.map(m => s"keys decrypt: $m")
    yield (id, ct, ctx)

  /** Parse `aegis keys wrap --id <id> --dek <text|@file>`. */
  private[cli] def parseKeysWrap(args: List[String]): Either[String, (String, String)] =
    val flags = parseFlags(args)
    for
      id  <- flags.get("--id").toRight("keys wrap: --id <id> is required")
      dek <- flags.get("--dek").toRight("keys wrap: --dek <text|@file> is required")
    yield (id, dek)

  /** Parse `aegis keys unwrap --id <id> --wrapped <b64>`. */
  private[cli] def parseKeysUnwrap(args: List[String]): Either[String, (String, String)] =
    val flags = parseFlags(args)
    for
      id      <- flags.get("--id").toRight("keys unwrap: --id <id> is required")
      wrapped <- flags.get("--wrapped").toRight("keys unwrap: --wrapped <base64> is required")
    yield (id, wrapped)

  /** Parse `aegis keys compromise --id <id> --reason "..."`. The reason must be non-empty — the audit row
    * carries this string at severity=Critical, and a blank justification undermines the post-incident report.
    */
  private[cli] def parseKeysCompromise(args: List[String]): Either[String, (String, String)] =
    val flags = parseFlags(args)
    for
      id <- flags.get("--id").toRight("keys compromise: --id <id> is required")
      reason <- flags.get("--reason").filter(_.nonEmpty).toRight(
        "keys compromise: --reason <text> is required (non-empty)"
      )
    yield (id, reason)

  /** Parse `aegis keys rotate --id <id> [--policy <policy>]`. Default policy is `Manual`. */
  private[cli] def parseKeysRotate(args: List[String]): Either[String, (String, String)] =
    val flags  = parseFlags(args)
    val policy = flags.getOrElse("--policy", "Manual")
    flags.get("--id")
      .toRight("keys rotate: --id <id> is required")
      .map(id => (id, policy))

  /** Parse `--context k=v,k2=v2` into a map. Empty / missing → empty map. */
  private def parseContext(raw: Option[String]): Either[String, Map[String, String]] =
    raw.filter(_.nonEmpty) match
      case None => Right(Map.empty)
      case Some(s) =>
        s.split(",").toList.foldLeft[Either[String, Map[String, String]]](Right(Map.empty)) {
          (acc, pair) =>
            acc.flatMap { m =>
              pair.split("=", 2).toList match
                case k :: v :: Nil if k.nonEmpty => Right(m + (k -> v))
                case _ => Left(s"invalid --context entry: '$pair' (expected key=value)")
            }
        }

  /** Tiny `--key value --key2 value2 …` flag parser. Anything else gets ignored — fine for our tiny surface.
    */
  private def parseFlags(args: List[String]): Map[String, String] =
    args.sliding(2, 2).collect {
      case List(k, v) if k.startsWith("--") => k -> v
    }.toMap

  /** Detect boolean flags (`--watch`, etc.) that take no value. The pair-stride parser above skips these; we
    * look for them with a separate pass.
    */
  private def hasFlag(args: List[String], name: String): Boolean = args.contains(name)

  /** Parse `aegis agent issue --label … --scopes Sign,Get --ttl 3600 [--parent alice@org]`.
    *
    * Scopes are comma-separated `Operation` enum names — the server validates them. TTL is in seconds. Parent
    * is optional; when omitted the server uses the calling principal's subject.
    */
  private[cli] def parseAgentIssue(
      args: List[String]
  ): Either[String, (String, List[String], Long, Option[String])] =
    val flags = parseFlags(args)
    for
      label <- flags.get("--label").filter(_.nonEmpty)
        .toRight("agent issue: --label <text> is required (non-empty)")
      scopesRaw <- flags.get("--scopes").filter(_.nonEmpty)
        .toRight("agent issue: --scopes <Op,Op,…> is required (non-empty)")
      ttlRaw <- flags.get("--ttl").toRight("agent issue: --ttl <seconds> is required")
      ttl <- ttlRaw.toLongOption.filter(_ > 0)
        .toRight(s"agent issue: --ttl must be a positive integer (was '$ttlRaw')")
    yield
      val scopes = scopesRaw.split(",").iterator.map(_.trim).filter(_.nonEmpty).toList
      val parent = flags.get("--parent").filter(_.nonEmpty)
      (label, scopes, ttl, parent)

  /** Filter type for the `audit tail` parser. Kept as a small case class instead of a 7-tuple so the
    * `Cli.run` dispatch site reads cleanly.
    */
  final private[cli] case class AuditTailFilter(
      since: Option[String],
      until: Option[String],
      actor: Option[String],
      key: Option[String],
      op: Option[String],
      limit: Option[Int],
      offset: Option[Int],
      watch: Boolean
  )

  /** Parse `aegis audit tail [--since …] [--until …] [--actor …] [--key …] [--op …] [--limit n] [--offset n]
    * [--watch]`.
    *
    * All flags are optional. `--limit` and `--offset` must parse as positive integers if provided. `--watch`
    * is a boolean flag (no value) — when present, `Cli.run` runs the polling loop.
    */
  private[cli] def parseAuditTail(args: List[String]): Either[String, AuditTailFilter] =
    // Strip `--watch` before the pair-stride parser so it doesn't accidentally consume the next
    // flag as its value.
    val watch  = hasFlag(args, "--watch")
    val rest   = args.filterNot(_ == "--watch")
    val flags  = parseFlags(rest)
    val since  = flags.get("--since").filter(_.nonEmpty)
    val until  = flags.get("--until").filter(_.nonEmpty)
    val actor  = flags.get("--actor").filter(_.nonEmpty)
    val key    = flags.get("--key").filter(_.nonEmpty)
    val op     = flags.get("--op").filter(_.nonEmpty)
    val limit  = flags.get("--limit")
    val offset = flags.get("--offset")
    for
      l <- limit match
        case None => Right(None)
        case Some(v) =>
          v.toIntOption.filter(_ > 0).map(Some(_))
            .toRight(s"audit tail: --limit must be a positive integer (was '$v')")
      o <- offset match
        case None => Right(None)
        case Some(v) =>
          v.toIntOption.filter(_ >= 0).map(Some(_))
            .toRight(s"audit tail: --offset must be a non-negative integer (was '$v')")
    yield AuditTailFilter(since, until, actor, key, op, l, o, watch)

  /** Watch-mode loop: print one page, then poll every 2 s for new records (using the last seen `at` as the
    * new `since`). Runs indefinitely until the JVM is killed. Sleeps via `Thread.sleep` because the CLI is
    * synchronous; the rest of the codebase uses cats-effect but dragging IO/IOApp into the CLI's startup path
    * doubles its boot time.
    *
    * Returns a `CommandResult` only if the initial query fails — once we're in the polling loop the process
    * runs until SIGINT.
    */
  private def runAuditWatch(client: AegisHttpClient, initial: AuditTailFilter): CommandResult =
    var since = initial.since
    var first = true
    while true do
      Commands.auditTail(
        client,
        since,
        initial.until,
        initial.actor,
        initial.key,
        initial.op,
        initial.limit,
        initial.offset
      ) match
        case res if res.exitCode == 0 =>
          if res.stdout.nonEmpty then println(res.stdout)
          // Advance `since` to the highest `at` we just saw. If the page was empty we keep the
          // previous `since` so we don't lose ground.
          val nextSince = extractMaxAt(res.stdout).orElse(since)
          since = nextSince
          first = false
          Thread.sleep(2000)
        case failure =>
          // Surface the first failure as the CLI exit. Subsequent transient failures would just
          // keep retrying — in v0.2.0 we keep it simple and exit on the first one.
          if first then return failure
          else
            System.err.println(failure.stderr)
            Thread.sleep(5000) // back off on errors during a watch session
    // Unreachable; satisfies the type checker.
    CommandResult.out("")

  /** Pull the latest `at:` timestamp out of an `audit tail` page render so the next watch tick uses it as the
    * new `since`. Returns `None` if the page didn't contain any `at:` lines — which is the case for the
    * empty-page footer.
    */
  private def extractMaxAt(rendered: String): Option[String] =
    val atLines = rendered.linesIterator
      .map(_.trim)
      .filter(_.startsWith("at:"))
      .map(_.stripPrefix("at:").trim)
      .toList
    if atLines.isEmpty then None else Some(atLines.max)

  // ── Help text ──────────────────────────────────────────────────────────────

  private def help: CommandResult = CommandResult.out(
    """aegis — Aegis-KMS admin CLI
      |
      |Usage:
      |  aegis version
      |  aegis login --server <url> [--principal <subject>]
      |  aegis keys create --alg AES-256 --name <name>
      |  aegis keys get <id>
      |  aegis keys activate <id>
      |  aegis keys destroy <id>
      |  aegis keys sign --id <id> --message <text|@file> [--alg RsaPssSha256]
      |  aegis keys verify --id <id> --message <text|@file> --signature <b64> [--alg RsaPssSha256]
      |  aegis keys encrypt --id <id> --plaintext <text|@file> [--context k=v,k2=v2]
      |  aegis keys decrypt --id <id> --ciphertext <b64> [--context k=v,k2=v2]
      |  aegis keys wrap --id <id> --dek <text|@file>
      |  aegis keys unwrap --id <id> --wrapped <b64>
      |  aegis keys compromise --id <id> --reason "<text>"
      |  aegis keys rotate --id <id> [--policy Manual|TimeBased:7days|OpCountBased:N]
      |  aegis agent issue --label <text> --scopes Op,Op,… --ttl <seconds> [--parent <subject>]
      |  aegis audit tail [--since <ISO>] [--until <ISO>] [--actor <subject>] [--key <id>]
      |                   [--op <name>] [--limit <n>] [--offset <n>] [--watch]
      |  aegis advisor scan       (planned — PR W4)
      |
      |Config: $AEGIS_CONFIG, or ~/.aegis/config.json
      |Env:    AEGIS_SERVER, AEGIS_USER override the saved config""".stripMargin
  )

  private val loginHelp: String = "Usage: aegis login --server <url> [--principal <subject>]"
  private val agentIssueHelp: String =
    """Usage: aegis agent issue --label <text> --scopes Op,Op,… --ttl <seconds> [--parent <subject>]
      |
      |  --label   Human-readable purpose (e.g. claude-invoice-batch-q2)
      |  --scopes  Comma-separated KMIP Operation names (Sign,Get,Encrypt,…)
      |  --ttl     Token lifetime in seconds (1–86400)
      |  --parent  Optional; defaults to the calling principal's subject""".stripMargin
  private val auditTailHelp: String =
    """Usage: aegis audit tail [filters] [--watch]
      |
      |  --since <ISO>   Half-open lower bound on occurred_at (inclusive)
      |  --until <ISO>   Half-open upper bound on occurred_at (exclusive)
      |  --actor <sub>   Exact match on actor_subject (e.g. alice@org, agent-7a3)
      |  --key <id>      Exact match on resource (e.g. key:abc-123)
      |  --op <name>     KMIP Operation enum name (Sign, Get, Encrypt, …)
      |  --limit <n>     Page size; default 100, max 1000
      |  --offset <n>    Starting row offset; default 0
      |  --watch         Poll every 2 s for new records (tail -f UX)""".stripMargin
  private val keysHelp: String =
    """Usage:
      |  aegis keys create --alg <ALG> --name <NAME>
      |  aegis keys get <id>
      |  aegis keys activate <id>
      |  aegis keys destroy <id>
      |  aegis keys sign --id <id> --message <text|@file> [--alg RsaPssSha256]
      |  aegis keys verify --id <id> --message <text|@file> --signature <b64> [--alg RsaPssSha256]
      |  aegis keys encrypt --id <id> --plaintext <text|@file> [--context k=v,k2=v2]
      |  aegis keys decrypt --id <id> --ciphertext <b64> [--context k=v,k2=v2]
      |  aegis keys wrap --id <id> --dek <text|@file>
      |  aegis keys unwrap --id <id> --wrapped <b64>
      |  aegis keys compromise --id <id> --reason "<text>"
      |  aegis keys rotate --id <id> [--policy Manual|TimeBased:7days|OpCountBased:N]""".stripMargin
  private val keysCreateHelp: String = "Usage: aegis keys create --alg AES-256 --name <name>"
  private val keysSignHelp: String =
    "Usage: aegis keys sign --id <id> --message <text|@file> [--alg RsaPssSha256]"
  private val keysVerifyHelp: String =
    "Usage: aegis keys verify --id <id> --message <text|@file> --signature <b64> [--alg RsaPssSha256]"
  private val keysEncryptHelp: String =
    "Usage: aegis keys encrypt --id <id> --plaintext <text|@file> [--context k=v,k2=v2]"
  private val keysDecryptHelp: String =
    "Usage: aegis keys decrypt --id <id> --ciphertext <b64> [--context k=v,k2=v2]"
  private val keysWrapHelp: String   = "Usage: aegis keys wrap --id <id> --dek <text|@file>"
  private val keysUnwrapHelp: String = "Usage: aegis keys unwrap --id <id> --wrapped <b64>"
  private val keysCompromiseHelp: String =
    "Usage: aegis keys compromise --id <id> --reason \"<text>\""
  private val keysRotateHelp: String =
    "Usage: aegis keys rotate --id <id> [--policy Manual|TimeBased:7days|OpCountBased:N]"
