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
      case Nil                  => help
      case "version" :: Nil     => Commands.version
      case "--help" :: _ | "help" :: _ => help

      case "login" :: rest =>
        parseLogin(rest) match
          case Right((server, principal)) => Commands.login(server, principal)
          case Left(msg)                  => CommandResult.err(s"$msg\n\n${loginHelp}")

      case "keys" :: subcmd :: rest =>
        keysCommand(subcmd, rest, cfg, makeClient)

      case "agent" :: "issue" :: _   => Commands.agentIssue
      case "audit" :: "tail" :: _    => Commands.auditTail
      case "advisor" :: "scan" :: _  => Commands.advisorScan

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
          case _ => CommandResult.err(s"keys get: missing <id>\n\nUsage: aegis keys get <id>")

      case "activate" =>
        rest match
          case id :: _ if id.nonEmpty => Commands.keysActivate(makeClient(cfg), id)
          case _ => CommandResult.err(s"keys activate: missing <id>\n\nUsage: aegis keys activate <id>")

      case "destroy" =>
        rest match
          case id :: _ if id.nonEmpty => Commands.keysDestroy(makeClient(cfg), id)
          case _ => CommandResult.err(s"keys destroy: missing <id>\n\nUsage: aegis keys destroy <id>")

      case other =>
        CommandResult.err(s"unknown keys subcommand: $other\n\n${keysHelp}")

  /** Parse `aegis login --server <url> [--user <subject>]`. */
  private def parseLogin(args: List[String]): Either[String, (String, Option[String])] =
    val flags = parseFlags(args)
    flags.get("--server") match
      case None      => Left("login: --server <url> is required")
      case Some(url) => Right((url, flags.get("--user")))

  /** Parse `aegis keys create --alg AES-256 --name <name>` (also accepts `--alg AES --size 256`). */
  private def parseKeysCreate(args: List[String]): Either[String, (String, Int, String)] =
    val flags = parseFlags(args)
    val name = flags.get("--name").toRight("keys create: --name <name> is required")

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
          case None    => Left("keys create: --size is required when --alg has no size suffix")

    for
      n  <- name
      as <- algAndSize
    yield (as._1, as._2, n)

  /** Tiny `--key value --key2 value2 …` flag parser. Anything else gets ignored — fine for our tiny surface. */
  private def parseFlags(args: List[String]): Map[String, String] =
    args.sliding(2, 2).collect {
      case List(k, v) if k.startsWith("--") => k -> v
    }.toMap

  // ── Help text ──────────────────────────────────────────────────────────────

  private def help: CommandResult = CommandResult.out(
    """aegis — Aegis-KMS admin CLI
      |
      |Usage:
      |  aegis version
      |  aegis login --server <url> [--user <subject>]
      |  aegis keys create --alg AES-256 --name <name>
      |  aegis keys get <id>
      |  aegis keys activate <id>
      |  aegis keys destroy <id>
      |  aegis agent issue        (planned — PR A1)
      |  aegis audit tail         (planned — PR F2.b)
      |  aegis advisor scan       (planned — PR W4)
      |
      |Config: $AEGIS_CONFIG, or ~/.aegis/config.json
      |Env:    AEGIS_SERVER, AEGIS_USER override the saved config""".stripMargin
  )

  private val loginHelp: String     = "Usage: aegis login --server <url> [--user <subject>]"
  private val keysHelp: String      =
    """Usage:
      |  aegis keys create --alg <ALG> --name <NAME>
      |  aegis keys get <id>
      |  aegis keys activate <id>
      |  aegis keys destroy <id>""".stripMargin
  private val keysCreateHelp: String = "Usage: aegis keys create --alg AES-256 --name <name>"
