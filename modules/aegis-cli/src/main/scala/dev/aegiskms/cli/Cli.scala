package dev.aegiskms.cli

/** The `aegis` admin CLI. Planned commands:
  *
  *   aegis keys create --alg AES-256 --name invoice-signing
  *   aegis keys list
  *   aegis keys rotate <id>
  *   aegis keys revoke <id>
  *   aegis policy show
  *   aegis audit tail
  *
  * Placeholder during scaffolding.
  */
object Cli:
  def main(args: Array[String]): Unit =
    args.toList match
      case "version" :: Nil => println("aegis 0.1.0-SNAPSHOT")
      case _ =>
        println(
          """aegis — Aegis-KMS admin CLI (scaffold)
            |
            |Usage:
            |  aegis version
            |  aegis keys create --alg <ALG> --name <NAME>
            |  aegis keys list
            |  aegis keys rotate <id>
            |  aegis keys revoke <id>
            |  aegis policy show
            |  aegis audit tail
            |""".stripMargin
        )
