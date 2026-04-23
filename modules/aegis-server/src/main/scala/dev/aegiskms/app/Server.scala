package dev.aegiskms.app

/** Main entry point for the standalone Aegis-KMS server.
  *
  * This wires together all modules — `aegis-kmip`, `aegis-http`, `aegis-mcp-server`, `aegis-agent-ai`,
  * `aegis-iam`, `aegis-audit`, `aegis-persistence`, `aegis-crypto` — under a single Pekko Typed
  * `ActorSystem[Guardian.Command]`.
  *
  * Placeholder during scaffolding.
  */
object Server:
  def main(args: Array[String]): Unit =
    println("aegis-server: scaffold only. See ENHANCEMENT_PLAN.md for the roadmap.")
