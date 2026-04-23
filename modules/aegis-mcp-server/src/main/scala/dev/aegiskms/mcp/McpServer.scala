package dev.aegiskms.mcp

/** Aegis-KMS MCP server. Exposes KMS operations as Model Context Protocol tools so Claude and other
  * MCP-speaking LLMs can act as operators (within the scope of a `Principal.Agent`).
  *
  * Planned tool surface:
  *   - aegis.keys.list
  *   - aegis.keys.create
  *   - aegis.keys.rotate
  *   - aegis.keys.revoke (step-up required)
  *   - aegis.keys.destroy (step-up required)
  *   - aegis.audit.search
  *   - aegis.policy.recommend
  *
  * Placeholder during scaffolding.
  */
object McpServer:
  val tools: List[String] = List(
    "aegis.keys.list",
    "aegis.keys.create",
    "aegis.keys.rotate",
    "aegis.keys.revoke",
    "aegis.keys.destroy",
    "aegis.audit.search",
    "aegis.policy.recommend"
  )
