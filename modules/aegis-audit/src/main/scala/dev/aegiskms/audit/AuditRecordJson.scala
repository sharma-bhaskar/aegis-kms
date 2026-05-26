package dev.aegiskms.audit

import dev.aegiskms.core.{Operation, Principal}
import io.circe.{Encoder, Json}

/** Canonical JSON serialisation for `AuditRecord` — used by sinks that POST records to external systems (the
  * SIEM webhook sink in `aegis-server`; future Kafka/NATS sinks). Lives in the library tier so any future
  * audit sink (in `aegis-audit`, in `aegis-server`, or in a community module) can reuse the same wire shape.
  *
  * Distinct from `aegis-http`'s `AuditRecordDto`: that one is the REST audit-read endpoint's wire format and
  * may evolve with the API surface. This one is the canonical record shape downstream SIEM / streaming
  * consumers will pin to, and should change only with a versioning story.
  *
  * Shape (top-level JSON object):
  * {{{
  * {
  *   "at":            "2026-05-26T10:14:53.412Z",       // ISO-8601 UTC
  *   "actor":         { "subject": "alice@org", "kind": "Human", ... },
  *   "operation":     "Sign",                            // KMIP enum name
  *   "resource":      "key:invoice-2026",
  *   "outcome":       "Success alg=RsaPssSha256 msgLen=42",
  *   "correlationId": "0c5e7f0e-3a8c-4b2a-8e6c-3b8d…",
  *   "context":       { "source.ip": "203.0.113.42", "risk.score": "0.42", … }
  * }
  * }}}
  *
  * The `actor` subobject preserves the `Principal` ADT discriminator so consumers can tell a Human from an
  * Agent apart without re-deriving it from the subject string.
  */
object AuditRecordJson:

  given Encoder[Principal] = Encoder.instance {
    case Principal.Human(subject, groups) =>
      Json.obj(
        "kind"    -> Json.fromString("Human"),
        "subject" -> Json.fromString(subject),
        "groups"  -> Json.fromValues(groups.toList.sorted.map(Json.fromString))
      )
    case Principal.Service(subject, tenant) =>
      import dev.aegiskms.core.TenantId.value
      Json.obj(
        "kind"    -> Json.fromString("Service"),
        "subject" -> Json.fromString(subject),
        "tenant"  -> Json.fromString(tenant.value)
      )
    case Principal.Agent(subject, operator, purpose, issuedAt, ttl, allowedOps, parent) =>
      import dev.aegiskms.core.AgentId.value
      Json.obj(
        "kind"    -> Json.fromString("Agent"),
        "subject" -> Json.fromString(subject),
        // Operator is the issuing human/service principal — recurses through the ADT to capture the
        // full chain of responsibility. SIEM rules can pattern-match on `actor.operator.subject` to
        // attribute an agent action to its human issuer without re-joining elsewhere.
        "operator"   -> summon[Encoder[Principal]].apply(operator),
        "purpose"    -> Json.fromString(purpose),
        "issuedAt"   -> Json.fromString(issuedAt.toString),
        "ttlSeconds" -> Json.fromLong(if ttl.isFinite then ttl.toSeconds else -1L),
        "allowedOps" -> Json.fromValues(allowedOps.toList.map(_.toString).sorted.map(Json.fromString)),
        // `parent` is the lineage chain for agents-issued-by-agents (rare today, allowed by the ADT).
        "parent" -> parent.fold(Json.Null)(id => Json.fromString(id.value))
      )
  }

  given Encoder[Operation] = Encoder.instance(op => Json.fromString(op.toString))

  given Encoder[AuditRecord] = Encoder.instance { r =>
    Json.obj(
      "at"            -> Json.fromString(r.at.toString),
      "actor"         -> summon[Encoder[Principal]].apply(r.principal),
      "operation"     -> summon[Encoder[Operation]].apply(r.operation),
      "resource"      -> Json.fromString(r.resource),
      "outcome"       -> Json.fromString(r.outcome),
      "correlationId" -> Json.fromString(r.correlationId),
      "context" -> Json.obj(
        r.context.toList.sortBy(_._1).map { case (k, v) => k -> Json.fromString(v) }*
      )
    )
  }
