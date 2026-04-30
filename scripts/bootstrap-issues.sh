#!/usr/bin/env bash
#
# Bootstrap the GitHub issue tracker for Aegis-KMS from ROADMAP.md.
#
# Run once after `gh auth login`. Idempotent: safe to re-run — labels and
# milestones use `--force` / "create or update" semantics, and issue creation
# is gated on title uniqueness (we skip an issue if one with the same title
# already exists).
#
# Usage:
#   brew install gh                           # one-time
#   gh auth login                             # one-time, follow the prompts
#   ./scripts/bootstrap-issues.sh             # creates labels + milestones + issues
#
# To dry-run (print what would be created without touching GitHub):
#   DRY_RUN=1 ./scripts/bootstrap-issues.sh

set -euo pipefail

REPO="${REPO:-sharma-bhaskar/aegis-kms}"
DRY_RUN="${DRY_RUN:-}"

# ─── Helpers ─────────────────────────────────────────────────────────────────

run() {
  if [[ -n "$DRY_RUN" ]]; then
    echo "    [dry-run] $*"
  else
    "$@"
  fi
}

ensure_label() {
  local name="$1" color="$2" desc="$3"
  if gh label list --repo "$REPO" --json name -q '.[].name' | grep -Fxq "$name"; then
    echo "  · label exists: $name"
    return 0
  fi
  echo "  + label: $name ($color)"
  run gh label create --repo "$REPO" "$name" --color "$color" --description "$desc"
}

ensure_milestone() {
  local title="$1" desc="$2"
  if gh api "repos/$REPO/milestones?state=all" --jq '.[].title' | grep -Fxq "$title"; then
    echo "  · milestone exists: $title"
    return 0
  fi
  echo "  + milestone: $title"
  run gh api --method POST "repos/$REPO/milestones" \
    -f "title=$title" -f "description=$desc" \
    --silent
}

ensure_issue() {
  local title="$1" milestone="$2" labels="$3" body="$4"

  if gh issue list --repo "$REPO" --state all --search "\"$title\" in:title" --json title -q '.[].title' | grep -Fxq "$title"; then
    echo "  · issue exists: $title"
    return 0
  fi
  echo "  + issue: $title  [milestone=$milestone, labels=$labels]"
  if [[ -n "$DRY_RUN" ]]; then
    echo "    [dry-run] gh issue create --title \"$title\" --milestone \"$milestone\" --label \"$labels\""
    return 0
  fi
  if ! gh issue create --repo "$REPO" \
       --title "$title" \
       --milestone "$milestone" \
       --label "$labels" \
       --body "$body" >/dev/null; then
    echo "    !! issue creation failed (continuing): $title" >&2
    FAILED_ISSUES+=("$title")
  fi
}

FAILED_ISSUES=()

# ─── 1. Labels ───────────────────────────────────────────────────────────────

echo "── labels ──────────────────────────────────────────────────────────────"

# Areas
ensure_label "area/audit"             "0E8A16" "Audit log, sinks, fan-out"
ensure_label "area/ai-governance"     "B60205" "Agent registry, kill-switch, governance features"
ensure_label "area/auto-response"     "B60205" "W3 — auto-response loop (revoke / step-up / alert)"
ensure_label "area/compliance"        "5319E7" "SOC2 / PCI / HIPAA / NIST AI RMF / EU AI Act"
ensure_label "area/crypto"            "FBCA04" "Cryptographic ops, RoT, key lifecycle"
ensure_label "area/deployment"        "1D76DB" "Docker, Helm, k8s operator, deployment topology"
ensure_label "area/iam"               "0E8A16" "Identity, OIDC, JWT, agent tokens"
ensure_label "area/integration/aws"   "FF9900" "AWS-specific integrations"
ensure_label "area/integration/azure" "0089D6" "Azure-specific integrations"
ensure_label "area/integration/gcp"   "4285F4" "GCP-specific integrations"
ensure_label "area/integration/kafka" "231F20" "Apache Kafka audit fan-out / source"
ensure_label "area/integration/mysql" "00758F" "MySQL / MariaDB event journal adapter"
ensure_label "area/integration/nats"  "27AAE1" "NATS / NATS JetStream audit fan-out"
ensure_label "area/integration/sqlite" "003B57" "SQLite event journal (embedded / dev)"
ensure_label "area/integration/oidc"  "0E8A16" "OIDC providers (Keycloak / Authentik / Dex / Okta / Auth0)"
ensure_label "area/integration/opa"   "7D4698" "Open Policy Agent (Rego) externalised policy"
ensure_label "area/integration/redis" "DC382C" "Redis (jti revocation, rate limit, nonce cache)"
ensure_label "area/integration/splunk" "65A637" "Splunk HEC audit sink"
ensure_label "area/integration/vault" "FFD814" "HashiCorp Vault adapter / Transit RoT"
ensure_label "area/multi-tenancy"     "5319E7" "Per-tenant isolation"
ensure_label "area/observability"     "0052CC" "Metrics, traces, logs"
ensure_label "area/policy"            "5319E7" "Policy engine, rule evaluation, decision recording"
ensure_label "area/risk"              "B60205" "W2 — risk scoring / step-up logic"
ensure_label "area/sdk"               "C5DEF5" "Scala / Java / Python / TS / Go / Rust SDKs"
ensure_label "area/server-tier"       "1D76DB" "Pekko-based server modules (server, http, kmip, mcp, agent-ai)"
ensure_label "area/wedge"             "B60205" "The four-pillar differentiator"
ensure_label "area/wedge/llm-advisor" "B60205" "W4 — read-only LLM advisor"
ensure_label "area/wire/agent-ai"     "0052CC" "Agent-AI plane (function-call shape)"
ensure_label "area/wire/kmip"         "0052CC" "KMIP TTLV / TLS / multi-version"
ensure_label "area/wire/mcp"          "0052CC" "Model Context Protocol server"

# Kinds
ensure_label "kind/feature"  "A2EEEF" "New capability"
ensure_label "kind/bug"      "D73A4A" "Something is broken"
ensure_label "kind/security" "B60205" "Security-relevant change"
ensure_label "kind/docs"     "0075CA" "Documentation"
ensure_label "kind/refactor" "C2E0C6" "Internal change with no behaviour delta"
ensure_label "kind/release"  "5319E7" "Release-pipeline / packaging"

# Status / triage
ensure_label "good first issue" "7057FF" "Good for newcomers"
ensure_label "help wanted"      "008672" "Community contribution welcome"
ensure_label "priority/high"    "B60205" "Block this milestone if not done"
ensure_label "priority/medium"  "FBCA04" "Should land in this milestone"
ensure_label "priority/low"     "0E8A16" "Nice to have"

# ─── 2. Milestones ───────────────────────────────────────────────────────────

echo ""
echo "── milestones ──────────────────────────────────────────────────────────"

ensure_milestone "v0.1.1" "Make Aegis a real KMS — sign/verify/encrypt/decrypt/wrap/unwrap, rotate, metrics, tracing, Resource[IO,Unit] boot scope, Maven Central."
ensure_milestone "v0.2.0" "Ship the wedge — anomaly surfacing in CLI, risk scorer, auto-responder, agent-token issuance, audit table + audit-tail API, OIDC/JWKS, SIEM webhook, Kafka fan-out, Redis revocation list."
ensure_milestone "v0.2.1" "LLM advisor — aegis advisor scan/explain with bounded prompt set, pluggable LLM provider."
ensure_milestone "v0.3.0" "Multi-cloud + production deployment — GCP/Azure/Vault/Software RoT adapters, Helm chart, time-windowed access, JIT access, approval workflows."
ensure_milestone "v0.4.0" "KMIP + MCP — TTLV codec, TLS server, multi-version negotiation; MCP server with tool annotations + host approval flow + per-prompt accountability."
ensure_milestone "v0.5.0" "HSM + Standalone hardening — PKCS#11 adapter (Luna/nShield/YubiHSM/CloudHSM/SoftHSM), AEAD wrapping, audit immutability proofs."
ensure_milestone "v0.6.0" "Compliance + multi-tenancy — per-tenant isolation, compliance reports, NIST AI RMF / EU AI Act mapping, GDPR labels, audit retention tiering."
ensure_milestone "v1.0.0" "API stability + production-hardened — algebra/REST surface stability guarantees, performance targets, chaos testing, runbook."

# ─── 3. Issues ───────────────────────────────────────────────────────────────

echo ""
echo "── issues ──────────────────────────────────────────────────────────────"

# v0.1.1 — Make Aegis a real KMS
ensure_issue "Add sign / verify operations to KeyService + REST + AWS adapter" "v0.1.1" "area/crypto,kind/feature,priority/high" \
"Add \`sign(id, message, alg)\` and \`verify(id, message, signature, alg)\` to the \`KeyService[F[_]]\` algebra in \`aegis-core\`. Wire through the \`AwsKmsRootOfTrust\` adapter using \`Sign\` and \`Verify\` AWS KMS API calls, then expose \`POST /v1/keys/{id}/sign\` and \`POST /v1/keys/{id}/verify\` REST endpoints with request/response DTOs.

**Acceptance:**
- New algebra methods with property-based round-trip tests.
- AWS adapter implements them via real AWS SDK calls (with localstack-based integration test).
- REST endpoints validated end-to-end.
- CLI gains \`aegis keys sign --id ... --message ...\` and \`aegis keys verify\`.

Tracked in [ROADMAP.md §v0.1.1](../ROADMAP.md#v011--make-it-a-real-kms) (1.1.a, 1.1.b)."

ensure_issue "Add encrypt / decrypt operations to KeyService + REST + AWS adapter" "v0.1.1" "area/crypto,kind/feature,priority/high" \
"Add \`encrypt(id, plaintext, ctx)\` and \`decrypt(id, ciphertext, ctx)\` to the algebra. Wire through AWS adapter (\`Encrypt\` / \`Decrypt\` API). Expose \`/v1/keys/{id}/encrypt\` and \`/v1/keys/{id}/decrypt\` with the encryption-context map propagated end-to-end.

Tracked in [ROADMAP.md §v0.1.1](../ROADMAP.md#v011--make-it-a-real-kms) (1.1.c)."

ensure_issue "Add wrap / unwrap operations to KeyService + REST + AWS adapter" "v0.1.1" "area/crypto,kind/feature,priority/high" \
"Add \`wrap(id, dek)\` and \`unwrap(id, wrappedDek)\` for envelope encryption. AWS adapter uses \`Encrypt\`/\`Decrypt\` of the DEK material. Expose \`/v1/keys/{id}/wrap\` and \`/v1/keys/{id}/unwrap\`.

Tracked in [ROADMAP.md §v0.1.1](../ROADMAP.md#v011--make-it-a-real-kms) (1.1.d)."

ensure_issue "Add rotate(id, policy) — new active version, old → Deactivated" "v0.1.1" "area/crypto,kind/feature,priority/high" \
"Implement key rotation per ARCHITECTURE.md §3 state machine: a rotate call creates a new version of the same logical key (PreActive, then Active), and the previous version transitions to Deactivated (still legal for verify and decrypt so existing ciphertexts/signatures stay readable). Per-key policy: time-based, op-count-based, or manual.

Tracked in [ROADMAP.md §v0.1.1](../ROADMAP.md#v011--make-it-a-real-kms) (1.1.e)."

ensure_issue "Add compromise(id, reason) operator override" "v0.1.1" "area/crypto,kind/security,priority/medium" \
"Manual override that locks a key down — it can no longer perform any cryptographic operation. The compromise itself is the highest-severity audit event.

Tracked in [ROADMAP.md §v0.1.1](../ROADMAP.md#v011--make-it-a-real-kms) (1.1.f)."

ensure_issue "Prometheus /metrics endpoint" "v0.1.1" "area/observability,kind/feature,priority/high" \
"Expose Prometheus-format metrics on \`/metrics\`: request rate (per route + status), latency histograms, error rate, audit-write lag, journal-append latency, Pekko mailbox depth, JVM/GC standard set. Use \`prometheus4cats\` or hand-rolled with \`micrometer-registry-prometheus\`.

Tracked in [ROADMAP.md §v0.1.1](../ROADMAP.md#v011--make-it-a-real-kms) (1.1.g)."

ensure_issue "OpenTelemetry tracing across REST + JDBC + AWS SDK" "v0.1.1" "area/observability,kind/feature,priority/high" \
"Auto-instrument the REST surface (Tapir/pekko-http), the Doobie/JDBC layer, and the AWS SDK calls so every request produces a single trace from edge to RoT. Standard W3C trace-context header propagation. Test against a Jaeger or Tempo container.

Tracked in [ROADMAP.md §v0.1.1](../ROADMAP.md#v011--make-it-a-real-kms) (1.1.h)."

ensure_issue "Resource[IO, Unit] boot scope for graceful shutdown" "v0.1.1" "area/server-tier,kind/refactor,priority/medium" \
"Wrap the entire server boot in a \`Resource[IO, Unit]\` so the Postgres connection pool, Pekko ActorSystem, audit sinks, and HTTP binding all release cleanly on SIGTERM. Today's Postgres path leaks the pool until JVM exit (called out in CHANGELOG known limitations).

Tracked in [ROADMAP.md §v0.1.1](../ROADMAP.md#v011--make-it-a-real-kms) (1.1.i)."

ensure_issue "Anomaly detector: time-of-day + source-IP + op-histogram baselines" "v0.1.1" "area/wedge,area/ai-governance,kind/feature,priority/high" \
"Today \`BaselineDetector\` only does scope + rate-spike. Add three more heuristics from POSITIONING §3 \"Anomaly Detection\": time-of-day distribution, source-IP set delta, op-type histogram. Each is a pluggable \`AnomalyHeuristic\` so future ones drop in without changing the framework.

Tracked in [ROADMAP.md §v0.1.1](../ROADMAP.md#v011--make-it-a-real-kms) (1.1.j)."

ensure_issue "Maven Central publishing — Sonatype OSSRH + GPG + workflow secrets" "v0.1.1" "kind/release,priority/high" \
"File OSSRH ticket for \`dev.aegiskms\`, generate a GPG signing key, configure GitHub repo secrets (\`PGP_SECRET\`, \`PGP_PASSPHRASE\`, \`SONATYPE_USERNAME\`, \`SONATYPE_PASSWORD\`). Once configured, the existing \`release.yml\` already publishes via \`sbt ci-release\` — see ROADMAP §v0.1.1.

Tracked in [ROADMAP.md §v0.1.1](../ROADMAP.md#v011--make-it-a-real-kms) (1.1.k)."

# v0.2.0 — Ship the wedge
ensure_issue "Risk scorer (W2): multi-factor numeric score with reasoning" "v0.2.0" "area/risk,area/wedge,kind/feature,priority/high" \
"Combine behavioral baseline (request rate, time-of-day, source-IP set, op histogram) with contextual signals (agent-vs-human, credential age, scope breadth) into a real-valued risk score in [0.0, 1.0]. Recorded in audit context as \`{risk_score: 0.42, risk_factors: [...]}\`.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (2.0.a)."

ensure_issue "Decision adapter: allow / step-up / deny wired into IAM" "v0.2.0" "area/risk,area/wedge,area/policy,kind/feature,priority/high" \
"Translate risk score into one of three decisions. step-up returns 401 with a re-auth challenge. Boolean policy stays as the floor. Recorded in audit as \`outcome.decision\`.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (2.0.b)."

ensure_issue "Auto-responder (W3): rules from AgentRecommendation → action" "v0.2.0" "area/auto-response,area/wedge,area/ai-governance,kind/feature,priority/high" \
"Configurable \`Rule\` entries map a detector + severity to one of: revoke / deactivate / freeze / alert. The auto-responder consumes \`AgentRecommendation\` events from the in-memory sink and applies the rule. Every action recorded as a separate audit event with \`actor=system, reason=AnomalyAlert(...)\`.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (2.0.c)."

ensure_issue "Agent-token issuance HTTP endpoint POST /v1/agents/issue" "v0.2.0" "area/iam,area/wedge,area/ai-governance,kind/feature,priority/high" \
"Expose the existing \`JwtIssuer\` via REST so operators can request agent tokens programmatically. Body: \`{parent, scopes, ttl, label}\`. Response: \`{agent_id, jwt, jti, expires_at}\`. Authorize: only humans can issue agents; agents cannot issue agents.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (2.0.d, 2.0.e)."

ensure_issue "Postgres audit table with indexed schema + retention policy" "v0.2.0" "area/audit,kind/feature,priority/high" \
"\`aegis_audit_events\` table indexed on (actor_subject, occurred_at, key_id, action). Retention configurable via \`aegis.audit.retention.days\`. ARCHITECTURE.md §6 already shows the audit-event shape; this is the Postgres binding.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (2.0.f)."

ensure_issue "Audit-read API: GET /v1/audit?since=&actor=&key=&op=" "v0.2.0" "area/audit,kind/feature,priority/high" \
"Paginated read API over the Postgres audit table. Backs the \`aegis audit tail\` CLI (currently a stub). Authn: same as everything else; audit-read requires the \`audit:read\` permission.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (2.0.g, 2.0.h)."

ensure_issue "Generic SIEM webhook audit sink (HTTPS POST per event, batched + retried)" "v0.2.0" "area/audit,kind/feature,priority/high" \
"Pluggable webhook sink: configurable URL, secret-based HMAC signing of the body, retry with exponential backoff, dead-letter to disk after N attempts. Single config knob \`aegis.audit.sinks.webhook\`.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (2.0.i)."

ensure_issue "Kafka audit fan-out via Pekko-Connectors-Kafka" "v0.2.0" "area/audit,area/integration/kafka,kind/feature,priority/medium" \
"Drop-in \`KafkaAuditSink\` publishing each \`AuditEvent\` as JSON to a configurable topic. Idempotent producer config (acks=all + idempotence). Schema documented in \`docs/audit-event-schema.md\`.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (2.0.j)."

ensure_issue "NATS / NATS JetStream audit sink" "v0.2.0" "area/audit,area/integration/nats,kind/feature,priority/medium,help wanted" \
"Mirror the Kafka sink for NATS JetStream. Useful for shops standardised on NATS for messaging. \`nats.java\` client + JetStream PubAck for durability.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (audit fan-out track)."

ensure_issue "Redis-backed JWT revocation list (jti blacklist)" "v0.2.0" "area/iam,area/integration/redis,kind/security,priority/high" \
"Required for the auto-responder to actually revoke a JWT instantly. Stores revoked \`jti\` values with TTL == token's remaining lifetime. \`JwtVerifier\` checks Redis on every call. Falls back to in-memory if Redis unavailable.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (2.0.k)."

ensure_issue "OIDC verifier + JWKS rotation + RS256/ES256 support" "v0.2.0" "area/iam,kind/feature,priority/high" \
"Today only HS256 ships. OIDC requires fetching the provider's JWKS, caching with TTL, picking the kid that matches the token, verifying with RS256 / ES256 / EdDSA. Test against Keycloak in a Testcontainer.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (2.0.m)."

ensure_issue "Honey keys (canary keys) with auto-alert" "v0.2.0" "area/wedge,area/ai-governance,kind/security,priority/medium,help wanted" \
"Operator marks specific \`KeyId\`s as honey. Any agent operation against a honey key triggers an immediate high-severity alert and auto-revoke of the agent's parent JWT chain. Tagged \`kind/security\` because it's a fishing-detector.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (2.0.l)."

ensure_issue "Open Policy Agent (OPA / Rego) integration as policy backend" "v0.2.0" "area/policy,area/integration/opa,kind/feature,priority/medium,help wanted" \
"Adapter that delegates the \`PolicyEngine.allow(...)\` call to an OPA sidecar (HTTP) or in-process (\`opa-java\`). Lets security teams write policies in Rego instead of Scala. Aegis becomes a Policy Decision Point caller.

Tracked in [ROADMAP.md §v0.2.0](../ROADMAP.md#v020--ship-the-wedge) (2.0.n)."

# v0.2.1 — LLM advisor
ensure_issue "aegis advisor scan — find unused keys, scope-creep, anomalies" "v0.2.1" "area/wedge/llm-advisor,area/ai-governance,kind/feature,priority/high" \
"Wire the existing CLI stub to a backend that reads the audit log + key inventory and answers a bounded set of prompts: unused keys (>N days), scope-creep agents, active anomalies, top-N riskiest agents. Structured output schema; never executes mutations.

Tracked in [ROADMAP.md §v0.2.1](../ROADMAP.md#v021--llm-advisor) (2.1.a)."

ensure_issue "aegis advisor explain <agent-id> — human-readable timeline" "v0.2.1" "area/wedge/llm-advisor,area/ai-governance,kind/feature,priority/medium" \
"Given an agent session, produce a natural-language timeline of what happened, why a recommendation fired, and what action was taken. RAG over the audit table + agent registry. The README's 'aegis advisor explain claude-session-7a3' example is the target shape.

Tracked in [ROADMAP.md §v0.2.1](../ROADMAP.md#v021--llm-advisor) (2.1.b)."

ensure_issue "Pluggable LLM provider (OpenAI / Anthropic / Bedrock / Ollama)" "v0.2.1" "area/wedge/llm-advisor,kind/feature,priority/medium,help wanted" \
"\`LlmProvider\` SPI in \`aegis-agent-ai\` with adapters for the four providers. Local Ollama matters for privacy-conscious shops; cloud providers matter for the \"pair with our existing AI vendor\" pitch.

Tracked in [ROADMAP.md §v0.2.1](../ROADMAP.md#v021--llm-advisor) (2.1.c)."

# v0.3.0 — Multi-cloud + production deployment
ensure_issue "GCP KMS root-of-trust adapter" "v0.3.0" "area/crypto,area/integration/gcp,kind/feature,priority/high" \
"Mirror \`AwsKmsRootOfTrust\` for Google Cloud KMS. \`google-cloud-kms\` client. Same SPI methods (\`encrypt\`, \`decrypt\`, \`generateDataKey\`). Integration test against a fake-gcs-server or real GCP project (env-gated).

Tracked in [ROADMAP.md §v0.3.0](../ROADMAP.md#v030--multi-cloud--production-deployment) (3.0.a)."

ensure_issue "Azure Key Vault root-of-trust adapter" "v0.3.0" "area/crypto,area/integration/azure,kind/feature,priority/high" \
"Mirror AWS adapter for Azure Key Vault using \`azure-security-keyvault-keys\`. HSM-backed keys via the Premium SKU. Integration test env-gated on real Azure.

Tracked in [ROADMAP.md §v0.3.0](../ROADMAP.md#v030--multi-cloud--production-deployment) (3.0.b)."

ensure_issue "HashiCorp Vault Transit root-of-trust adapter" "v0.3.0" "area/crypto,area/integration/vault,kind/feature,priority/high" \
"Adapter for Vault's Transit secrets engine. Different API shape (no native AEAD; use transit/encrypt + transit/decrypt). Test against a real Vault container.

Tracked in [ROADMAP.md §v0.3.0](../ROADMAP.md#v030--multi-cloud--production-deployment) (3.0.c)."

ensure_issue "Software root-of-trust (JCE-backed) for dev/test" "v0.3.0" "area/crypto,kind/feature,priority/medium,good first issue" \
"JDK \`KeyStore\`-backed local RoT, no external dependencies. Ships disabled by default with a loud warning that production deployments must use a real KMS or HSM.

Tracked in [ROADMAP.md §v0.3.0](../ROADMAP.md#v030--multi-cloud--production-deployment) (3.0.d)."

ensure_issue "Helm chart for production Kubernetes deployment" "v0.3.0" "area/deployment,kind/feature,priority/high" \
"\`deploy/helm/aegis-kms/\` is empty today. Need a chart that brings up Postgres (StatefulSet), \`aegis-server\` (Deployment + Service + Ingress), the audit-sink config, and TLS via cert-manager. Values for the typical knobs (replicas, resources, RoT backend, JWT secret).

Tracked in [ROADMAP.md §v0.3.0](../ROADMAP.md#v030--multi-cloud--production-deployment) (3.0.f)."

ensure_issue "Time-windowed access policies (business-hours-only keys)" "v0.3.0" "area/policy,kind/feature,priority/medium" \
"Per-key policy attribute \`allowed_windows\`, e.g. \`[{tz: UTC, days: [Mon..Fri], hours: [9..18]}]\`. PolicyEngine denies outside the window with reason \`OutsideAllowedWindow\`.

Tracked in [ROADMAP.md §v0.3.0](../ROADMAP.md#v030--multi-cloud--production-deployment) (3.0.j)."

# v0.4.0 — KMIP + MCP
ensure_issue "KMIP TTLV codec with multi-version negotiation (1.4 / 2.0 / 2.1 / 3.0)" "v0.4.0" "area/wire/kmip,kind/feature,priority/high" \
"The TTLV (Tag-Type-Length-Value) binary codec is the foundation. Multi-version means the server reads the client's protocol version field and dispatches to the right schema. Test against PyKMIP client + a few real vendors (NetApp simulator if available).

Tracked in [ROADMAP.md §v0.4.0](../ROADMAP.md#v040--kmip--mcp) (4.0.a)."

ensure_issue "KMIP TLS 1.3 server with mTLS client cert auth" "v0.4.0" "area/wire/kmip,area/iam,kind/feature,priority/high" \
"Pekko-stream TLS server with mutual TLS; client cert maps to a \`Principal\` via configured CA + DN-to-subject mapping rules. Standard KMIP profile compliance.

Tracked in [ROADMAP.md §v0.4.0](../ROADMAP.md#v040--kmip--mcp) (4.0.b)."

ensure_issue "KMIP operations: Create, Get, Activate, Destroy, Register, Encrypt, Decrypt, Sign, SignatureVerify" "v0.4.0" "area/wire/kmip,area/crypto,kind/feature,priority/high" \
"The minimum set required for storage / DB-TDE / backup vendor compatibility. Each operation translates KMIP request → \`KeyService\` call → KMIP response, going through identity → policy → audit just like every other plane.

Tracked in [ROADMAP.md §v0.4.0](../ROADMAP.md#v040--kmip--mcp) (4.0.c)."

ensure_issue "MCP server with curated KMS tool surface" "v0.4.0" "area/wire/mcp,area/ai-governance,kind/feature,priority/high" \
"\`aegis-mcp-server\` exposes a fixed list of MCP tools: \`create_key\`, \`activate\`, \`sign\`, \`encrypt\`, \`decrypt\`, \`list_keys\`, \`audit_query\`. Each tool annotated with required permissions + side-effect category so the MCP host can show appropriate approval UI.

Tracked in [ROADMAP.md §v0.4.0](../ROADMAP.md#v040--kmip--mcp) (4.0.e, 4.0.f)."

ensure_issue "Per-prompt accountability — record originating LLM prompt with each MCP-driven op" "v0.4.0" "area/ai-governance,area/wire/mcp,kind/feature,priority/medium,help wanted" \
"When an MCP host calls a tool, ask the host (via MCP context) for the user prompt that triggered it. Record in audit \`context.prompt_hash\` (or full prompt if policy allows). Enables \"which prompts caused which key ops?\" forensics.

Tracked in [ROADMAP.md §v0.4.0](../ROADMAP.md#v040--kmip--mcp) (4.0.g)."

ensure_issue "Model identifier in audit (actor.model = 'claude-3.5-sonnet')" "v0.4.0" "area/ai-governance,area/audit,kind/feature,priority/medium,good first issue" \
"Extend \`Principal.Agent\` with an optional \`model\` field. MCP server populates it from the host's identification. Audit records carry it. Lets analytics split agent activity by model family.

Tracked in [ROADMAP.md §v0.4.0](../ROADMAP.md#v040--kmip--mcp) (4.0.h)."

# v0.5.0 — HSM + Standalone hardening
ensure_issue "PKCS#11 root-of-trust adapter (Luna / nShield / YubiHSM / CloudHSM / SoftHSM)" "v0.5.0" "area/crypto,kind/feature,kind/security,priority/high" \
"Use JDK 21 \`sun.security.pkcs11\` provider. Session/login/object lifecycle is fiddly — write a state machine. Test against SoftHSM in a Testcontainer to shake out the integration without needing real hardware.

Tracked in [ROADMAP.md §v0.5.0](../ROADMAP.md#v050--hsm-backed--standalone-hardening) (5.0.a)."

ensure_issue "SoftHSM Testcontainer for CI integration testing" "v0.5.0" "area/crypto,kind/feature,priority/medium,good first issue" \
"Custom \`testcontainers\` image with SoftHSM2 + a fresh slot. Test fixtures that initialise the slot, generate a master key, and exercise the PKCS#11 adapter. Lets the CI catch PKCS#11 regressions without needing real hardware.

Tracked in [ROADMAP.md §v0.5.0](../ROADMAP.md#v050--hsm-backed--standalone-hardening) (5.0.b)."

# v0.6.0 — Compliance + multi-tenancy
ensure_issue "Multi-tenant Aegis: per-tenant isolation across keys, agents, audit, policies" "v0.6.0" "area/multi-tenancy,kind/feature,priority/high" \
"Add \`TenantId\` to every domain entity, every audit row, every policy rule. Authentication resolves to a \`(Principal, TenantId)\` pair. Authorization enforces tenant boundary on every call. Required for any SaaS-style deployment.

Tracked in [ROADMAP.md §v0.6.0](../ROADMAP.md#v060--compliance--multi-tenancy) (6.0.a)."

ensure_issue "Compliance reports: SOC2 / PCI / HIPAA exportable" "v0.6.0" "area/compliance,area/ai-governance,kind/feature,priority/medium,help wanted" \
"Predefined report templates rendered from the audit table to CSV / PDF. \"List every key any AI agent touched in Q2 across PCI-tagged keys\" etc. Auditors love this.

Tracked in [ROADMAP.md §v0.6.0](../ROADMAP.md#v060--compliance--multi-tenancy) (6.0.b)."

ensure_issue "NIST AI RMF / EU AI Act compliance mapping doc" "v0.6.0" "area/compliance,area/ai-governance,kind/docs,priority/medium,good first issue,help wanted" \
"Document mapping each NIST AI RMF function (govern / map / measure / manage) and each EU AI Act obligation (record-keeping, transparency, human oversight) to the specific Aegis features that satisfy it. Selling point for regulated industries.

Tracked in [ROADMAP.md §v0.6.0](../ROADMAP.md#v060--compliance--multi-tenancy) (6.0.c)."

# Cross-cutting / quick wins
ensure_issue "MySQL adapter for the event journal (driver already in deps)" "v0.2.0" "area/integration/mysql,kind/feature,priority/low,good first issue,help wanted" \
"\`mysql-connector-j\` is already in \`Dependencies.scala\`. Wire a \`MySqlEventJournal\` analogous to \`PostgresEventJournal\` — schema needs minor tweaks (\`BIGSERIAL\` → \`BIGINT AUTO_INCREMENT\`, \`JSONB\` → \`JSON\`).

Tracked in [ROADMAP.md cross-cutting](../ROADMAP.md#database-support)."

ensure_issue "SQLite adapter for embedded / single-node demos" "v0.2.0" "kind/feature,priority/low,good first issue,help wanted" \
"Lets users boot Aegis without Postgres for laptop demos and CI. \`sqlite-jdbc\` driver, schema adapted for SQLite (no \`JSONB\`, use \`TEXT\` and parse JSON in app).

Tracked in [ROADMAP.md cross-cutting](../ROADMAP.md#database-support)."

ensure_issue "Docker Compose hardening: no default Postgres password" "v0.1.1" "area/deployment,kind/security,priority/medium,good first issue" \
"Replace \`POSTGRES_PASSWORD: aegis-dev-password-change-me\` in \`deploy/docker/docker-compose.yml\` with \`\${POSTGRES_PASSWORD:?required}\` so compose fails fast without an explicit value. Also add a \`SECURITY.md\` documenting the deploy-time decisions.

Tracked in [ROADMAP.md cross-cutting](../ROADMAP.md#observability--ops)."

ensure_issue "OpenAPI advertising + Swagger UI on REST plane" "v0.1.1" "area/wire/agent-ai,kind/docs,priority/medium,good first issue" \
"Tapir's \`tapir-openapi-docs\` and \`tapir-swagger-ui-bundle\` are already deps. Add a \`/openapi.yaml\` route and a Swagger UI under \`/docs\`. Discovery for any tool that reads OpenAPI.

Tracked in [ROADMAP.md cross-cutting](../ROADMAP.md#wire-planes)."

# ─── 4. Done ─────────────────────────────────────────────────────────────────

echo ""
echo "── done ────────────────────────────────────────────────────────────────"
if [[ ${#FAILED_ISSUES[@]} -gt 0 ]]; then
  echo "${#FAILED_ISSUES[@]} issue(s) failed to create:" >&2
  for t in "${FAILED_ISSUES[@]}"; do
    echo "  - $t" >&2
  done
  echo "Re-run the script after fixing the underlying problem (it's idempotent)." >&2
fi
echo "Browse:"
echo "  https://github.com/${REPO}/issues"
echo "  https://github.com/${REPO}/milestones"
echo "  https://github.com/${REPO}/labels"
