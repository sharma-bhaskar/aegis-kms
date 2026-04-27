# Positioning

What Aegis is, what it isn't, and why the framing matters.

## In one sentence

**Aegis protects AI agents from abusing API keys.** It sits in front of the key store you already have (AWS KMS, GCP, Azure, Vault, HSM) and adds the four things every existing key manager is missing for the agent era: agent-to-human identity binding, context-aware risk scoring, behavioral anomaly detection, and real-time auto-response.

Everything else — KMIP fronting, REST surface, MCP server, layered/standalone/HSM deployment — stays behind the curtain. Those are the plumbing that makes the protection work; they are not what we sell.

## Why this framing, not "yet another KMS"

The temptation when you build a key manager is to position it as a key manager. That positioning is weak:

- There are already excellent open-source key managers (Vault, OpenBao, PyKMIP, EJBCA, Cosmian).
- There is a mature commercial market (AWS KMS, GCP, Azure, Thales CipherTrust, Fortanix).
- Adding one more "OSS KMIP server with a Scala twist" to that list is forgettable.

What is genuinely missing today, across all of those products, is a system designed for the world we're actually moving into — one where AI agents are first-class actors in production systems and **nobody is in control of how they use credentials.**

Three concrete gaps no other KMS closes:

- **You don't know which agent did it.** Service-account audit collapses to "the API key did it." There's no notion of "Claude session 7a3, acting on Alice's behalf, between 02:55 and 03:55, scoped to these keys."
- **You don't catch misuse until next week.** Static IAM says "the agent is in the right role" while it calls `sign` 80× per second at 3 AM from a new IP. Every existing KMS pushes that signal to a SIEM that gets read on Monday.
- **You can't respond in real time.** Detection without auto-response means a human gets paged, logs in, and revokes — minutes to hours after the damage. With agents that can sign 50 things per second, "minutes" is the entire incident.

These gaps are the wedge. Aegis exists to close them.

## The four pillars (what users see)

The product surface is intentionally small. Four checks on every request, every time:

### 1. Identity & Context

Every action is attributed to either a `Principal.Human` or a `Principal.Agent`. Agents carry a mandatory back-pointer to the parent human who issued the credential, the explicit scope (which keys, which ops), and the time window. There is no anonymous agent identity.

What this enables:

- `aegis audit --actor alice@org` joins Alice's actions and every agent she ever spawned, automatically.
- Revoking Alice revokes every credential issued under her — no orphan agent tokens.
- An agent's allowlist is enforced on every call, not just at issuance.

No other KMS — proprietary or open source — has this model.

### 2. Risk Scoring

Each request is scored against the actor's behavioral baseline (request rate, time-of-day distribution, source IP set, op-type histogram, key set used) and contextual signals (deployment environment, agent vs. human, credential age, scope breadth). The score informs the decision: **allow, step-up (re-auth, MFA), or deny** — and is recorded in the audit event with structured reasoning.

Boolean policy is the floor. Risk scoring is the layer that catches "the right principal in the right role being used in the wrong way."

### 3. Anomaly Detection

A streaming detector watches the audit log and flags deviations: usage spikes, off-hours access, new source IPs, new op types per key, agents touching keys outside their normal pattern. Detections produce `AgentRecommendation` events surfaced in the operator UI, the CLI, and webhooks.

### 4. Real-time Response

Configurable wiring from detections to actions: **allow · step-up · deny · rotate · revoke · alert.** All recorded. The point is that the loop closes inside Aegis — without a human in the path for the cases that don't need one.

A focused **LLM advisor** complements the four checks: it reads the audit log and key inventory and answers questions like "explain why this key is risky," "suggest a rotation policy for this set of keys," "find unused keys older than 60 days," "summarize what Alice's agents did this week." It's read-only and never executes mutations directly.

## What's behind the curtain

Once the four pillars are the lead, everything else is plumbing — important plumbing, but not the thing on the box.

### Three deployment modes

The same `KeyService` algebra runs in all three; only the data plane differs.

**Layered (recommended for almost everyone).** Aegis fronts your existing AWS KMS, GCP KMS, Azure Key Vault, or HashiCorp Vault. You don't migrate keys. You either register existing CMK ARNs or have Aegis delegate new key creation to the cloud KMS. Every operation passes through Aegis (identity, risk, audit, response) and is proxied to the cloud KMS for the actual crypto. You keep your existing FIPS attestation, SLAs, cost model, and escape hatch.

**Standalone.** Aegis owns the data plane too. Keys are generated by the configured Root of Trust (software / cloud-KMS in envelope mode / PKCS#11) and the wrapped form is persisted in Aegis's Postgres. Best for air-gapped deployments, sovereign-cloud requirements, and full-stack OSS shops who don't want a dependency on a commercial KMS.

**HSM-backed.** Aegis is the control plane in front of a real PKCS#11 HSM (Thales Luna, Entrust nShield, YubiHSM, AWS CloudHSM). The HSM generates and holds all key material; Aegis holds opaque handles. Best for FIPS 140-2 Level 3, regulated industries, and any deployment that needs to attest that key material has never existed outside a tamper-resistant boundary.

### Four wire planes

REST for app developers. KMIP for storage / DB / backup vendors that speak only KMIP. **MCP server out of the box** for Claude, Cursor, and any other MCP-aware host — with the same identity, scope, risk scoring, and response model as REST and KMIP. Agent-AI plane for the intelligence layer itself.

The MCP host's approval UI gives the human a chance to approve sensitive operations before they run. Critically, **there is not a separate auth model for AI tools** — which is what every "we added an LLM endpoint" bolt-on actually has.

## What Aegis is *not*

- **Not a general secrets manager.** Vault and OpenBao do dynamic database credentials, SSH CA, AppRole, and a dozen other things. Aegis is intentionally narrow — keys, agents, and the lifecycle around them. Pair it with a secrets manager rather than expecting one tool to do both.
- **Not a replacement for AWS KMS / GCP / Azure KMS.** In layered mode it's explicitly a *layer*, not a substitute. Most teams should not migrate their CMKs.
- **Not a cryptographic library.** It uses Tink, BouncyCastle, and the JCE underneath. If you want algorithms and primitives, use those directly.
- **Not a SIEM or a security analytics platform.** The intelligence layer focuses on what's in the KMS audit log. It surfaces detections; it integrates with your SIEM via webhooks; it doesn't try to replace it.
- **Not "MCP for keys" or "an OSS KMIP server."** Both are true. Neither is the point. The point is agent abuse protection. Those are the wires.

## Honest competitive positioning

In one paragraph each. The full version with sub-bullets is in [ARCHITECTURE.md §10](ARCHITECTURE.md#10-how-aegis-kms-compares).

**vs AWS / GCP / Azure KMS.** Excellent products if your entire infrastructure lives in one cloud and you have no AI agents. Pick them for the data plane; pick Aegis as the layered control plane on top — that's where agent identity, risk scoring, anomaly detection, and auto-response live.

**vs HashiCorp Vault Enterprise.** Vault is a general secrets manager that happens to include KMIP and a transit engine. Aegis is purpose-built for keys, has an Apache-2.0 license that includes KMIP, and ships an agent-native model and intelligence layer Vault does not. If you already run Vault Enterprise and use most of its breadth, stay. If you bought Vault for the KMIP engine specifically, or you want real agent governance, Aegis is the credible alternative.

**vs OpenBao.** Peer license-wise (MPL-2.0 vs Apache-2.0), missing KMIP (it didn't fork from Vault Enterprise), and missing the agent-native and intelligence-layer story.

**vs PyKMIP / Cosmian / EJBCA.** KMIP-only. No REST, no MCP, no agent identity, no intelligence layer. Aegis strictly supersets them on everything except language ecosystem (pick those if you specifically need Python/Rust/Java rather than Scala).

## When *not* to use Aegis

- You are 100% on AWS, have no AI agents in production, and don't anticipate either changing. AWS KMS is well-integrated and Aegis adds operational overhead without enough payoff yet.
- You need a general secrets manager (database credentials, dynamic secrets, SSH CA). Use Vault or OpenBao for that and — if the keys story matters — pair them with Aegis.
- You are pre-product, pre-customers, and adding a control plane is premature. Use a cloud KMS directly until the cost of *not* having identity, audit, and intelligence is real.

## The roadmap toward the wedge

The substrate is in the scaffold today: the four wire planes, the IAM model, the audit log, the agent identity model, the pluggable RoT. The differentiator work happens in `aegis-agent-ai`, in roughly this order:

1. **Anomaly detection on key usage.** Sliding-window baseline per key / per actor / per source; `AgentRecommendation` events; CLI surfacing. *(Smallest scope, biggest demo value — this is the thing that makes the "Claude goes rogue" example in the README actually run.)*
2. **Risk-scored access decisions.** Multi-factor scorer, thresholds wired into IAM, recorded reasoning in audit context. Boolean policy stays as the floor.
3. **Auto-response.** Configurable wiring from detections to actions: revoke, deactivate, alert, freeze, rotate.
4. **LLM advisor.** Bounded helper that reads the audit log and inventory and answers fixed prompts ("unused keys," "rotation suggestions," "explain riskiness"). Carefully scoped — read-only, never executes mutations directly.
5. **Layered-mode integrations.** First-class registration and proxying for AWS KMS, GCP KMS, Azure Key Vault, Vault Transit. Standalone and HSM-backed already covered by the Root-of-Trust SPI.
6. **MCP polish.** Tool annotations, host-side approval flow, scope explorer, audit replay.

Each of these is independently shippable and demoable. The order is chosen so each one builds on what's already there and produces a concrete artifact someone outside the project can use.

## See also

- [README](../README.md) — the agent-abuse framing, the four pillars, the "Claude goes rogue" example, the demo transcript.
- [ARCHITECTURE.md](ARCHITECTURE.md) — module layout, wire planes, key lifecycle, audit model, security model, comparison.
- [USAGE.md](USAGE.md) — end-to-end walkthrough for app developers, operators, AI agents, and KMIP vendors.
