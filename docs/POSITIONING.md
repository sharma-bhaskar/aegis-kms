# Positioning

What Aegis-KMS is, what it isn't, and why the framing matters.

## In one sentence

Aegis-KMS is the **agent-native control and intelligence plane** for cryptographic keys — sitting in front of the key store you already have (AWS KMS, GCP, Azure, Vault, HSM), adding the things every legacy KMS is missing: AI agent identity, context-aware risk scoring, baseline-aware anomaly detection, and an MCP server that lets LLMs use keys safely under human-tied scopes.

## The shift

This project deliberately is not "yet another open-source KMS." That positioning is weak: there are already excellent open-source key managers (Vault, OpenBao, PyKMIP, EJBCA, Cosmian) and a mature commercial market (AWS KMS, GCP, Azure, Thales CipherTrust, Fortanix). Adding one more "OSS KMIP server" to that list is forgettable.

What is genuinely missing today, across all of those products, is a system designed for the world we're actually moving into:

- **AI agents are now first-class actors in production systems.** They sign things, they encrypt things, they call tools that need keys. None of the existing KMSes have a real model for "this action was taken by Claude, on Alice's behalf, under these scopes, for the next hour." Identity collapses to a service account, audit collapses to "the API key did it," and accountability quietly goes missing.
- **Static policy is no longer enough.** "Allow if `principal in role`" doesn't help when the right principal in the right role is being used in the wrong way — at 3 AM, from a new IP, at 80× normal request rate, against keys it has never touched before. Every other KMS treats this as out-of-scope and pushes it to a SIEM that someone might look at next week.
- **Operators are drowning in key sprawl.** Hundreds or thousands of keys, no signal on which are unused, which are over-permissioned, which are due for rotation. An LLM that can read the audit log and surface "these 47 keys haven't been used in 90 days; here's a suggested rotation policy for the rest" is real value that costs nothing to expose because the data is already there.

These three gaps are the wedge. Aegis-KMS exists to close them.

## The three differentiators

### 1. Agent identity tied to a human

Every action is attributed to either a `Principal.Human` or a `Principal.Agent`. An agent always carries the identity of the parent human who issued its credential, the explicit scope (which keys, which ops), and the time window. There is no anonymous agent identity and no way to call Aegis as "an agent" without a parent human on file.

This means:

- `aegis audit --actor alice@org` includes everything Alice's agents did, joined automatically.
- Revoking Alice revokes every credential issued under her — no orphan agent tokens.
- An agent's allowlist is enforced on every call, not just at issuance, so a credential leak has narrow blast radius.

No other KMS — proprietary or open source — has this model.

### 2. Intelligence layer over static policy

Boolean policy is the floor; the intelligence layer (`aegis-agent-ai`) is what you add on top:

- **Risk scoring.** Each request is scored against the actor's behavioral baseline (request rate, time-of-day distribution, source IP set, op-type histogram, key set used) and contextual signals (deployment environment, agent vs. human, cred age, scope breadth). The score informs the decision: allow, step-up (re-auth, MFA), or deny.
- **Anomaly detection.** A streaming detector watches the audit log and flags deviations: usage spikes, off-hours access, new source IPs, new op types per key, agents touching keys outside their normal pattern. Detections produce `AgentRecommendation` events surfaced in the operator UI, the CLI, and webhooks.
- **Auto-response.** Configurable policies wire detections to actions: revoke an agent credential, deactivate a key, page the on-call operator, freeze ops for a key class until human review.
- **LLM advisor.** A focused LLM helper reads the audit log and key inventory and answers questions like "explain why this key is risky," "suggest a rotation policy for this set of keys," "find unused keys older than 60 days," "summarize what Alice's agents did this week."

This module is in active design; the substrate it needs (audit, agent identity, MCP) is already in place.

### 3. MCP-native

Aegis-KMS publishes an MCP server out of the box. Claude, Cursor, and any other MCP-aware host see a curated tool surface (`create_key`, `sign`, `verify`, `rotate`, `list_keys`) with permissions and side effects annotated. The MCP host's approval UI gives the human a chance to approve sensitive operations before they run.

The same agent identity, scope check, and risk scoring apply on the MCP plane as on REST or KMIP — there isn't a separate auth model for AI tools, which is what every "we added an LLM endpoint" bolt-on actually has.

## Three deployment modes

The same `KeyService` algebra runs in all three; only the data plane differs.

### Layered (recommended for almost everyone)

Aegis fronts your existing AWS KMS, GCP KMS, Azure Key Vault, or HashiCorp Vault. You don't migrate keys. You either register existing CMK ARNs or have Aegis delegate new key creation to the cloud KMS. Every operation passes through Aegis (IAM, risk scoring, audit, MCP visibility) and is proxied to the cloud KMS for the actual crypto.

You get: agent governance, risk scoring, anomaly detection, MCP integration, KMIP fronting (for storage/DB customers), audit consolidation across multiple cloud KMSes — without a key migration.

You keep: your existing FIPS attestation, your existing SLAs, your existing cost model, your existing escape hatch.

### Standalone

Aegis owns the data plane too. Keys are generated by the configured Root of Trust (software / cloud-KMS in envelope mode / PKCS#11) and the wrapped form is persisted in Aegis's Postgres. Best for air-gapped deployments, sovereign-cloud requirements, and full-stack OSS shops who don't want a dependency on a commercial KMS.

### HSM-backed

Aegis is the control plane in front of a real PKCS#11 HSM (Thales Luna, Entrust nShield, YubiHSM, AWS CloudHSM). The HSM generates and holds all key material; Aegis holds opaque handles. Best for FIPS 140-2 Level 3, regulated industries, and any deployment that needs to attest that key material has never existed outside a tamper-resistant boundary.

## What Aegis-KMS is *not*

- **Not a general secrets manager.** Vault and OpenBao do dynamic database credentials, SSH CA, AppRole, and a dozen other things. Aegis-KMS is intentionally narrow — keys and the lifecycle around them. Pair it with a secrets manager rather than expecting one tool to do both.
- **Not a replacement for AWS KMS / GCP / Azure KMS.** In layered mode it's explicitly a *layer*, not a substitute. Most teams should not migrate their CMKs.
- **Not a cryptographic library.** It uses Tink, BouncyCastle, and the JCE underneath. If you want algorithms and primitives, use those directly. Aegis-KMS is the surrounding infrastructure that turns "I can call AES-GCM" into "I can manage 50 keys across 12 services with policy, intelligence, and audit."
- **Not a SIEM or a security analytics platform.** The intelligence layer focuses on what's in the KMS audit log. It surfaces detections; it integrates with your SIEM via webhooks; it doesn't try to replace it.

## Honest competitive positioning

In one paragraph each. The full version with sub-bullets is in [ARCHITECTURE.md §10](ARCHITECTURE.md#10-how-aegis-kms-compares).

**vs AWS / GCP / Azure KMS.** Excellent products if your entire infrastructure lives in one cloud and you have no AI agents. Pick them for the data plane; pick Aegis as the layered control plane on top.

**vs HashiCorp Vault Enterprise.** Vault is a general secrets manager that happens to include KMIP and a transit engine. Aegis is purpose-built for keys, has an Apache-2.0 license that includes KMIP, and ships an agent-native model and intelligence layer Vault does not. If you already run Vault Enterprise and use most of its breadth, stay. If you bought Vault for the KMIP engine specifically, Aegis is a credible OSS replacement.

**vs OpenBao.** Peer license-wise (MPL-2.0 vs Apache-2.0), missing KMIP (it didn't fork from Vault Enterprise), and missing the agent-native and intelligence-layer story.

**vs PyKMIP / Cosmian / EJBCA.** KMIP-only. No REST, no MCP, no agent identity, no intelligence layer. Aegis-KMS strictly supersets them on everything except language ecosystem (pick those if you specifically need Python/Rust/Java rather than Scala).

## When *not* to use Aegis-KMS

- You are 100% on AWS, have no AI agents in production, and don't anticipate either changing. AWS KMS is well-integrated and Aegis adds operational overhead without enough payoff yet.
- You need a general secrets manager (database credentials, dynamic secrets, SSH CA). Use Vault or OpenBao for that and — if the keys story matters — pair them with Aegis.
- You are pre-product, pre-customers, and adding a control plane is premature. Use a cloud KMS directly until the cost of *not* having identity, audit, and intelligence is real.

## The roadmap toward the wedge

The substrate is in the scaffold today: the four wire planes, the IAM model, the audit log, the agent identity model, the pluggable RoT. The differentiator work happens in `aegis-agent-ai`, in roughly this order:

1. **Anomaly detection on key usage.** Sliding-window baseline per key / per actor / per source; `AgentRecommendation` events; CLI surfacing. *(Smallest scope, biggest demo value.)*
2. **Risk-scored access decisions.** Multi-factor scorer, thresholds wired into IAM, recorded reasoning in audit context. Boolean policy stays as the floor.
3. **Auto-response.** Configurable wiring from detections to actions: revoke, deactivate, alert, freeze.
4. **LLM advisor.** Bounded helper that reads the audit log and inventory and answers fixed prompts ("unused keys," "rotation suggestions," "explain riskiness"). Carefully scoped — read-only, never executes mutations directly.
5. **Layered-mode integrations.** First-class registration and proxying for AWS KMS, GCP KMS, Azure Key Vault, Vault Transit. Standalone and HSM-backed already covered by the Root-of-Trust SPI.
6. **MCP polish.** Tool annotations, host-side approval flow, scope explorer, audit replay.

Each of these is independently shippable and demoable. The order is chosen so each one builds on what's already there and produces a concrete artifact someone outside the project can use.

## See also

- [README](../README.md) — overview, three deployment modes, key generation, quickstarts.
- [ARCHITECTURE.md](ARCHITECTURE.md) — module layout, wire planes, key lifecycle, audit model, security model, comparison.
- [USAGE.md](USAGE.md) — end-to-end walkthrough for app developers, operators, AI agents, and KMIP vendors.
