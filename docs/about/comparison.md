# Comparison

How Aegis-KMS compares to the existing options on the KMS shortlist — including a clear "do
not pick Aegis if…" section, because the new entrant in this space has to earn the row in
your decision matrix, not assume it.

## The 30-second version

| Dimension | AWS KMS | HashiCorp Vault | OpenBao | GCP KMS / Azure Key Vault | Aegis-KMS |
|---|---|---|---|---|---|
| **License** | Proprietary | BSL (Enterprise: commercial) | MPL 2.0 | Proprietary | Apache 2.0 |
| **Maturity** | Production, 10+ yrs | Production, 10+ yrs | Stable, ~2 yrs | Production, mature | Pre-alpha (v0.1.1) |
| **Cloud-portable** | No (AWS only) | Yes | Yes | No | Yes |
| **Self-hostable** | No | Yes | Yes | No | Yes |
| **Per-call cost** | ~$0.03/10K calls | Self-host: free | Self-host: free | ~$0.03/10K calls | Self-host: free |
| **Audit granularity** | Account-level (CloudTrail) | Configurable audit devices | Configurable audit devices | Cloud Audit Logs | Per-call agent-aware |
| **Agent identity in audit** | No | Workload identity (not agent-aware) | Workload identity | No | First-class (`agent_id`, `session_id`, `tool_name`) |
| **Risk-scored decisions** | No | No | No | No | `Allow` / `StepUp` / `Deny` from a [0,1] risk score with structured reasoning (v0.2.0) |
| **Auto-response to anomalies** | CloudTrail → Lambda (DIY) | Audit device → external pipeline (DIY) | Audit device → external pipeline (DIY) | Cloud Audit → Pub/Sub (DIY) | First-class `AutoResponder` with default rules + cooldown (v0.2.0) |
| **KMIP** | No | Enterprise only | Roadmap | No | Designed (v0.2.0) |
| **MCP-native** | No | No | No | No | Designed (v0.2.0) |
| **Policy engine** | AWS IAM | Vault HCL policies | Vault HCL policies | Cloud IAM | Boolean policy (v0.1.x) + risk overlay (v0.2.0); richer policies (v0.3.0) |
| **HSM-backed** | CloudHSM | Enterprise only | Roadmap | Cloud HSM | Via AWS KMS RoT today |
| **OSS contributors** | N/A | 200+ | 100+ | N/A | <5 |
| **Best fit** | AWS-only shops | Multi-cloud secrets + KMS | Vault refugees on OSS | Cloud-native shops | AI/agent-heavy shops |

## What problem is Aegis-KMS actually solving?

Every existing KMS in the table above is built around a model that pre-dates LLM agents in
production: a request arrives carrying a credential, the credential maps to a role, the role
has a policy, the policy says yes or no, the audit log records the role and the operation.
This works fine when the actor on the other side of the credential is a human, a long-lived
service, or a deterministic pipeline.

It breaks when the actor is an agent. Agents are spawned at runtime — one human can launch
dozens per day, each doing something different. They act on behalf of humans, but the chain
isn't recorded. They misbehave in ways static policies can't catch — *"billing-signer can
sign invoices"* doesn't say *"billing-signer should not sign 80 invoices in 20 minutes from a
never-before-seen IP at 3 AM."*

So when an agent goes off the rails, the audit log says: *"role billing-signer made 80 sign
calls."* You can't tell which agent did it. You can't tell whose agent it was. You can't
revoke "the agent" because there is no agent — only the role, and revoking the role takes down
the legitimate workflow for everyone.

This is the gap Aegis-KMS is built around. Every other dimension of the product flows from it.

## AWS KMS vs. Aegis — when each wins

**Pick AWS KMS if:** You're an AWS-only shop and don't expect that to change. AWS KMS is
mature, integrated with every AWS service, audited by CloudTrail at the account level, and at
small scale roughly free. The control plane is operated by Amazon, which is exactly what you
want for a security-critical service if your platform team is small.

**Pick Aegis-KMS if:** Your audit team has asked questions like *"which Claude session signed
this invoice?"* or *"which human's agents triggered this signing burst?"* and CloudTrail
couldn't answer. Or you've left AWS, or expect to. Or your KMS API bill at agent scale is
becoming a line item people are noticing.

## HashiCorp Vault vs. Aegis — when each wins

**Pick Vault if:** You need a secrets manager *and* a KMS in the same product, with mature
dynamic secrets, PKI issuance, database credential rotation, and SSH certificate authority.
Vault is the Swiss Army knife answer. The community is enormous, the ecosystem is well-trodden.

You also still pick Vault if you need MFA-gated unsealing, quorum-based recovery
(Shamir's Secret Sharing), HCL policies you've already invested in, or Vault Enterprise's HSM
and namespace features.

**Pick Aegis-KMS if:** You don't need a Swiss Army knife — you need a KMS specifically, with
first-class agent-aware audit. Vault's audit devices give you per-request structured logs,
but the principal field still resolves to a workload identity, not an agent. Aegis is what
*that something on top* looks like, but as a first-class control plane.

## OpenBao vs. Aegis — the OSS-vs-OSS conversation

OpenBao is the IBM-backed MPL 2.0 fork of Vault that emerged after the BSL relicense. It's
the right answer for teams who want Vault's surface area without Vault's license. Maturity-wise,
OpenBao is roughly where Vault was a few years ago — production-usable, but the contributor
base and third-party integrations are still catching up.

If you're choosing between OpenBao and Aegis:

- **Surface area.** OpenBao is broad and shallow-relative-to-Vault. Aegis is narrow and deep —
  KMS only, but with an architecture that takes agents seriously.
- **Maturity.** OpenBao has more deployments today than Aegis will have in 2027.
- **Roadmap.** OpenBao is converging on Vault's roadmap. Aegis is on a different roadmap
  entirely — agent identity, MCP, anomaly detection, KMIP.

Most teams who land here will pick OpenBao today and watch Aegis. That's the right call.

## When you should *not* pick Aegis-KMS today

This section is the most important one in the post. As of v0.1.1, **don't pick Aegis-KMS
if:**

- You need a production-stable KMS this quarter. Aegis is pre-alpha. AWS KMS or Vault are
  the safe answers.
- You need MFA-gated unsealing, quorum-based recovery, or Shamir-style secret splitting.
  Vault is the answer.
- You need shipped KMIP for a backup vendor, storage system, or database integration *today*.
  Thales, Fortanix, or Vault Enterprise are the answers.
- You need SOC 2 Type 2 attestation today. Aegis doesn't have it (Type 1 in progress).
- You don't run LLM agents in production and don't expect to. The wedge isn't relevant for
  you.
- Your organization can't take a dependency on a project with fewer than five committers.

We mean this section. If any of those apply, the right call is to keep using whatever you're
using.

## When you *should* pick Aegis-KMS

You should consider Aegis-KMS if:

- You run LLM agents in production and your security team has asked *"which Claude session
  signed this?"* and you couldn't answer.
- Your KMS audit log is "useless during incident triage" — too coarse, too account-level,
  too principal-blind.
- You want a KMS you can run on AWS today and Azure or GCP tomorrow without a rewrite.
- You're paying meaningful per-call KMS charges at agent scale and the cost feels
  disproportionate to the value.
- You're willing to be a design partner for v1.0 in exchange for influence over the roadmap.

If two or more apply, a 30-minute conversation will probably tell us both whether the fit is
real.

## How to engage

Open an issue on [GitHub](https://github.com/sharma-bhaskar/aegis-kms/issues) with your
use case. We're looking for three to five design partners through v1.0.

The pitch isn't *"Aegis is better than Vault."* It isn't. The pitch is *"the gap exists, the
gap is widening as agents become production actors, and the existing KMSes weren't built to
close it. Here's what an agent-aware control plane looks like when you build one from scratch
in 2026."* If that gap matches a problem you're carrying, Aegis is on the shortlist. If not,
the existing five products in the table are exactly what you should be using.
