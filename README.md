<div align="center">

# Aegis-KMS

**An agent-aware open-source key management service.**

*Identity, audit, and real-time control for an era when LLM agents call your sign / encrypt APIs.*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange.svg)](https://sharma-bhaskar.github.io/aegis-kms/about/status/)
[![Release](https://img.shields.io/github/v/release/sharma-bhaskar/aegis-kms?include_prereleases&label=release)](https://github.com/sharma-bhaskar/aegis-kms/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/sharma-bhaskar/aegis-kms/ci.yml?branch=main&label=CI)](https://github.com/sharma-bhaskar/aegis-kms/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-aegiskms.dev-black)](https://sharma-bhaskar.github.io/aegis-kms/)

[Documentation](https://sharma-bhaskar.github.io/aegis-kms/) ·
[Quickstart](https://sharma-bhaskar.github.io/aegis-kms/getting-started/quickstart/) ·
[Architecture](https://sharma-bhaskar.github.io/aegis-kms/concepts/architecture/) ·
[CHANGELOG](CHANGELOG.md) ·
[Roadmap](ROADMAP.md)

</div>

---

> **v0.1.1 — pre-alpha.** The crypto surface is real and end-to-end (sign / verify / encrypt /
> decrypt / wrap / unwrap / rotate / compromise) on REST + CLI, with JWT auth, Postgres event
> journal, Prometheus metrics, OpenTelemetry tracing, OpenAPI on `/docs/`, and a 5-detector
> anomaly engine wired into the audit pipeline. Production-stable backends, KMIP, MCP-native,
> and the auto-response loop land in v0.2.0+. See [the status table](https://sharma-bhaskar.github.io/aegis-kms/about/status/)
> for the per-capability split.

## Why Aegis exists

AI agents — Claude, GPT, custom agents, RAG workloads — now sign payloads, decrypt secrets, and
call tools that hold real credentials. None of the existing key managers were built for this:
when something goes wrong, the audit log says *"role `billing-signer` made 80 sign calls"* and
can't tell you *which agent did it, on whose behalf, or whether the burst is anomalous*.

Aegis is the agent-native control plane that sits in front of an existing KMS (AWS KMS today;
GCP / Azure / Vault adapters in v0.2.0) and adds the four things role-centric KMSes don't:

1. **Per-agent identity** — every request resolves to a `Principal.Agent` with a back-pointer
   to the human who issued it, an explicit scope, and a TTL.
2. **Behavioural baselines** — five detectors flag scope violations, rate spikes, off-hours
   access, new source IPs, and operations the actor has never performed.
3. **Structured audit** — every decision, score, and detection lands in an immutable journal
   with full agent + parent attribution.
4. **Real-time response** *(v0.2.0)* — configurable wiring from detection to action: allow /
   step-up / deny / rotate / revoke / alert, applied before the next request lands.

For the long-form argument see the [comparison post](https://sharma-bhaskar.github.io/aegis-kms/about/comparison/)
or [docs/concepts/architecture](https://sharma-bhaskar.github.io/aegis-kms/concepts/architecture/).

## Quickstart — Docker Compose

Brings up `aegis-server` against a local Postgres in two commands. Requires Docker.

```bash
git clone https://github.com/sharma-bhaskar/aegis-kms.git
cd aegis-kms
export POSTGRES_PASSWORD="$(openssl rand -base64 24)"
docker compose -f deploy/docker/docker-compose.yml up
```

In another shell:

```bash
# Create a key (dev auth via X-Aegis-User header)
curl -X POST http://localhost:8080/v1/keys \
  -H 'Content-Type: application/json' -H 'X-Aegis-User: alice' \
  -d '{"spec":{"name":"invoice-signing","algorithm":"AES","sizeBits":256,"objectType":"SymmetricKey"}}'

# OpenAPI / Swagger UI for the full surface
open http://localhost:8080/docs/
```

For JWT auth, embedding-as-a-library, the CLI, observability wiring, and a full walkthrough
across REST / KMIP / MCP / agent-token — see the [docs site](https://sharma-bhaskar.github.io/aegis-kms/).

## Documentation

The rendered docs site has the full surface. Quick links:

- **[Getting started](https://sharma-bhaskar.github.io/aegis-kms/getting-started/quickstart/)** — Docker, library, CLI quickstarts
- **[Architecture](https://sharma-bhaskar.github.io/aegis-kms/concepts/architecture/)** — two-tier module split, request lifecycle, state machine, audit model
- **[Operating Aegis](https://sharma-bhaskar.github.io/aegis-kms/operations/usage/)** — auth, deployment, observability, security
- **[REST API reference](https://sharma-bhaskar.github.io/aegis-kms/reference/rest-api/)** — generated from the live OpenAPI spec
- **[Developer Guide](https://sharma-bhaskar.github.io/aegis-kms/development/developer-guide/)** — build, test, debug, contribute
- **[Roadmap](ROADMAP.md)** — per-release delivery plan
- **[Changelog](CHANGELOG.md)** — what shipped when

## Modules

Aegis is a Scala 3 / sbt multi-project. The build enforces a two-tier split: **library tier**
modules have zero Pekko on the classpath and are embeddable in any JVM app; **server tier**
modules add the actor system, HTTP, and process boot.

| Module | Tier | Status |
|---|---|---|
| `aegis-core` | Library | `KeyService[F[_]]` algebra, ADTs, no I/O |
| `aegis-iam` | Library | Principal + JWT verification + authorization decorator |
| `aegis-audit` | Library | `AuditSink` SPI + auditing decorator |
| `aegis-crypto` | Library | `RootOfTrust` SPI + AWS KMS adapter |
| `aegis-persistence` | Library | Doobie event journal (Postgres / MySQL / SQLite / in-memory) |
| `aegis-sdk-scala` / `aegis-sdk-java` | Library | Client SDKs |
| `aegis-http` | Server | Tapir REST + OpenAPI 3.1 |
| `aegis-agent-ai` | Server | 5-detector baseline anomaly engine |
| `aegis-server` | Server | Boot wiring, Prometheus, OTel, Pekko actor |
| `aegis-cli` | Server | `aegis` admin CLI |
| `aegis-kmip`, `aegis-mcp-server` | Server | Skeletons — v0.4.0 |

Module-level docs: [docs/reference/modules](https://sharma-bhaskar.github.io/aegis-kms/reference/modules/).

## Status

- **v0.1.1**: full crypto surface, observability, anomaly detector — see [CHANGELOG](CHANGELOG.md).
- **v0.2.0** *(WIP)*: KMIP wire plane, MCP-native server, agent-aware audit fields populated
  end-to-end, GCP/Azure/Vault adapters, auto-response loop.
- **v0.3.0+**: policy engine, SIEM/Kafka/Postgres audit fan-out, Helm chart, auto-rotation
  scheduler.

The full per-release breakdown lives in [ROADMAP.md](ROADMAP.md).

## Contributing

Aegis welcomes contributions under Apache-2.0. Every commit must be DCO-signed
(`git commit -s`); the library tier must remain Pekko-free; CHANGELOG updates land in the same
PR as the change.

- **[CONTRIBUTING.md](CONTRIBUTING.md)** — ground rules, PR checklist, code style
- **[Developer Guide](https://sharma-bhaskar.github.io/aegis-kms/development/developer-guide/)** — full local-dev workflow

Good first issues are labeled on the [issue tracker](https://github.com/sharma-bhaskar/aegis-kms/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22).

## Security

Please do **not** open a public issue for a security report. See [SECURITY.md](SECURITY.md)
for the disclosure process and the deploy-time configuration matrix.

## License

Apache-2.0 — see [LICENSE](LICENSE).
