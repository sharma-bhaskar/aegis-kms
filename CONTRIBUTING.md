# Contributing to Aegis-KMS

Thanks for considering a contribution. Aegis-KMS is an Apache-2.0 project and
welcomes patches from anyone.

## Ground rules

1. By submitting a PR you agree to license your contribution under Apache-2.0.
2. Every commit must be signed off (`git commit -s`) — we use the
   [Developer Certificate of Origin](https://developercertificate.org/).
3. No vendor-specific code in `aegis-core`. Vendor integrations live in
   `aegis-crypto`, `aegis-persistence`, or `aegis-audit`, behind an SPI.
4. `aegis-core`, `aegis-crypto`, `aegis-iam`, `aegis-audit`,
   `aegis-persistence`, and the SDK modules MUST NOT depend on Pekko.

## Getting started

```bash
git clone https://github.com/aegis-kms/aegis-kms.git
cd aegis-kms
sbt test                 # run unit tests
sbt scalafmtCheckAll     # formatting gate
sbt scalafixAll --check  # lint gate
```

## Good first issues

The best places to start without needing deep context:

- Add a new `RootOfTrust` backend (GCP KMS, HashiCorp Vault, YubiHSM).
- Add a new `PersistenceStore` driver (CockroachDB, SQLite).
- Add a new `AuditSink` (Kafka, S3, OpenTelemetry logs).
- Add a new `LlmClient` backend (Ollama, Anthropic, OpenAI).
- Expand KMIP test vector coverage under `modules/aegis-kmip/src/test`.
- Improve docs in `docs/`.

## PR checklist

- [ ] Linked to a tracking issue
- [ ] Unit tests added or updated
- [ ] `sbt test` passes locally
- [ ] `sbt scalafmtCheckAll scalafixAll --check` passes
- [ ] CHANGELOG updated under `## Unreleased`
- [ ] MiMa check green (`sbt mimaReportBinaryIssues`) — or the breaking change
      is documented and justified

## Code style

- Scala 3, `-Xfatal-warnings`, `-Wunused:all`.
- `scalafmt` on every file; `scalafix` for lint rules.
- Prefer immutable data, `Option`/`Either` over nulls, ADTs over flags.
- Actor behaviors are **always** typed (`Behavior[T]` with a sealed command
  ADT).

## Reporting security issues

Please do not open a public issue for a security report. See
[SECURITY.md](SECURITY.md).
