# Observability

`aegis-server` exposes three observability surfaces alongside the application port (`8080` by
default). None require code changes — the first two are wired in by the boot, the third is
opt-in via env vars.

## Prometheus metrics

`GET /metrics` returns the standard Prometheus exposition format. Per-`KeyService` operation:

```
aegis_keys_op_total{operation="Sign"}                                            counter
aegis_keys_op_duration_seconds_bucket{operation="Sign", outcome="success"}       histogram
aegis_keys_op_errors_total{operation="Sign", code="IllegalOperation"}            counter
```

The standard JVM/GC/threads/classloader/processor/uptime collectors are bound on boot, so
`jvm_memory_used_bytes`, `jvm_gc_pause_seconds`, `process_uptime_seconds` and friends are
exposed too. Point your Prometheus scrape config at `http://aegis-server:8080/metrics`.

### Decorator placement

`MeteredKeyService` sits **outside** `AuthorizingKeyService` so denials are countable as
`aegis_keys_op_errors_total{code="PermissionDenied"}` rather than disappearing. `AuditingKeyService`
remains the outermost decorator so the audit row reflects the true outcome including the deny.

## OpenAPI / Swagger UI

The full REST surface is documented at `GET /docs/` (Swagger UI) with the raw spec at
`GET /docs/docs.yaml`. Because the spec is generated from the same Tapir endpoint values the
runtime interprets, drift between the docs and the wire shape is impossible by construction.

If you want the spec offline:

```bash
curl -s http://localhost:8080/docs/docs.yaml > aegis-openapi.yaml
```

## OpenTelemetry tracing

The OTel SDK is auto-configured from the standard environment variables. Point it at any
compatible backend (Jaeger, Tempo, Honeycomb, Datadog, OTel Collector):

```bash
export OTEL_SERVICE_NAME=aegis-server
export OTEL_TRACES_EXPORTER=otlp                    # or `none` to silence
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
export OTEL_TRACES_SAMPLER=parentbased_traceidratio
export OTEL_TRACES_SAMPLER_ARG=0.1
export OTEL_RESOURCE_ATTRIBUTES=deployment.environment=prod,service.namespace=kms
```

Each `KeyService` operation emits a span named `kms.<operation>` with attributes:

| Attribute | Example |
|---|---|
| `aegis.operation` | `Sign`, `Encrypt`, `Rotate`, `Compromise`, … |
| `aegis.key.id` | `kid_8a3f…` (when applicable) |
| `aegis.principal.subject` | `alice@org` or `claude-session-7a3` |
| `aegis.principal.kind` | `human` or `agent` |
| `aegis.outcome` | `success` or `error_<code>` |

Span status is set to `ERROR` with the `KmsError` message on failure.

### Full request-graph coverage

For pekko-http server spans, JDBC client spans, and AWS SDK client spans, attach the
OpenTelemetry Java Agent at JVM start:

```bash
java -javaagent:opentelemetry-javaagent.jar -jar aegis-server.jar
```

The agent and the SDK read the same `OTEL_*` env vars, so the operator's configuration is
unchanged and the manual `kms.<op>` spans become children of the agent's auto-instrumented
spans via W3C trace-context propagation.

## Current observability limitations

Be aware of these limitations in the current observability surface:

- **No built-in Grafana dashboard.** Sample dashboards for the standard metric set will land
  alongside a later polish release.

As of v0.2.0, `AuditRecord.context("source.ip")` is populated by the HTTP layer (#78), and audit
fan-out is no longer stdout-only — Postgres, SIEM webhook, Kafka, and NATS JetStream sinks ship
and compose via `FanOutAuditSink`. See [Operations → Security](security.md) and the audit-sink
HOCON blocks in `application.conf`.
