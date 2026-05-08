package dev.aegiskms.app

import io.opentelemetry.api.trace.{Tracer, TracerProvider}
import io.opentelemetry.api.{GlobalOpenTelemetry, OpenTelemetry}
import io.opentelemetry.sdk.autoconfigure.AutoConfiguredOpenTelemetrySdk

/** OpenTelemetry SDK bootstrap. Lives in `aegis-server` rather than a library module because OTel is a
  * server-tier dependency only — the library-safe modules (`aegis-core`, `aegis-iam`, `aegis-audit`,
  * `aegis-persistence`, the SDKs) MUST stay dep-light so embedders aren't forced to ship a tracing library
  * they may not want.
  *
  * Configuration is driven entirely by environment variables / system properties; the Java SDK's
  * `AutoConfiguredOpenTelemetrySdk` reads the standard `OTEL_*` set:
  *
  *   - `OTEL_SERVICE_NAME=aegis-server`
  *   - `OTEL_TRACES_EXPORTER=otlp` (or `none`, `console`, `logging-otlp`, `zipkin`, `jaeger`)
  *   - `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318`
  *   - `OTEL_TRACES_SAMPLER=parentbased_always_on` (default)
  *   - `OTEL_RESOURCE_ATTRIBUTES=deployment.environment=prod,service.namespace=kms`
  *
  * When the operator hasn't set `OTEL_TRACES_EXPORTER` we still build the SDK; the autoconfigure default is
  * the OTLP exporter, which silently no-ops without a configured endpoint. To explicitly disable tracing for
  * local development, set `OTEL_TRACES_EXPORTER=none`.
  *
  * **Production note.** Application-level spans (created by `TracingKeyService`) are the slice this module
  * instruments. For full request-graph coverage — pekko-http server spans, JDBC client spans, AWS SDK client
  * spans — attach the OpenTelemetry Java Agent at JVM start:
  *
  * {{{
  * java -javaagent:opentelemetry-javaagent.jar -jar aegis-server.jar
  * }}}
  *
  * The agent and the SDK both read the same `OTEL_*` env vars, so the operator's configuration is unchanged.
  * The agent contributes server / database / AWS spans automatically and our manual spans become children via
  * the standard W3C trace-context propagation.
  */
object TracingRegistry:

  /** Build the autoconfigured `OpenTelemetry` instance. We deliberately do NOT call `setResultAsGlobal`:
    *
    *   - When the OpenTelemetry Java Agent is attached at JVM start, the agent owns `GlobalOpenTelemetry` and
    *     our manual spans become children of the agent's via thread-local `Context.current()`. We thread our
    *     SDK explicitly into [[TracingKeyService]] so we don't fight the agent for the global slot.
    *   - Without the agent, no other code in the process reads the global anyway — `TracingKeyService`
    *     receives the `Tracer` by constructor argument, not via `GlobalOpenTelemetry.getTracer`.
    *   - Tests can build a fresh registry per suite without the global-singleton trap (the autoconfigure SDK
    *     throws if `setResultAsGlobal` is called twice).
    *
    * The returned `OpenTelemetrySdk` is `AutoCloseable`; closing it flushes pending spans + shuts down the
    * exporter. Callers wrap this in a `Resource` so SIGTERM unwinds cleanly.
    */
  def make(): OpenTelemetry =
    AutoConfiguredOpenTelemetrySdk.builder()
      .build()
      .getOpenTelemetrySdk

  /** Convenience accessor for downstream callers that just want a `Tracer` — the most common need. Returns
    * the application's tracer keyed by the `aegis-kms` instrumentation name.
    */
  def tracerFor(otel: OpenTelemetry, instrumentationName: String = "aegis-kms"): Tracer =
    otel.getTracer(instrumentationName)

  /** Last-resort accessor that reads from the global. Useful for tests / pure-utility code paths that don't
    * have a handle on the boot-scope OpenTelemetry. Falls back to a no-op tracer if the SDK hasn't been
    * initialized.
    */
  def globalTracerProvider: TracerProvider = GlobalOpenTelemetry.getTracerProvider
