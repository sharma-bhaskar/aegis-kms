package dev.aegiskms.app

import io.micrometer.core.instrument.binder.jvm.{
  ClassLoaderMetrics,
  JvmGcMetrics,
  JvmMemoryMetrics,
  JvmThreadMetrics
}
import io.micrometer.core.instrument.binder.system.{ProcessorMetrics, UptimeMetrics}
import io.micrometer.prometheusmetrics.{PrometheusConfig, PrometheusMeterRegistry}

/** Builds a Prometheus-backed Micrometer registry and binds the standard JVM/GC/processor/uptime metrics
  * once. Lives in `aegis-server` rather than a library module because Micrometer is a server-tier dependency
  * only — the library-safe modules (`aegis-core`, `aegis-audit`, `aegis-iam`, `aegis-persistence`, the SDKs)
  * must remain dep-light so embedders aren't forced to ship a metrics library they may not want.
  *
  * The standard binders attached here cover the v0.1.1 demo target's "JVM/GC standard set" requirement from
  * issue #10:
  *   - heap & non-heap memory pools, buffer pools (`JvmMemoryMetrics`)
  *   - GC pause durations, allocation/promotion rates (`JvmGcMetrics`)
  *   - thread states + counts (`JvmThreadMetrics`)
  *   - loaded class count (`ClassLoaderMetrics`)
  *   - CPU usage + system load (`ProcessorMetrics`)
  *   - process uptime (`UptimeMetrics`)
  *
  * Application-specific instrumentation lives in [[MeteredKeyService]]; the registry produced here is the
  * single sink both the JVM binders and the application code emit into.
  */
object MetricsRegistry:

  /** Build a fresh registry, attach the standard JVM binders, return it. The caller is responsible for
    * closing the binders' resources at shutdown — for now, the JVM exit handles cleanup since `aegis-server`
    * is a long-running daemon (the proper `Resource[IO, Unit]` boot scope is on the F1.b follow-up list).
    */
  def make(): PrometheusMeterRegistry =
    val registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT)
    bindStandardJvmMetrics(registry)
    registry

  private def bindStandardJvmMetrics(registry: PrometheusMeterRegistry): Unit =
    new JvmMemoryMetrics().bindTo(registry)
    // JvmGcMetrics is itself an AutoCloseable — installs JMX listeners; we leak the reference because the
    // process lifetime is the server lifetime.
    new JvmGcMetrics().bindTo(registry)
    new JvmThreadMetrics().bindTo(registry)
    new ClassLoaderMetrics().bindTo(registry)
    new ProcessorMetrics().bindTo(registry)
    new UptimeMetrics().bindTo(registry)
