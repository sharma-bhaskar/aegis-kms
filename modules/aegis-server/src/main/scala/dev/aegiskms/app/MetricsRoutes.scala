package dev.aegiskms.app

import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import org.apache.pekko.http.scaladsl.model.{ContentType, HttpCharsets, HttpEntity, MediaType}
import org.apache.pekko.http.scaladsl.server.Directives.*
import org.apache.pekko.http.scaladsl.server.Route

/** Pekko-HTTP route that serves `GET /metrics` in Prometheus exposition format. Lives in `aegis-server` (not
  * `aegis-http`) to keep the Tapir API module dependency-free of Micrometer; the metrics endpoint is stitched
  * into the application route alongside `HttpRoutes.routes` at boot time.
  *
  * Content-type is `text/plain; version=0.0.4; charset=utf-8`, the format expected by Prometheus's `scrape`
  * config and by Grafana Cloud's hosted Prometheus. The exposition is regenerated on every scrape via
  * `registry.scrape()` — Micrometer collects the values lazily, so a scrape rate of 15s (the typical
  * Prometheus default) imposes negligible overhead.
  */
object MetricsRoutes:

  /** Prometheus's exposition format: text/plain with a version tag. The narrower
    * `ContentType.WithFixedCharset` static type lets the compiler pick the
    * `HttpEntity.apply(ContentType.WithFixedCharset, String)` overload directly without an explicit
    * conversion at the call site.
    */
  private val prometheusContentType: ContentType.WithFixedCharset =
    ContentType(
      MediaType.customWithFixedCharset(
        mainType = "text",
        subType = "plain",
        charset = HttpCharsets.`UTF-8`,
        params = Map("version" -> "0.0.4")
      )
    )

  /** Build the route. `registry.scrape()` returns the rendered exposition in one allocation; for the v0.1.1
    * demo target's "watch metrics in Grafana" workflow that's well within budget — Prometheus polls every
    * ~15s and the body is tens of KB.
    */
  def route(registry: PrometheusMeterRegistry): Route =
    path("metrics") {
      get {
        complete(HttpEntity(prometheusContentType, registry.scrape()))
      }
    }
