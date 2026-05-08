package dev.aegiskms.app

import io.micrometer.prometheusmetrics.{PrometheusConfig, PrometheusMeterRegistry}
import org.apache.pekko.http.scaladsl.model.StatusCodes
import org.apache.pekko.http.scaladsl.testkit.ScalatestRouteTest
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Tests the `/metrics` route end-to-end via pekko-http's test-kit. We don't mock the registry — a real
  * `PrometheusMeterRegistry` is cheap to construct and the test reads the rendered exposition like Prometheus
  * would.
  */
final class MetricsRoutesSpec extends AnyFunSuite with Matchers with ScalatestRouteTest:

  test("GET /metrics returns 200 with Prometheus content-type and the version=0.0.4 parameter") {
    val registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT)
    Get("/metrics") ~> MetricsRoutes.route(registry) ~> check {
      status shouldBe StatusCodes.OK
      val ct = response.entity.contentType.toString
      ct should startWith("text/plain")
      ct should include("version=0.0.4")
    }
  }

  test("GET /metrics surfaces a freshly-registered counter in the rendered exposition") {
    val registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT)
    registry.counter("aegis_test_counter", "operation", "Sign").increment(7.0)

    Get("/metrics") ~> MetricsRoutes.route(registry) ~> check {
      status shouldBe StatusCodes.OK
      val body = responseAs[String]
      body should include("aegis_test_counter_total")
      body should include("""operation="Sign"""")
      body should include("7.0")
    }
  }

  test("GET /metrics renders the standard JVM binders bound by MetricsRegistry.make") {
    val registry = MetricsRegistry.make()
    Get("/metrics") ~> MetricsRoutes.route(registry) ~> check {
      status shouldBe StatusCodes.OK
      val body = responseAs[String]
      // representative subset — every binder writes something into the exposition on first scrape
      body should include("jvm_memory_used_bytes")
      body should include("jvm_threads_live_threads")
      body should include("system_cpu_count")
      body should include("process_uptime_seconds")
    }
  }

  test("non-/metrics paths are not handled by this route (lets the rest of the route tree match)") {
    val registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT)
    Get("/v1/keys") ~> MetricsRoutes.route(registry) ~> check {
      handled shouldBe false
    }
  }
