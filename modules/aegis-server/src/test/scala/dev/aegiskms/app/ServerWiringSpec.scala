package dev.aegiskms.app

import cats.effect.unsafe.IORuntime
import dev.aegiskms.core.KeyService
import dev.aegiskms.http.HttpRoutes
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Boot-wiring smoke test: prove that the modules compile together and that the in-memory `KeyService` can be
  * wrapped in `HttpRoutes` without explosion. Network binding is deferred to integration tests so this stays
  * fast and deterministic.
  */
final class ServerWiringSpec extends AnyFunSuite with Matchers:

  test("HttpRoutes assembles around an in-memory KeyService") {
    given IORuntime = IORuntime.global
    val svc         = KeyService.inMemory.unsafeRunSync()
    val routes      = HttpRoutes(svc)
    routes.serverEndpoints.size shouldBe 4
  }
