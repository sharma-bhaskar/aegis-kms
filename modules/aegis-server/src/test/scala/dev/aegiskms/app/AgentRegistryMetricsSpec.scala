package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import dev.aegiskms.agent.{AgentRecord, AgentRegistry}
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.util.concurrent.atomic.AtomicInteger
import scala.concurrent.duration.*

/** Tests for the `aegis_agents_active` gauge.
  *
  * The behaviour that matters is the failure mode: a gauge that reports 0 during a database blip reads as "no
  * agents are active", which mid-incident is the most dangerous lie the metric could tell. It must hold the
  * previous value instead.
  */
final class AgentRegistryMetricsSpec extends AnyFunSuite with Matchers:

  /** A registry whose active count is scripted per *execution*.
    *
    * The counters live inside `IO.defer` on purpose. `AgentRegistryMetrics.refresh` is a `val`, so it
    * evaluates `registry.activeCount` once to obtain the effect and then re-runs that same value on every
    * tick — which is exactly how a real `AgentRegistry` behaves, since its `activeCount` builds the query
    * inside `IO`. A double that incremented in the method body instead would report one invocation forever
    * and make the loop look broken when it is not.
    */
  final private class ScriptedRegistry(counts: IO[Int]*) extends AgentRegistry[IO]:
    private val calls                                             = new AtomicInteger(0)
    val invocations                                               = new AtomicInteger(0)
    def list(filter: AgentRegistry.Filter): IO[List[AgentRecord]] = IO.pure(Nil)
    def activeCount: IO[Int] = IO.defer {
      invocations.incrementAndGet()
      val i = calls.getAndIncrement()
      counts(math.min(i, counts.length - 1))
    }

  private def gaugeValue(reg: SimpleMeterRegistry): Option[Double] =
    Option(reg.find("aegis_agents_active").gauge()).map(_.value())

  test("the gauge is registered and populated on boot, before any scrape") {
    val meters   = new SimpleMeterRegistry()
    val registry = new ScriptedRegistry(IO.pure(7))

    AgentRegistryMetrics.resource(registry, meters, 1.hour).use { _ =>
      IO(gaugeValue(meters) shouldBe Some(7.0))
    }.unsafeRunSync()
  }

  test("an empty registry publishes zero rather than leaving the gauge absent") {
    val meters = new SimpleMeterRegistry()

    AgentRegistryMetrics.resource(new ScriptedRegistry(IO.pure(0)), meters, 1.hour).use { _ =>
      IO(gaugeValue(meters) shouldBe Some(0.0))
    }.unsafeRunSync()
  }

  test("a refresh failure keeps the previous value instead of reporting zero active agents") {
    val meters = new SimpleMeterRegistry()
    // First refresh succeeds with 5; every subsequent one fails.
    val registry = new ScriptedRegistry(
      IO.pure(5),
      IO.raiseError(new RuntimeException("audit store unreachable"))
    )

    AgentRegistryMetrics.resource(registry, meters, 50.millis).use { _ =>
      IO.sleep(250.millis) *> IO {
        registry.invocations.get() should be > 1
        // The failing refreshes must not have zeroed it.
        gaugeValue(meters) shouldBe Some(5.0)
      }
    }.unsafeRunSync()
  }

  test("a failing first refresh leaves the gauge at zero without crashing the boot") {
    val meters   = new SimpleMeterRegistry()
    val registry = new ScriptedRegistry(IO.raiseError(new RuntimeException("down")))

    noException should be thrownBy
      AgentRegistryMetrics.resource(registry, meters, 1.hour).use { _ =>
        IO(gaugeValue(meters) shouldBe Some(0.0))
      }.unsafeRunSync()
  }

  test("the gauge tracks the registry as the count changes") {
    val meters   = new SimpleMeterRegistry()
    val registry = new ScriptedRegistry(IO.pure(2), IO.pure(9))

    AgentRegistryMetrics.resource(registry, meters, 50.millis).use { _ =>
      IO.sleep(200.millis) *> IO(gaugeValue(meters) shouldBe Some(9.0))
    }.unsafeRunSync()
  }

  test("the refresh fiber stops when the resource is released") {
    val meters   = new SimpleMeterRegistry()
    val registry = new ScriptedRegistry(IO.pure(1))

    AgentRegistryMetrics.resource(registry, meters, 30.millis)
      .use(_ => IO.sleep(150.millis))
      .unsafeRunSync()

    val afterRelease = registry.invocations.get()
    Thread.sleep(200)
    // No further polling once the Resource finalizer has cancelled the fiber.
    registry.invocations.get() shouldBe afterRelease
  }
