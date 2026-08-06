package dev.aegiskms.app

import cats.effect.{IO, Resource}
import cats.syntax.all.*
import dev.aegiskms.agent.AgentRegistry
import io.micrometer.core.instrument.MeterRegistry
import org.slf4j.LoggerFactory

import java.util.concurrent.atomic.AtomicInteger
import scala.concurrent.duration.{FiniteDuration, SECONDS}

/** Publishes `aegis_agents_active` — how many agent credentials are valid right now (#101).
  *
  * The number matters operationally: a slow climb means agents are being minted faster than they expire, and
  * a spike is the shape an agent-token-minting incident makes.
  *
  * **Why a cached value rather than a live gauge.** Micrometer polls gauges synchronously on every `/metrics`
  * scrape. `AgentRegistry.activeCount` runs an audit-table query, so wiring it directly would put a database
  * round-trip on the scrape path — a Prometheus scrape every 15 s across several replicas, each able to block
  * or fail independently, and a slow query would stall metrics collection for everything else in the process.
  * Instead a background fiber refreshes an `AtomicInteger` on a fixed interval and the gauge reads that. The
  * cost is staleness bounded by the refresh interval, which for a count that moves on human timescales is not
  * a real loss.
  *
  * A failed refresh logs and leaves the previous value in place: reporting a stale count is better than
  * reporting zero active agents during a transient database blip, which would read as "the incident is over".
  */
object AgentRegistryMetrics:

  private val logger = LoggerFactory.getLogger(getClass)

  /** How often to recompute the active-agent count. */
  val RefreshInterval: FiniteDuration = FiniteDuration(30L, SECONDS)

  /** Register the gauge and start the refresh fiber. The fiber is cancelled when the returned `Resource` is
    * released, so it never outlives the server.
    */
  def resource(
      registry: AgentRegistry[IO],
      meters: MeterRegistry,
      refreshInterval: FiniteDuration = RefreshInterval
  ): Resource[IO, Unit] =
    val cached = new AtomicInteger(0)

    val register: IO[Unit] = IO {
      meters.gauge[AtomicInteger](
        "aegis_agents_active",
        cached,
        (c: AtomicInteger) => c.get().toDouble
      )
      ()
    }

    val refresh: IO[Unit] =
      registry.activeCount
        .flatMap(n => IO(cached.set(n)))
        .handleErrorWith { t =>
          IO(logger.warn(
            s"agent-registry gauge refresh failed, keeping previous value ${cached.get()}: ${t.getMessage}"
          ))
        }

    // Only the *periodic* part runs in the background; the priming refresh below is not in here.
    val loop: IO[Unit] = (IO.sleep(refreshInterval) *> refresh).foreverM

    // Order matters, and it is load-bearing:
    //
    //   1. register  — create the gauge.
    //   2. refresh   — prime it, as part of acquisition, so the Resource is not "ready" until the
    //                  first real value is in place.
    //   3. loop.start — only then begin polling in the background.
    //
    // Step 2 was originally the head of `loop`, which meant acquisition merely *started* a fiber that
    // would refresh at some point. A Prometheus scrape landing between boot and that fiber's first tick
    // read 0 — indistinguishable from "no agents are active", which is the exact misleading answer this
    // class exists to avoid. It also made the tests racy: they passed on JDK 17 and failed on JDK 21
    // purely on scheduling.
    Resource.eval(register) *> Resource.eval(refresh) *> Resource.make(loop.start)(_.cancel).void
