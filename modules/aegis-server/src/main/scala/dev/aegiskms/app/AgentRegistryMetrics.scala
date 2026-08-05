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

    // Refresh once at boot so the first scrape isn't a misleading zero, then on the interval.
    val loop: IO[Unit] = refresh *> (IO.sleep(refreshInterval) *> refresh).foreverM

    Resource.eval(register) *> Resource.make(loop.start)(_.cancel).void
