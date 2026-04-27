package dev.aegiskms.agent

import cats.effect.{IO, Ref}

/** Sink for `AgentRecommendation` events.
  *
  * A streaming detector emits one record per detected deviation; whatever consumes the stream — the CLI
  * tail, the operator UI, the auto-responder (PR W3), webhooks (PR W3.b) — implements this trait.
  *
  * For tests and the dev-mode server we ship `InMemoryRecommendationSink`, which retains every record so an
  * assertion can ask "did W1 emit a high-severity ScopeBaseline event for actor X?".
  */
trait RecommendationSink:
  def publish(rec: AgentRecommendation): IO[Unit]

final class InMemoryRecommendationSink private (ref: Ref[IO, Vector[AgentRecommendation]])
    extends RecommendationSink:
  def publish(rec: AgentRecommendation): IO[Unit] = ref.update(_ :+ rec)
  def all: IO[List[AgentRecommendation]]          = ref.get.map(_.toList)
  def clear: IO[Unit]                             = ref.set(Vector.empty)

object InMemoryRecommendationSink:
  def make: IO[InMemoryRecommendationSink] =
    Ref.of[IO, Vector[AgentRecommendation]](Vector.empty).map(new InMemoryRecommendationSink(_))
