package dev.aegiskms.iam

import cats.effect.{IO, Ref}

import java.net.URI
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.security.PublicKey
import java.time.{Duration as JDuration, Instant}
import scala.concurrent.duration.FiniteDuration

/** SPI for fetching the set of public verification keys an OIDC provider advertises at its `jwks_uri`
  * endpoint.
  *
  * The OIDC verifier consults a `JwksProvider` for every token it verifies — but in practice the provider
  * caches with a TTL so most lookups hit memory, not the network. Rotating an OIDC provider's signing keys
  * becomes "publish the new `kid` to JWKS, wait one cache TTL, retire the old key" — there's no Aegis-side
  * restart required.
  *
  * Implementations:
  *   - `JwksProvider.http(uri, ttl)` — production path; fetches JSON from a remote URI and parses into a
  *     `JwkSet`. Caches with `ttl`; refreshes lazily when the cached value is expired or when a `kid` lookup
  *     misses.
  *   - `JwksProvider.static(set)` — test seam; takes a pre-built set, never refreshes.
  *
  * The trait deliberately returns the whole `JwkSet` rather than `def keyFor(kid)`, because the
  * `kid`-not-found path needs special handling — on a miss we want the verifier to force a refresh (the
  * provider may have rotated since our last fetch) before giving up.
  */
trait JwksProvider:

  /** Return the currently-cached `JwkSet`. May trigger a fetch if the cache is empty or expired. */
  def get: IO[JwkSet]

  /** Force a fetch, bypassing the cache. Called by the verifier when a token's `kid` doesn't match any key in
    * the cached set — handles the "provider just rotated" race without operator action.
    */
  def refresh: IO[JwkSet]

object JwksProvider:

  /** Build an HTTP-backed provider. Uses `java.net.http.HttpClient` so the library tier doesn't pick up Pekko
    * / sttp / http4s as a transitive dependency — keeping `aegis-iam` embeddable in any JVM app.
    */
  def http(jwksUri: URI, ttl: FiniteDuration): IO[JwksProvider] =
    Ref
      .of[IO, Option[(JwkSet, Instant)]](None)
      .map(cache => new HttpJwksProvider(jwksUri, ttl, cache, HttpClient.newHttpClient()))

  /** Build a static provider for tests. Never refreshes. */
  def static(set: JwkSet): JwksProvider = new StaticJwksProvider(set)

  // ── Impl ──────────────────────────────────────────────────────────────────

  final private class HttpJwksProvider(
      jwksUri: URI,
      ttl: FiniteDuration,
      cache: Ref[IO, Option[(JwkSet, Instant)]],
      client: HttpClient
  ) extends JwksProvider:

    def get: IO[JwkSet] =
      for
        now    <- IO.realTimeInstant
        cached <- cache.get
        result <- cached match
          case Some((set, fetchedAt)) if !isExpired(fetchedAt, now) => IO.pure(set)
          case _                                                    => refresh
      yield result

    def refresh: IO[JwkSet] =
      for
        body <- IO.blocking {
          val req = HttpRequest.newBuilder(jwksUri)
            .timeout(JDuration.ofSeconds(10))
            .header("Accept", "application/json")
            .GET()
            .build()
          val resp = client.send(req, HttpResponse.BodyHandlers.ofString())
          if resp.statusCode() / 100 != 2 then
            throw new RuntimeException(
              s"JWKS fetch failed: ${resp.statusCode()} from $jwksUri"
            )
          resp.body()
        }
        set <- IO.fromEither(JwkSet.parse(body).left.map(msg =>
          new RuntimeException(s"JWKS parse failed for $jwksUri: $msg")
        ))
        now <- IO.realTimeInstant
        _   <- cache.set(Some((set, now)))
      yield set

    private def isExpired(fetchedAt: Instant, now: Instant): Boolean =
      JDuration.between(fetchedAt, now).toMillis >= ttl.toMillis

  final private class StaticJwksProvider(set: JwkSet) extends JwksProvider:
    def get: IO[JwkSet]     = IO.pure(set)
    def refresh: IO[JwkSet] = IO.pure(set)

/** Parsed JWKS — a collection of public keys keyed by `kid`.
  *
  * Holding the parsed `java.security.PublicKey` values rather than the raw JWK JSON lets the verifier hand
  * each one straight to jjwt's `Jwts.parser().verifyWith(key)` without re-parsing per request.
  */
final case class JwkSet(keys: Map[String, PublicKey]):
  /** Look up a key by its `kid` header claim. Returns `None` if the kid isn't known — the verifier uses this
    * signal to decide whether to force a JWKS refresh before failing.
    */
  def get(kid: String): Option[PublicKey] = keys.get(kid)

  /** Number of keys advertised. Useful for log messages on refresh. */
  def size: Int = keys.size

object JwkSet:

  /** Parse a JWKS JSON document (`{"keys": [...]}`) into a `JwkSet`. Keys that fail to parse are dropped with
    * no error — a single corrupt JWK shouldn't disable the rest of the set. The verifier already handles "kid
    * not found" cleanly, so a dropped key just looks like a not-yet-rotated cache.
    *
    * Uses jjwt's `Jwks.parser()` for the per-key parsing so we get RSA / EC support for free.
    */
  def parse(json: String): Either[String, JwkSet] =
    try
      val root = io.circe.parser.parse(json).left.map(_.message) match
        case Right(j)  => j
        case Left(msg) => return Left(s"invalid JSON: $msg")

      val keysArray = root.hcursor.downField("keys").as[List[io.circe.Json]] match
        case Right(arr) => arr
        case Left(_)    => return Left("missing or non-array 'keys' field")

      val parser = io.jsonwebtoken.security.Jwks.parser().build()
      val parsed: Map[String, PublicKey] = keysArray.flatMap { keyJson =>
        val keyJsonStr = keyJson.noSpaces
        try
          val jwk = parser.parse(keyJsonStr)
          val kid = Option(jwk.getId).getOrElse("")
          jwk.toKey match
            case pk: PublicKey if kid.nonEmpty => Some(kid -> pk)
            case _                             => None
        catch case _: Throwable => None
      }.toMap

      if parsed.isEmpty then Left("JWKS contained no parseable public keys with `kid`")
      else Right(JwkSet(parsed))
    catch case e: Throwable => Left(s"JWKS parse error: ${e.getMessage}")
