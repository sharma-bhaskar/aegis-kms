package dev.aegiskms.sdk

/** Entry point for the Scala SDK. Both factories return a working [[AegisHttpClient]] with full coverage of
  * the Aegis REST surface (key lifecycle, crypto ops, agent issuance, audit read, advisor).
  *
  * The client is blocking (JDK `HttpClient` underneath) and returns `Either[ClientError, A]`. Effect-system
  * users can lift calls into their own `F[_]` with a single `blocking(...)` wrapper; we deliberately don't
  * force a cats-effect dependency on every consumer for what is one HTTP round-trip per call.
  */
object AegisClient:

  /** Connect with a bearer JWT — the production path (`AEGIS_AUTH_KIND=hmac` or OIDC). */
  def https(baseUrl: String, token: String): AegisHttpClient =
    new AegisHttpClient(HttpPort.jdk(), baseUrl, principal = None, token = Some(token))

  /** Connect to a dev-mode server (`AEGIS_AUTH_KIND=dev`) identifying as `principal` via the `X-Aegis-User`
    * header. Workstation use only — dev auth performs no verification.
    */
  def dev(baseUrl: String, principal: String): AegisHttpClient =
    new AegisHttpClient(HttpPort.jdk(), baseUrl, principal = Some(principal))
