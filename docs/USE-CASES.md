# Use-Case Guide

A goal-oriented cookbook. Where the [Quickstart](getting-started/quickstart.md) is the fastest
path to a running server and [USAGE.md](USAGE.md) is the linear crypto walkthrough (sign / verify
/ encrypt / … in order), **this guide is organized by what you're trying to do** — run the
rogue-agent demo, wire production auth, fan out audit to a SIEM, embed Aegis as a library, and so
on. Each use case is self-contained and starts from a clean checkout.

> **Version:** written for **v0.2.0**. Every knob below is set by an environment variable; the
> canonical defaults live in `modules/aegis-server/src/main/resources/application.conf`.

---

## Step 0 — Prerequisites & conventions

| Tool | Needed for | Notes |
|---|---|---|
| Docker + Docker Compose | every server use case | `aegis-server` + backing stores run as containers |
| `curl`, `jq` | the REST examples | `jq` is optional but assumed in the output snippets |
| `openssl` | minting secrets | `openssl rand -base64 48` for HMAC/webhook secrets |
| JDK 21 + `sbt` | the **library** use case (UC-3) and minting bootstrap JWTs | only if you embed Aegis or run in `hmac` mode locally |

Get the code and set shell conventions used throughout:

```bash
git clone https://github.com/sharma-bhaskar/aegis-kms.git
cd aegis-kms
export AEGIS=http://localhost:8080
export COMPOSE="docker compose -f deploy/docker/docker-compose.yml"
export POSTGRES_PASSWORD="$(openssl rand -base64 24)"   # compose requires this; no insecure default
```

**The config model in one line:** the server reads HOCON with env-var overrides. Pass them as
`-e VAR=value` to the container, or add them under the `aegis-server.environment:` block in the
compose file. The knobs you'll meet here:

| Concern | Env var | Values |
|---|---|---|
| Auth mode | `AEGIS_AUTH_KIND` | `dev` · `hmac` · `oidc` |
| Journal | `AEGIS_JOURNAL_KIND` | `in-memory` · `postgres` · `mysql` · `sqlite` |
| Root of trust | `AEGIS_CRYPTO_KIND` | `in-memory` · `aws-kms` |
| Audit sink | `AEGIS_AUDIT_KIND` | `stdout` · `postgres` |
| JWT revocation | `AEGIS_REVOCATION_KIND` | `none` · `in-memory` · `redis` |
| Policy | `AEGIS_POLICY_KIND` | `dev` · `role-based` |
| Honey keys | `AEGIS_HONEY_KEYS` | comma-separated KeyIds |

A full cheat-sheet is at the [bottom of this page](#reference-environment-variable-cheat-sheet).

---

## UC-1 — The flagship: catch a rogue agent and auto-revoke it

This is the demo Aegis exists for: an agent acting under a human's authority touches a **honey
key**, and Aegis revokes both the key and the agent's token *before its next call lands*.

> **Why `hmac` mode:** issued agent tokens are HS256 JWTs signed with `AEGIS_AUTH_HMAC_SECRET`,
> and the server verifies them with the same secret. In `dev` mode the server reads
> `X-Aegis-User` and ignores Bearer tokens, so an agent token can't actually authenticate — the
> demo needs `hmac`. We also use the **Postgres** journal so the honey key survives the restart
> in Step 3.

### Step 1 — Boot in hmac mode with a durable journal

```bash
export AEGIS_AUTH_HMAC_SECRET="$(openssl rand -base64 48)"   # ≥32 bytes
AEGIS_AUTH_KIND=hmac AEGIS_JOURNAL_KIND=postgres AEGIS_REVOCATION_KIND=in-memory \
  $COMPOSE up -d
```

### Step 2 — Mint a bootstrap human token

In `hmac` mode even creating a key needs a `Bearer` JWT. Aegis exposes the issuer the server uses
(`dev.aegiskms.iam.JwtIssuer`) so you can mint one out-of-band. From the repo root:

```bash
sbt 'iam/console'
```
```scala
// In the sbt console — adjust the JwtClaims constructor to your version if needed.
import dev.aegiskms.iam.*
import java.time.*, java.util.UUID
val secret = sys.env("AEGIS_AUTH_HMAC_SECRET")
val now    = Instant.now()
val claims = JwtClaims.Human(            // a human principal
  jti       = UUID.randomUUID().toString,
  subject   = "alice@org",
  issuedAt  = now,
  expiresAt = now.plusSeconds(3600),
  issuer    = Some("aegis-demo"),
  groups    = Set("kms-admins")
)
println(JwtIssuer.hmac(secret).issue(claims))   // copy this JWT
```

```bash
export ALICE_JWT="<paste the JWT>"
export H_ALICE="Authorization: Bearer $ALICE_JWT"
```

### Step 3 — Create a key, then promote it to a honey key

```bash
KEY_ID=$(curl -s -X POST "$AEGIS/v1/keys" -H "$H_ALICE" -H 'Content-Type: application/json' \
  -d '{"spec":{"name":"prod-signing-canary","algorithm":"AES","sizeBits":256,"objectType":"SymmetricKey"}}' \
  | jq -r '.id')
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/activate" -H "$H_ALICE" | jq -r '.state'   # → Active
echo "honey key = $KEY_ID"

# Honey keys are read at boot — recreate the server with this KeyId registered.
AEGIS_AUTH_KIND=hmac AEGIS_JOURNAL_KIND=postgres AEGIS_REVOCATION_KIND=in-memory \
  AEGIS_HONEY_KEYS="$KEY_ID" $COMPOSE up -d
```

### Step 4 — Issue an agent token under alice

```bash
AGENT_JWT=$(curl -s -X POST "$AEGIS/v1/agents/issue" -H "$H_ALICE" -H 'Content-Type: application/json' \
  -d '{"label":"invoice-bot","scopes":["Sign","Get"],"ttlSeconds":3600}' | jq -r '.jwt')
export H_AGENT="Authorization: Bearer $AGENT_JWT"
```

### Step 5 — The agent touches the honey key → auto-revoke

```bash
# First touch trips the HoneyKey detector (Severity.High → Revoke).
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/sign" -H "$H_AGENT" -H 'Content-Type: application/json' \
  -d '{"messageBase64":"aGVsbG8=","algorithm":"RsaPssSha256"}' | jq

# The NEXT call from the same agent is rejected — its JTI is now on the revocation list.
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$AEGIS/v1/keys/$KEY_ID/sign" \
  -H "$H_AGENT" -H 'Content-Type: application/json' \
  -d '{"messageBase64":"aGVsbG8=","algorithm":"RsaPssSha256"}'   # → 401
```

### Step 6 — Read the story out of the audit log

```bash
curl -s "$AEGIS/v1/audit?key=$KEY_ID" -H "$H_ALICE" | jq '.events[] | {occurredAt, actor, operation, "risk": .context."risk.score", outcome: .context."outcome.decision"}'
```

You'll see the agent's sign attempt, the `HoneyKey` detection at `Severity.High`, and the
`Revoke` outcome — all attributed to `invoice-bot` *issued by* `alice@org`. That parent linkage is
the thing a role-centric KMS can't give you.

> **Variations:** swap the honey key for a **rate-spike** (loop the sign call ~50× to exceed the
> baseline) or a **scope violation** (issue the agent with `scopes:["Get"]`, then try to `Sign`).
> Honey keys are the most deterministic because the first touch is the trip wire by design.

---

## UC-2 — Exercise the full crypto surface

Create → activate → sign / verify → encrypt / decrypt (with AAD) → wrap / unwrap → rotate →
compromise, on REST + CLI. This is covered step-by-step (with expected output for each call) in
the linear walkthrough — follow **[USAGE.md, Steps 6–13](USAGE.md)**. Use `dev` auth
(`AEGIS_AUTH_KIND=dev`, default) for the fastest path; pass `-H 'X-Aegis-User: alice'` on each
request.

---

## UC-3 — Embed Aegis as a library in your JVM app

The library tier (`aegis-core`, `aegis-iam`, `aegis-audit`, `aegis-crypto`, `aegis-persistence`)
has **zero Pekko** on the classpath and exposes the pure `KeyService[F[_]]` algebra. You can run a
KMS in-process without the HTTP server.

```scala
libraryDependencies += "dev.aegiskms" %% "aegis-core" % "0.2.0"
```

> ⚠️ **Maven Central note:** the library jars are **not published yet** (see
> [Maven Central status](#maven-central-the-release-checklist)). Until they are, build from source
> with `sbt publishLocal` and depend on the resulting local artifact.

The shape (illustrative — see the in-memory reference `KeyService` in `aegis-core` for the exact
constructor in your version):

```scala
import cats.effect.*
import dev.aegiskms.core.*

object Demo extends IOApp.Simple:
  val run: IO[Unit] =
    for
      svc <- KeyService.inMemory[IO]                      // pure, no I/O backend
      key <- svc.create(KeySpec("demo", Algorithm.AES, 256, ObjectType.SymmetricKey), principal)
      _   <- svc.activate(key.id, principal)
      sig <- svc.sign(key.id, "hello".getBytes, SignatureAlgorithm.RsaPssSha256, principal)
      _   <- IO.println(sig)
    yield ()
```

Wrap it with the audit + authorization decorators from `aegis-audit` / `aegis-iam` to get the
same pipeline the server runs. The [Architecture page](ARCHITECTURE.md) documents the decorator
stack.

---

## UC-4 — Production authentication

`dev` mode (`X-Aegis-User`) is for workstations only. Anything network-reachable must use `hmac`
or `oidc`.

### UC-4a — HMAC JWT (HS256), self-issued

```bash
export AEGIS_AUTH_HMAC_SECRET="$(openssl rand -base64 48)"
AEGIS_AUTH_KIND=hmac $COMPOSE up -d
```
Mint caller tokens with `JwtIssuer.hmac` (see [UC-1, Step 2](#step-2--mint-a-bootstrap-human-token)).
Use only inside a single trust boundary — the symmetric secret can both sign and verify.

### UC-4b — OIDC / JWKS (Keycloak, Auth0, Okta, Google, …)

```bash
AEGIS_AUTH_KIND=oidc \
  AEGIS_AUTH_OIDC_ISSUER_URI="https://keycloak.example.com/realms/aegis" \
  AEGIS_AUTH_OIDC_AUDIENCE="aegis-kms" \
  $COMPOSE up -d
```
Aegis fetches the issuer's `.well-known/openid-configuration` once at boot to resolve `jwks_uri`,
caches the JWKS (`AEGIS_AUTH_OIDC_JWKS_CACHE_TTL_SECONDS`, default 1h), and refreshes lazily on a
`kid` miss — so provider key rotation needs no operator action. Supports RS256/384/512 and
ES256/384/512. Always set an `audience` in production to prevent token reuse across services.

---

## UC-5 — Issue agent tokens with durable, multi-node revocation

For the auto-responder's `Revoke` to kill an agent's JWT *before* it expires — and for that to
hold across a multi-node deployment — back the revocation list with Redis:

```bash
AEGIS_AUTH_KIND=hmac AEGIS_REVOCATION_KIND=redis \
  AEGIS_REVOCATION_REDIS_URI="redis://localhost:6379" \
  $COMPOSE up -d
```
- `none` — tokens revoke only at natural expiry.
- `in-memory` — process-local, lost on restart (fine for single-node dev).
- `redis` — durable, shared across nodes (production path; required for instant kill-switch).

Issue tokens with `POST /v1/agents/issue` (UC-1 Step 4) or `aegis agent issue` (UC-12). Max TTL is
24h by design — agent credentials are deliberately short-lived.

---

## UC-6 — Honey keys (canary keys)

Mark real-looking KeyIds so any **agent** touch fires `Severity.High` → auto-revoke. Human touches
are *not* auto-revoked (operators may validate the canary is alive) but still produce an audit row.

```bash
AEGIS_HONEY_KEYS="<key-id-1>,<key-id-2>" AEGIS_AUTH_KIND=hmac $COMPOSE up -d
```
Boot fails fast on a malformed KeyId (a typo'd canary that never catches anything is the opposite
of what you want). See the full walkthrough in [UC-1](#uc-1--the-flagship-catch-a-rogue-agent-and-auto-revoke-it).

---

## UC-7 — Human RBAC via the role-based policy engine

By default every human is allowed every op (`dev` policy). To enforce "alice can sign but not
revoke," switch to the role-based engine and bind groups/subjects to KMIP operation names:

```bash
AEGIS_POLICY_KIND=role-based $COMPOSE up -d
```
Bindings live under `aegis.policy.role-based` in HOCON (mount a config file or extend
`application.conf`):
```hocon
aegis.policy.role-based {
  role-bindings    { kms-signers = ["Sign", "Verify", "Get"] }
  subject-bindings { "break-glass@org" = ["Revoke", "Compromise", "Destroy"] }
}
```
Groups come from OIDC claims (or the dev header). Unknown operation names **fail fast at boot**;
`kind=role-based` with no bindings is rejected (silent allow-all would defeat the purpose).
Valid operations: `Create, Get, Locate, Activate, Revoke, Destroy, Sign, Verify, Encrypt, Decrypt,
Wrap, Unwrap, Rotate, Compromise, Query, GetAttributes, AddAttribute`.

---

## UC-8 — Choose a persistence backend

| `AEGIS_JOURNAL_KIND` | Use it for | Required vars |
|---|---|---|
| `in-memory` | tests, demos (lost on restart) | — |
| `postgres` | production, multi-node | `AEGIS_JDBC_URL`, `AEGIS_JDBC_USERNAME`, `AEGIS_JDBC_PASSWORD` |
| `mysql` | MySQL 8 shops | `AEGIS_MYSQL_JDBC_URL`, `AEGIS_MYSQL_USERNAME`, `AEGIS_MYSQL_PASSWORD` |
| `sqlite` | laptops, CI, single-node edge | `AEGIS_SQLITE_JDBC_URL` (use a **file** path, not `:memory:`) |

```bash
# SQLite single-file journal — no external DB needed
AEGIS_JOURNAL_KIND=sqlite AEGIS_SQLITE_JDBC_URL="jdbc:sqlite:/var/lib/aegis/journal.db" \
  $COMPOSE up -d
```
All backends bootstrap their schema on startup; the migration is idempotent.

---

## UC-9 — Use a real AWS KMS root of trust

The default `in-memory` root of trust is a dev stub (HMAC/XOR — **not** real crypto). For
production, layer Aegis over an AWS KMS customer master key:

```bash
AEGIS_CRYPTO_KIND=aws-kms \
  AEGIS_CRYPTO_AWS_KMS_REGION="us-east-1" \
  AEGIS_CRYPTO_AWS_KMS_KEK_ARN="arn:aws:kms:us-east-1:123456789012:key/abcd-…" \
  AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… \
  $COMPOSE up -d
```
Credentials come from the AWS SDK default provider chain (env vars, instance metadata, SSO).
GCP / Azure / Vault / PKCS#11 adapters are roadmapped for v0.3.0–v0.5.0.

---

## UC-10 — Audit fan-out and the audit-read API

Aegis writes one immutable audit record per state-changing call. The **primary** sink is durable;
**secondary** sinks fan out best-effort (failures retry + dead-letter, never block the durable
write). A typical production setup is `postgres` (for the read API) **plus** one or more streams.

```bash
AEGIS_AUDIT_KIND=postgres \
  AEGIS_AUDIT_WEBHOOK_ENABLED=true \
  AEGIS_AUDIT_WEBHOOK_URL="https://siem.example.com/ingest" \
  AEGIS_AUDIT_WEBHOOK_SECRET="$(openssl rand -base64 48)" \
  AEGIS_AUDIT_KAFKA_ENABLED=true \
  AEGIS_AUDIT_KAFKA_BOOTSTRAP_SERVERS="broker:9092" \
  AEGIS_AUDIT_KAFKA_TOPIC="aegis.audit" \
  AEGIS_AUDIT_NATS_ENABLED=true \
  AEGIS_AUDIT_NATS_SERVERS="nats://nats:4222" \
  $COMPOSE up -d
```
- **Webhook** — HTTPS POST per record, `X-Aegis-Signature: sha256=<hmac>` (GitHub-webhook style).
- **Kafka** — idempotent producer (`acks=all`), record key = `correlationId` for per-request order.
- **NATS JetStream** — `publishAsync` + `PubAck`; durable ack before the record is considered sent.

Each has retry/backoff and a JSONL dead-letter file (`AEGIS_AUDIT_*_DEAD_LETTER_FILE`). Query the
durable log over REST:

```bash
curl -s "$AEGIS/v1/audit?actor=invoice-bot&op=Sign&since=2026-05-01T00:00:00Z&limit=50" \
  -H "$H_ALICE" | jq
```
Filters (`since`, `until`, `actor`, `key`, `op`, `limit`, `offset`) compose with AND. Retention is
`AEGIS_AUDIT_RETENTION_DAYS` (default 365; `0` disables pruning).

---

## UC-11 — Observability (Prometheus + OpenTelemetry)

```bash
$COMPOSE up -d
curl -s "$AEGIS/metrics" | grep aegis_       # per-op counters, latency histograms, error codes
```
Point traces at any OTLP collector by setting standard OTel env vars on the container:
```bash
docker run … \
  -e OTEL_TRACES_EXPORTER=otlp \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318 \
  -e OTEL_SERVICE_NAME=aegis-server \
  ghcr.io/sharma-bhaskar/aegis-server:0.2.0
```
Spans are named `kms.<op>` with attributes. Full matrix in
[Operations → Observability](operations/observability.md).

---

## UC-12 — CLI workflows

The `aegis` CLI (download the tarball from a [release](https://github.com/sharma-bhaskar/aegis-kms/releases),
or `sbt 'cli/Universal/packageZipTarball'`):

```bash
aegis login --server http://localhost:8080 --principal alice   # stores dev X-Aegis-User config
aegis keys create --name demo --alg AES --size 256
aegis keys sign --id <key-id> --message "hello"
aegis keys rotate --id <key-id>
aegis agent issue --label invoice-bot --scopes Sign,Get --ttl 3600
aegis audit tail --actor invoice-bot --op Sign --watch        # live poll every 2s
```
> `aegis login` stores the server URL + dev principal (it uses the `X-Aegis-User` header). For
> `hmac`/`oidc` servers, the CLI needs a Bearer token; minting one is shown in
> [UC-1 Step 2](#step-2--mint-a-bootstrap-human-token). `aegis advisor scan` is a stub until the
> v0.2.1 LLM advisor.

---

## Reference — environment variable cheat sheet

| Var | Default | Purpose |
|---|---|---|
| `AEGIS_HTTP_HOST` / `AEGIS_HTTP_PORT` | `0.0.0.0` / `8080` | bind address |
| `AEGIS_AUTH_KIND` | `dev` | `dev` · `hmac` · `oidc` |
| `AEGIS_AUTH_HMAC_SECRET` | — | HS256 secret (≥32 bytes); also signs issued agent tokens |
| `AEGIS_AUTH_OIDC_ISSUER_URI` / `_AUDIENCE` | — | OIDC discovery + expected `aud` |
| `AEGIS_JOURNAL_KIND` | `in-memory` | `in-memory` · `postgres` · `mysql` · `sqlite` |
| `AEGIS_JDBC_URL` / `_USERNAME` / `_PASSWORD` | localhost | Postgres journal |
| `AEGIS_SQLITE_JDBC_URL` | `…/journal.db` | SQLite file path |
| `AEGIS_CRYPTO_KIND` | `in-memory` | `in-memory` (dev stub) · `aws-kms` |
| `AEGIS_CRYPTO_AWS_KMS_REGION` / `_KEK_ARN` | — | AWS KMS layered mode |
| `AEGIS_REVOCATION_KIND` | `in-memory` | `none` · `in-memory` · `redis` |
| `AEGIS_REVOCATION_REDIS_URI` | — | Lettuce URI for the kill-switch |
| `AEGIS_POLICY_KIND` | `dev` | `dev` · `role-based` |
| `AEGIS_HONEY_KEYS` | — | comma-separated canary KeyIds |
| `AEGIS_AUDIT_KIND` | `stdout` | `stdout` · `postgres` |
| `AEGIS_AUDIT_RETENTION_DAYS` | `365` | `0` disables pruning |
| `AEGIS_AUDIT_WEBHOOK_*` | disabled | SIEM HTTPS fan-out |
| `AEGIS_AUDIT_KAFKA_*` | disabled | Kafka fan-out |
| `AEGIS_AUDIT_NATS_*` | disabled | NATS JetStream fan-out |

## Where to next

- **[Quickstart](getting-started/quickstart.md)** — the two-command path to a running server.
- **[USAGE.md](USAGE.md)** — the linear, output-for-every-call crypto walkthrough.
- **[Architecture](ARCHITECTURE.md)** — module split, request lifecycle, audit model.
- **[Operations → Security](operations/security.md)** — the deploy-time hardening matrix.
