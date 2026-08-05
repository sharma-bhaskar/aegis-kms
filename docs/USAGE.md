# Usage Walkthrough

A linear, hands-on walk through every operation Aegis-KMS supports — Step 0 (Docker installed)
through Step 19 (clean up). Every step has the exact command to run and the expected output.
By the end you'll have created a key, used every crypto operation, rotated it, marked it as
compromised, inspected the audit trail, scraped Prometheus, and looked at OpenTelemetry traces.

Time to complete: **15-20 minutes** if you copy-paste; **30-45 minutes** if you read along.

!!! note "Prefer reference docs?"

    This page is the linear walkthrough. For a per-audience reference (app developer, operator,
    AI agent, storage vendor), see [POSITIONING.md](POSITIONING.md). For deep architecture, see
    [ARCHITECTURE.md](ARCHITECTURE.md). For the REST surface, the live OpenAPI spec is at
    `http://localhost:8080/docs/` once the server is running.

---

## Step 0 — Prerequisites

You need:

| Tool | Version | Why |
|---|---|---|
| Docker | any recent | Brings up `aegis-server` + Postgres |
| `curl` | any | All examples use `curl` |
| `jq` | optional but recommended | Pretty-prints JSON responses |
| `openssl` | optional | Used to mint a JWT secret |

Verify:

```bash
docker --version && curl --version | head -1 && jq --version 2>/dev/null || true
```

If Docker isn't installed: <https://docs.docker.com/get-docker/>.

---

## Step 1 — Get the code

```bash
git clone https://github.com/sharma-bhaskar/aegis-kms.git
cd aegis-kms
```

You don't need a JDK or sbt for this walkthrough — we'll use the published Docker image. (If you
*do* want to build from source, see [Developer Guide](development/developer-guide.md).)

---

## Step 2 — Boot Aegis

Aegis-KMS requires you to set the Postgres password explicitly. There is no insecure default.

```bash
export POSTGRES_PASSWORD="$(openssl rand -base64 24)"
docker compose -f deploy/docker/docker-compose.yml up -d
```

Expected output (last 5 lines):

```
[+] Running 3/3
 ✔ Network aegis-kms_default     Created
 ✔ Container aegis-postgres      Started
 ✔ Container aegis-server        Started
```

Stream the logs in another terminal so you can see what the server is doing:

```bash
docker compose -f deploy/docker/docker-compose.yml logs -f aegis-server
```

You should see something like:

```
INFO  Started Aegis server on 0.0.0.0:8080
INFO  Persistence: Postgres event journal at jdbc:postgresql://postgres:5432/aegis
INFO  Crypto: AwsKmsRootOfTrust (or InMemoryRootOfTrust if AWS not configured)
INFO  Auth: dev mode (X-Aegis-User header)
INFO  Tracing: OpenTelemetry SDK auto-configured (OTEL_TRACES_EXPORTER=none)
INFO  Boot complete in 2.34s
```

Leave that log tail running — you'll watch real audit + trace events appear in it as you work.

---

## Step 3 — Verify the server is up

There's no dedicated `/health` endpoint yet — instead, watch the log tail from Step 2
for the "Boot complete" line, or hit the Swagger UI (next step). You can also confirm the
server is listening on 8080:

```bash
curl -sI http://localhost:8080/docs/ | head -1
# → HTTP/1.1 200 OK
```

If you get `connection refused`, the server hasn't finished booting — give it ~5 seconds
and retry. If it still fails, check the log tail; most failures are configuration issues
(bad `POSTGRES_PASSWORD`, AWS credentials missing when `AEGIS_ROT_KIND=aws`).

A `/healthz` endpoint with structured component health is targeted for v0.1.2.

---

## Step 4 — Open the Swagger UI

```bash
open http://localhost:8080/docs/
```

(On Linux, `xdg-open`; or just paste the URL in your browser.)

You should see the **OpenAPI 3.1 spec** rendered as Swagger UI, listing every endpoint Aegis
serves: `/v1/keys`, `/v1/keys/{id}/sign`, `/v1/keys/{id}/encrypt`, etc. The spec is generated
from the same Tapir endpoint values the runtime interprets, so it's impossible for the docs to
drift from the wire shape.

You can drive every operation in this walkthrough from Swagger UI's **"Try it out"** buttons
instead of `curl` if you prefer.

---

## Step 5 — Authenticate (dev mode)

By default, Aegis-KMS in this Docker Compose setup uses **dev auth**: pass an
`X-Aegis-User: <name>` header and the server treats you as that human principal. Use this for
the walkthrough; we'll switch to JWT in Step 17.

Set a shell variable so you don't have to retype it:

```bash
export AEGIS=http://localhost:8080
export USER_HEADER="X-Aegis-User: alice"
```

We'll use `$USER_HEADER` on every request. If you forget it, you'll get `401 Unauthorized` —
that's by design. There is no anonymous access.

(There's no `GET /v1/keys` list endpoint to confirm against yet — only
`GET /v1/keys/{id}` for a specific key. Step 6 creates a key we can fetch.)

---

## Step 6 — Create your first key

We'll create a 256-bit AES symmetric key, named `walkthrough-demo`.

```bash
KEY_RESPONSE=$(curl -s -X POST "$AEGIS/v1/keys" \
  -H "$USER_HEADER" \
  -H "Content-Type: application/json" \
  -d '{
    "spec": {
      "name": "walkthrough-demo",
      "algorithm": "AES",
      "sizeBits": 256,
      "objectType": "SymmetricKey"
    }
  }')
echo "$KEY_RESPONSE" | jq
```

Expected output:

```json
{
  "id": "8a3f1e25-6b0a-4f5d-8e92-1c4f6a83b2d9",
  "spec": {
    "name": "walkthrough-demo",
    "algorithm": "AES",
    "sizeBits": 256,
    "objectType": "SymmetricKey"
  },
  "state": "PreActive",
  "currentVersion": 1,
  "createdAt": "2026-05-09T01:23:45Z"
}
```

**What just happened:**

1. Aegis recorded a `KeyCreated` event in the Postgres event journal.
2. The key is in state `PreActive` — by design. A key starts in `PreActive` so a policy
   engine, auditor, or human operator has a chance to review before it goes live. **You can't
   sign or encrypt with a `PreActive` key** — you must explicitly activate it (Step 7).
3. An audit row was emitted to stdout (look at the log tail from Step 2).

Capture the `id` for the rest of the walkthrough:

```bash
export KEY_ID=$(echo "$KEY_RESPONSE" | jq -r '.id')
echo "KEY_ID=$KEY_ID"
```

### Other key specs

The same endpoint accepts several spec shapes:

| `algorithm` | Variants | Typical use |
|---|---|---|
| `AES` | 128, 192, **256** | Symmetric encrypt/decrypt, AEAD, envelope DEKs |
| `RSA` | 2048, 3072, 4096 | Wrap/unwrap, sign/verify |
| `EC` | `P-256`, `P-384`, `P-521`, `secp256k1` | Sign/verify, ECDH |
| `EdDSA` | `Ed25519`, `Ed448` | Sign/verify |
| `HMAC` | 256, 384, 512 | MAC, JWT signing (HS*) |

For this walkthrough we'll stick with AES-256.

---

## Step 7 — Activate the key

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/activate" -H "$USER_HEADER" | jq
```

Expected output:

```json
{
  "id": "8a3f1e25-...",
  "state": "Active",
  "activatedAt": "2026-05-09T01:24:01Z"
}
```

**State machine:**

```
                                    rotate                compromise
PreActive  ──activate──►  Active  ───────►  Deactivated  ───────────►  Compromised  ──destroy──►  Destroyed
                            │                                                                        ▲
                            └────────────────────────────compromise──────────────────────────────────┘
```

Sign / encrypt / wrap require `Active`. Verify / decrypt / unwrap are permitted on `Active`
*and* `Deactivated` (so material produced before a rotation remains readable). `Compromised`
and `Destroyed` refuse every op.

---

## Step 8 — Sign a message

Aegis currently supports two signature algorithms: `RsaPssSha256` and `EcdsaSha256`. The dev-mode
in-memory Root of Trust accepts either against any key spec, so we'll use `RsaPssSha256` here.

```bash
MSG_B64=$(echo -n 'invoice #1234 total $42,000' | base64)

curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/sign" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"messageBase64\":\"$MSG_B64\",\"algorithm\":\"RsaPssSha256\"}" | jq
```

Expected output:

```json
{
  "signatureBase64": "kY3Z0bH9eXqPQ8a7cF6V4t5RmN1pL2rS3sO9wJxK8uM=",
  "algorithm":       "RsaPssSha256",
  "keyVersion":      1
}
```

Capture a signature of `"hello"` for Step 9:

```bash
HELLO_B64=$(echo -n 'hello' | base64)

export SIG=$(curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/sign" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"messageBase64\":\"$HELLO_B64\",\"algorithm\":\"RsaPssSha256\"}" \
  | jq -r '.signatureBase64')
echo "SIG=$SIG"
```

---

## Step 9 — Verify the signature

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/verify" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"messageBase64\":\"$HELLO_B64\",\"signatureBase64\":\"$SIG\",\"algorithm\":\"RsaPssSha256\"}" \
  | jq
```

Expected output:

```json
{
  "valid":     true,
  "algorithm": "RsaPssSha256"
}
```

Try tampering — change `'hello'` to `'helloo'`:

```bash
TAMPERED_B64=$(echo -n 'helloo' | base64)

curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/verify" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"messageBase64\":\"$TAMPERED_B64\",\"signatureBase64\":\"$SIG\",\"algorithm\":\"RsaPssSha256\"}" \
  | jq
```

Expected output (note: HTTP status is **still 200** — `valid: false` is a successful
verification *result*, not an error):

```json
{
  "valid":     false,
  "algorithm": "RsaPssSha256"
}
```

---

## Step 10 — Encrypt + decrypt with EncryptionContext (AAD)

`EncryptionContext` is bound to the ciphertext as **Additional Authenticated Data** — to
decrypt successfully, the caller must present the same context. This is what protects against
ciphertext-substitution attacks where an attacker swaps in another tenant's ciphertext.

```bash
ENC_RESPONSE=$(curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/encrypt" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{
    "plaintextBase64": "'"$(echo -n 'q2 financial summary: $42M revenue' | base64)"'",
    "context": {"dataset":"q2-financials","tenant":"acme"}
  }')
echo "$ENC_RESPONSE" | jq
```

Expected output:

```json
{
  "ciphertextBase64": "AQEBAHj...",
  "keyVersion": 1,
  "algorithm": "AesGcm256"
}
```

Decrypt with the **matching** context:

```bash
CIPHERTEXT=$(echo "$ENC_RESPONSE" | jq -r '.ciphertextBase64')

curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/decrypt" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{
    "ciphertextBase64": "'"$CIPHERTEXT"'",
    "context":          {"dataset":"q2-financials","tenant":"acme"}
  }' | jq -r '.plaintextBase64' | base64 -d
echo
```

Expected output:

```
q2 financial summary: $42M revenue
```

Now try with the **wrong** context — say a different tenant:

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/decrypt" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{
    "ciphertextBase64": "'"$CIPHERTEXT"'",
    "context":          {"dataset":"q2-financials","tenant":"different-tenant"}
  }' | jq
```

Expected output:

```json
{
  "error": "DecryptionFailed",
  "message": "EncryptionContext mismatch — refusing to decrypt"
}
```

This is the correct behaviour: the AAD bound the context to the ciphertext at encrypt time;
presenting different AAD at decrypt time is a forgery and rejected.

---

## Step 11 — Wrap + unwrap a data encryption key (DEK)

Envelope encryption is the standard pattern for encrypting large objects: you generate a
short-lived data encryption key (DEK) per object, encrypt the object with the DEK locally, and
then wrap the DEK under your KMS key. Aegis exposes `wrap` / `unwrap` for this.

```bash
WRAP_RESPONSE=$(curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/wrap" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{
    "plaintextBase64": "'"$(openssl rand -base64 32)"'"
  }')
echo "$WRAP_RESPONSE" | jq
```

Expected output:

```json
{
  "wrappedKeyBase64": "AQECAHg...",
  "keyVersion": 1,
  "algorithm": "AesKeyWrap256"
}
```

Unwrap:

```bash
WRAPPED=$(echo "$WRAP_RESPONSE" | jq -r '.wrappedKeyBase64')

curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/unwrap" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{"wrappedKeyBase64":"'"$WRAPPED"'"}' | jq
```

Expected output:

```json
{
  "plaintextBase64": "<original 32-byte random key>",
  "keyVersion": 1
}
```

---

## Step 12 — Rotate the key

Rotation creates a *new key version* under the same `KeyId`. New writes go to the new
version; old ciphertexts and signatures remain readable because `verify` / `decrypt` /
`unwrap` happily accept material from any active *or deactivated* prior version.

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/rotate" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{"reason":"scheduled-rotation"}' | jq
```

Expected output:

```json
{
  "id": "8a3f1e25-...",
  "previousVersion": 1,
  "currentVersion": 2,
  "rotatedAt": "2026-05-09T01:30:12Z"
}
```

Now sign with the rotated key — it'll use version 2:

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/sign" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{"messageBase64":"'"$(echo -n 'after rotation' | base64)"'","algorithm":"RsaPssSha256"}' \
  | jq '{algorithm, keyVersion}'
```

Expected output:

```json
{
  "algorithm":  "RsaPssSha256",
  "keyVersion": 2
}
```

But you can still verify a signature made by version 1:

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/verify" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"messageBase64\":\"$HELLO_B64\",\"signatureBase64\":\"$SIG\",\"algorithm\":\"RsaPssSha256\"}" \
  | jq
```

Returns `valid: true` because Aegis tracks per-version key material and routes the verify to
the version that signed it.

---

## Step 13 — Mark the key as compromised

This is a one-way transition. `Compromised` keys refuse all operations, and the audit row is
emitted with severity `Critical`.

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/compromise" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{"reason":"leaked in S3 audit on 2026-05-08"}' | jq
```

Expected output:

```json
{
  "id": "8a3f1e25-...",
  "state": "Compromised",
  "compromisedAt": "2026-05-09T01:31:00Z",
  "reason": "leaked in S3 audit on 2026-05-08"
}
```

Try to sign — it will refuse:

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/sign" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{"messageBase64":"'"$(echo -n 'too late' | base64)"'","algorithm":"RsaPssSha256"}' \
  | jq
```

Expected output:

```json
{
  "error": "IllegalOperation",
  "message": "Cannot sign with key in state Compromised"
}
```

This is what the v0.2.0 auto-responder will do automatically when the anomaly detector fires
a `Critical` alert — for now, it's an explicit operator action.

---

## Step 14 — Inspect the audit log

The default `AuditSink` writes to stdout. In your log-tail terminal (Step 2) you'll have seen
rows like:

```
{"ts":"2026-05-09T01:23:45.234Z","actor":"alice","actorKind":"Human","op":"KeyCreated","keyId":"8a3f1e25-...","outcome":"Success","keyVersion":1}
{"ts":"2026-05-09T01:24:01.567Z","actor":"alice","actorKind":"Human","op":"KeyActivated","keyId":"8a3f1e25-...","outcome":"Success"}
{"ts":"2026-05-09T01:24:30.890Z","actor":"alice","actorKind":"Human","op":"Sign","keyId":"8a3f1e25-...","outcome":"Success","keyVersion":1,"alg":"RsaPssSha256"}
{"ts":"2026-05-09T01:25:00.123Z","actor":"alice","actorKind":"Human","op":"Verify","keyId":"8a3f1e25-...","outcome":"Success","keyVersion":1}
{"ts":"2026-05-09T01:25:15.456Z","actor":"alice","actorKind":"Human","op":"Verify","keyId":"8a3f1e25-...","outcome":"InvalidSignature"}
{"ts":"2026-05-09T01:30:12.111Z","actor":"alice","actorKind":"Human","op":"Rotate","keyId":"8a3f1e25-...","outcome":"Success","previousVersion":1,"currentVersion":2}
{"ts":"2026-05-09T01:31:00.222Z","actor":"alice","actorKind":"Human","op":"Compromise","keyId":"8a3f1e25-...","outcome":"Success","severity":"Critical","reason":"leaked in S3 audit on 2026-05-08"}
{"ts":"2026-05-09T01:31:15.333Z","actor":"alice","actorKind":"Human","op":"Sign","keyId":"8a3f1e25-...","outcome":"IllegalOperation","reason":"key state=Compromised"}
```

Every state change *and* every crypto operation lands in this log. Including the failures —
note the last row, which records the rejected sign attempt against the compromised key.

In v0.2.0 these will fan out to Kafka / S3 / Webhook / Postgres sinks instead of (or in
addition to) stdout. The `AuditSink` SPI is in place; the adapters are next.

---

## Step 14b — See which agents exist right now

When an agent credential misbehaves, the first question is "what else is out there?". `GET
/v1/agents` answers it in one call — every agent minted in the last 7 days, who issued it, what
it can touch, and whether it's still live:

```bash
aegis agent list
```

```
AGENT ID                               STATUS   PARENT               EXPIRES                LAST SEEN              SCOPES
agent-7a3f1e25-...                     Active   alice@org            2026-08-04T12:50:00Z   2026-08-04T11:58:00Z   Get,Sign
agent-91bc0d42-...                     Active   alice@org            2026-08-04T13:10:00Z   never                  Decrypt,Encrypt
agent-4e77a1b9-...                     Revoked  bob@org              2026-08-04T12:30:00Z   2026-08-04T11:20:00Z   Sign

3 shown (offset 0), 2 active overall.
```

`never` in the last-seen column means the credential was minted but has not been used — worth
noticing on its own, since an unused agent token is pure standing risk.

Narrow it down during an incident:

```bash
aegis agent list --parent alice@org          # everything alice spawned
aegis agent list --status Revoked            # confirm a kill actually landed
aegis agent list --status Active --limit 20
```

The same data is on the REST surface, and the active count is exported as a Prometheus gauge:

```bash
curl -s "$AEGIS/v1/agents?status=Active" -H "X-Aegis-User: alice" | jq
curl -s http://localhost:8080/metrics | grep aegis_agents_active
```

Two things to know. Listing agents is **restricted to human principals** — an agent cannot
enumerate its peers, because a compromised credential should not come with a map of every other
credential to attack. And the registry is **assembled from the audit log** rather than a separate
table, so it needs a queryable audit sink; on the default `stdout` sink this endpoint returns
`501`. Set `AEGIS_AUDIT_KIND=postgres` to enable it.

---

## Step 14c — Pull the kill-switch

When an operator's account is compromised, revoking agents one `jti` at a time is not a plan. One call
kills every live agent under a parent:

```bash
aegis agent revoke --parent alice@org
```

```
Kill-switch: parent=alice@org — revoked 3, already revoked 1, expired 2
  agent-7a3f1e25-...                     claude-invoice-batch         expired 2026-08-04T12:50:00Z
  agent-91bc0d42-...                     claude-reconcile             expired 2026-08-04T13:10:00Z
  agent-0f2e7c81-...                     claude-report                expired 2026-08-04T12:35:00Z
```

The three counts are separate on purpose. "Revoked 3" and "revoked 1, 11 already revoked" call for very
different next steps.

Usually you want a time bound rather than everything alice has ever spawned — otherwise you take out
legitimate long-running work along with the compromised credentials:

```bash
aegis agent revoke --parent alice@org --issued-after 2026-08-04T11:00:00Z
```

It is **idempotent** — re-running it reports the agents as already revoked rather than erroring — and it
revokes through the same `RevocationList` every node consults on each verify, so on a Redis-backed
multi-node deployment the kill lands fleet-wide, not just on the replica that served your request.

### Step-up authentication

This is the most destructive endpoint Aegis exposes, so a valid token is not enough. Your credential must
prove you authenticated *strongly* and *recently*:

```bash
curl -s -X POST "$AEGIS/v1/agents/revoke" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"parent":"alice@org"}' -i
```

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: aegis-stepup realm="aegis", reason="this operation requires re-authentication with
                  one of: face, fpt, hwk, mfa, otp, swk", acr="face fpt hwk mfa otp swk", max_age=300

{"code":"StepUpRequired","message":"this operation requires re-authentication with one of: ..."}
```

Re-authenticate the human — genuinely, not by refreshing the token you already hold — and retry. Aegis
reads the OIDC-standard `amr` and `auth_time` claims: `amr` must include one of the accepted methods, and
`auth_time` must fall inside `max_age`. Both conditions are required, and everything fails closed:

| Credential | Result |
| --- | --- |
| `amr: ["mfa"]`, authenticated 1 minute ago | ✅ allowed |
| `amr: ["mfa"]`, authenticated 1 hour ago | ❌ stale — re-authenticate |
| `amr: ["pwd"]` | ❌ a password is what you already presented to get the session |
| no `amr` or no `auth_time` | ❌ the issuer told us nothing; that is not evidence |
| a service account or an agent | ❌ step-up means *a person* re-proved who they are |

Tune it to whatever your IDP actually emits:

```bash
export AEGIS_SECURITY_STEP_UP_METHODS='["hwk"]'      # hardware keys only
export AEGIS_SECURITY_STEP_UP_MAX_AGE_SECONDS=120    # tighter freshness window
```

### Automatic fleet revocation (off by default)

The auto-responder can pull the kill-switch itself on a high-severity anomaly:

```bash
export AEGIS_AUTO_RESPONSE_KILL_FLEET_ENABLED=true
```

Understand the blast radius before you do. With this on, a single false positive revokes **every** agent
belonging to the offending agent's parent operator, with no human in the loop — not one credential. That
is why it is off by default and absent from the default rule set: you must both enable the flag and write
the `KillAgentFleet` rule yourself.

---

## Step 15 — Inspect Prometheus metrics

```bash
curl -s http://localhost:8080/metrics | grep -E '^aegis_keys_op_(total|errors)' | head -20
```

Expected output (roughly):

```
aegis_keys_op_total{operation="Create"} 1.0
aegis_keys_op_total{operation="Activate"} 1.0
aegis_keys_op_total{operation="Sign"} 3.0
aegis_keys_op_total{operation="Verify"} 2.0
aegis_keys_op_total{operation="Encrypt"} 1.0
aegis_keys_op_total{operation="Decrypt"} 2.0
aegis_keys_op_total{operation="Wrap"} 1.0
aegis_keys_op_total{operation="Unwrap"} 1.0
aegis_keys_op_total{operation="Rotate"} 1.0
aegis_keys_op_total{operation="Compromise"} 1.0
aegis_keys_op_errors_total{operation="Decrypt",code="DecryptionFailed"} 1.0
aegis_keys_op_errors_total{operation="Sign",code="IllegalOperation"} 1.0
aegis_keys_op_errors_total{operation="Verify",code="InvalidSignature"} 1.0
```

You'll also see standard JVM metrics: `jvm_memory_used_bytes`, `jvm_gc_pause_seconds`,
`process_uptime_seconds`, etc. Point your Prometheus scrape config at
`http://aegis-server:8080/metrics` in production.

---

## Step 16 — Inspect OpenTelemetry traces (optional)

By default, traces are exported to nowhere (`OTEL_TRACES_EXPORTER=none`). To wire them to a
local Jaeger:

```bash
docker run -d --name jaeger \
  -p 16686:16686 -p 4318:4318 \
  jaegertracing/all-in-one:latest

# Restart Aegis with OTel pointing at Jaeger
docker compose -f deploy/docker/docker-compose.yml down
export OTEL_TRACES_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_ENDPOINT=http://host.docker.internal:4318
export OTEL_SERVICE_NAME=aegis-server
docker compose -f deploy/docker/docker-compose.yml up -d

# Make some requests so there's something to see
curl -s -X POST "$AEGIS/v1/keys" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{"spec":{"name":"trace-demo","algorithm":"AES","sizeBits":256,"objectType":"SymmetricKey"}}' \
  > /dev/null

# Open Jaeger UI
open http://localhost:16686
```

In Jaeger, select **service: aegis-server**. You'll see spans named `kms.Create`, `kms.Sign`,
`kms.Encrypt` etc. with attributes:

- `aegis.operation` — `Sign`, `Encrypt`, `Rotate`, ...
- `aegis.key.id` — the KeyId
- `aegis.principal.subject` — `alice`
- `aegis.principal.kind` — `human` or `agent`
- `aegis.outcome` — `success` or `error_<code>`

For full request-graph coverage (HTTP server spans, JDBC spans, AWS SDK spans), see
[Operations → Observability](operations/observability.md#full-request-graph-coverage).

---

## Step 17 — Use the `aegis` CLI

Everything you just did via `curl` is also available via the `aegis` CLI. Download the tarball
from the latest release:

```bash
TAG=0.2.0
curl -L -o aegis-cli.tgz \
  "https://github.com/sharma-bhaskar/aegis-kms/releases/download/v${TAG}/aegis-cli-${TAG}.tgz"
tar -xzf aegis-cli.tgz
export AEGIS_CLI=./aegis-cli-${TAG}/bin/aegis

$AEGIS_CLI version
# → aegis 0.2.0
```

Run the same end-to-end flow as Steps 5-13:

```bash
$AEGIS_CLI login --server $AEGIS --principal alice
$AEGIS_CLI keys create --alg AES-256 --name cli-demo
$AEGIS_CLI keys list
$AEGIS_CLI keys activate <id>
$AEGIS_CLI keys sign     --id <id> --message "hello"
$AEGIS_CLI keys encrypt  --id <id> --plaintext "secret" --context dataset=q2
$AEGIS_CLI keys rotate   --id <id>
$AEGIS_CLI keys compromise --id <id> --reason "leaked"
```

Every verb has `--help`. The login command stores the server URL + principal in
`~/.config/aegis/config.json`, so subsequent commands don't need to repeat them.

!!! note "CLI command status"

    `aegis agent issue` and `aegis audit tail` are wired end-to-end as of v0.2.0 (#79).
    `aegis advisor scan` / `explain` still print *"not yet wired up"* — they're the surface for
    the v0.2.1 LLM advisor. Don't be surprised when the advisor commands don't do anything yet.

---

## Step 18 — Switch from dev auth to JWT (for production)

Dev mode (`X-Aegis-User`) is fine for the walkthrough but unsafe for anything else. Production
uses JWT bearer tokens.

```bash
# Pick a strong shared secret (at least 32 bytes)
export AEGIS_AUTH_HMAC_SECRET="$(openssl rand -base64 48)"

# Restart the server with JWT auth
docker compose -f deploy/docker/docker-compose.yml down
docker run --rm -d --name aegis-server-jwt \
  -p 8080:8080 \
  -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  -e AEGIS_AUTH_KIND=hmac \
  -e AEGIS_AUTH_HMAC_SECRET="$AEGIS_AUTH_HMAC_SECRET" \
  ghcr.io/sharma-bhaskar/aegis-server:0.2.0
```

Mint a token (from a Scala REPL or a small program — Aegis ships `JwtIssuer.hmac` for this):

```scala
import dev.aegiskms.iam.JwtIssuer
val token = JwtIssuer.hmac(secret = sys.env("AEGIS_AUTH_HMAC_SECRET"))
  .issue(subject = "alice", groups = Set("admins"), ttl = 1.hour)
println(token)
```

Then use it in requests:

```bash
export TOKEN="<paste minted token>"
curl -s "$AEGIS/v1/keys" -H "Authorization: Bearer $TOKEN" | jq
```

For OIDC / JWKS / Auth0 / Okta integration, the `AEGIS_AUTH_KIND=oidc` mode is in WIP for
v0.2.0 — see [Operations → Security](operations/security.md) for the deploy-time
configuration matrix.

---

## Step 19 — Choose a Root of Trust

`AEGIS_CRYPTO_KIND` selects which backend actually performs the cryptography. Three ship today:

| `AEGIS_CRYPTO_KIND` | What it does | Use it for |
| --- | --- | --- |
| `in-memory` (default) | Deterministic MAC. `sign` is `HMAC(KeyId, msg)`; `encrypt` is XOR-with-keystream. **Not cryptography** — it exists so the wire surfaces round-trip. | The quickstart above; nothing else |
| `software` | Real AES-256-GCM, RSA-PSS-SHA-256 and ECDSA-P-256 from the JDK's own JCE providers, keyed from a PKCS#12 keystore. No cloud account, no network call. | CI, integration tests, and evaluating Aegis without AWS credentials |
| `aws-kms` | Every operation executes inside AWS KMS against a CMK. Key material never enters Aegis's process. | Production |

### The software backend

This is the one to reach for when you want the real crypto paths without an AWS account —
signatures that actually verify against a public key, ciphertext that is actually ciphertext:

```bash
export AEGIS_CRYPTO_KIND=software
# Optional: persist key material across restarts. Omit both to get an ephemeral keystore
# whose keys vanish when the JVM exits (the right choice in CI).
export AEGIS_CRYPTO_SOFTWARE_KEYSTORE_PATH=/var/lib/aegis/keystore.p12
export AEGIS_CRYPTO_SOFTWARE_KEYSTORE_PASSWORD='<a real password>'
```

The keystore file is created with owner-only permissions and holds raw key material protected
only by that password — back it up and guard it exactly as you would a TLS private key. Losing
it makes every key wrapped against it unrecoverable.

`aegis key rotate` mints a new KEK generation inside the keystore and leaves earlier generations
in place, so material wrapped before a rotation still unwraps afterwards. The generation number
travels in the ciphertext header.

**It is not a production backend.** The KEK and the signing private keys live in the server's
JVM heap, so a heap dump, a `/proc/<pid>/mem` read, or an RCE in the server exposes every key it
ever wrapped — none of which is true of AWS KMS or a PKCS#11 HSM. Aegis will not let you forget:
selecting it logs a warning banner at boot, and the boot preflight reports it as a dev-grade
setting, so `AEGIS_SECURITY_PREFLIGHT=enforce` refuses to bind a network-reachable address with
it configured.

### AWS KMS (production)

In production, swap in `AwsKmsRootOfTrust` so key material lives in AWS KMS hardware-backed CMKs
and never touches Aegis's process memory.

Required AWS IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "kms:CreateKey", "kms:DescribeKey", "kms:ScheduleKeyDeletion",
      "kms:Sign", "kms:Verify",
      "kms:Encrypt", "kms:Decrypt",
      "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext",
      "kms:GetPublicKey",
      "kms:CreateAlias", "kms:UpdateAlias",
      "kms:TagResource"
    ],
    "Resource": "*"
  }]
}
```

Boot Aegis with AWS RoT:

```bash
docker run --rm -d --name aegis-server-aws \
  -p 8080:8080 \
  -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  -e AEGIS_ROT_KIND=aws \
  -e AWS_REGION=us-east-1 \
  -e AWS_ACCESS_KEY_ID=... \
  -e AWS_SECRET_ACCESS_KEY=... \
  ghcr.io/sharma-bhaskar/aegis-server:0.2.0
```

(In production, use IAM Roles / IRSA on Kubernetes / ECS task roles instead of static
credentials.)

GCP / Azure / Vault RoT adapters are roadmapped for v0.3.0, and PKCS#11 / HSM for v0.5.0 — see
[Status](about/status.md#crypto-adapters-rootoftrust).

---

## Step 20 — Clean up

```bash
docker compose -f deploy/docker/docker-compose.yml down -v   # -v also removes the Postgres volume
docker rm -f aegis-server-jwt aegis-server-aws jaeger 2>/dev/null || true
```

`-v` removes the Postgres data volume. If you skip it, your keys persist for the next run.

---

## Reference — REST endpoints

You touched all of these. Full list:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/keys` | Create a new key (state: `PreActive`) |
| `GET` | `/v1/keys/{id}` | Get one key + state + version |
| `POST` | `/v1/keys/{id}/activate` | Transition `PreActive` → `Active` |
| `POST` | `/v1/keys/{id}/sign` | Sign a message (`RsaPssSha256` \| `EcdsaSha256`) |
| `POST` | `/v1/keys/{id}/verify` | Verify a signature |
| `POST` | `/v1/keys/{id}/encrypt` | Encrypt with EncryptionContext AAD |
| `POST` | `/v1/keys/{id}/decrypt` | Decrypt with matching AAD |
| `POST` | `/v1/keys/{id}/wrap` | Envelope-wrap a DEK |
| `POST` | `/v1/keys/{id}/unwrap` | Envelope-unwrap a DEK |
| `POST` | `/v1/keys/{id}/rotate` | Create a new key version |
| `POST` | `/v1/keys/{id}/compromise` | Mark key as `Compromised` (one-way) |
| `DELETE` | `/v1/keys/{id}` | Schedule destruction |
| `GET` | `/metrics` | Prometheus exposition |
| `GET` | `/docs/` | Swagger UI |
| `GET` | `/docs/docs.yaml` | Raw OpenAPI 3.1 spec |

> **Not yet:** there's no `GET /v1/keys` (list) endpoint and no `/health` /
> `/healthz` endpoint. Both are tracked for a later release.

---

## Reference — error codes

All error responses share this shape:

```json
{ "error": "<code>", "message": "<human-readable>" }
```

| Code | HTTP | When |
|---|---|---|
| `KeyNotFound` | 404 | Unknown KeyId |
| `IllegalOperation` | 409 | Operation not allowed in current state (e.g., sign on `Compromised`) |
| `InvalidSignature` | 200 | Verify returned `valid: false` (this is *not* an HTTP error) |
| `DecryptionFailed` | 400 | EncryptionContext mismatch, bad ciphertext, or algorithm mismatch |
| `PermissionDenied` | 403 | Principal not authorized for this operation on this key |
| `Unauthorized` | 401 | Missing or invalid bearer token / dev header |
| `BadRequest` | 400 | Schema validation error |
| `InternalError` | 500 | Unexpected error — open an issue with the request id from the response |

---

## Where to next

- **[Architecture](ARCHITECTURE.md)** — how the decorator stack, the actor model, and the
  two-tier module split fit together
- **[Operations → Observability](operations/observability.md)** — Prometheus + OpenTelemetry
  + Swagger UI deep-dive
- **[Operations → Security](operations/security.md)** — JWT, OIDC, IAM permissions, TLS termination
- **[Comparison](about/comparison.md)** — Aegis vs. AWS KMS / Vault / OpenBao / GCP / Azure
- **[Developer Guide](development/developer-guide.md)** — if you want to contribute
- **[Roadmap](about/roadmap.md)** — what lands when
