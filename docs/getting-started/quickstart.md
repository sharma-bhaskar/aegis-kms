# Quickstart

**Goal:** in ~15 minutes, get Aegis-KMS running on your machine and exercise the full crypto
operation surface — sign / verify, encrypt / decrypt (with AAD), wrap / unwrap a DEK, rotate, and
compromise — plus the three observability surfaces (Swagger UI, Prometheus, OpenTelemetry), plus
the **wedge** (shipped in v0.2.0): trip a rate-spike anomaly and watch the auto-responder revoke
the key in real time. Step 0 → Step 18, every command runnable, every
output shown, every prerequisite spelled out — assume you've never touched this project before.

**What you'll have when you're done:** a local Aegis-KMS instance, a key you created, a signed
message + verified signature, an encrypted-and-decrypted payload, a wrapped DEK, a rotated key,
a "compromised" key that refuses further use, a live audit log on stdout, a `/metrics` Prometheus
endpoint, and a demonstration of Aegis's differentiator — risk-scored decisions and an auto-revoke
when an actor exceeds their baseline.

For a deeper tour covering CLI usage, JWT auth, and configuring AWS KMS as the Root of Trust, see
the [full walkthrough](../USAGE.md) (~20 minutes).

---

## Step 0 — Prerequisites

You need **Docker**. That's it. (No JDK, no sbt — we use the published Docker image.)

```bash
docker --version
# → Docker version 27.x.x or newer
```

Optional but recommended:

```bash
curl --version | head -1   # any recent curl
jq --version               # for pretty-printing JSON
```

If Docker isn't installed: <https://docs.docker.com/get-docker/>.

---

## Step 1 — Get the repo

We use the Docker Compose file shipped in the repo (it brings up Postgres alongside the
server). You don't need to build anything from source.

```bash
git clone https://github.com/sharma-bhaskar/aegis-kms.git
cd aegis-kms
```

---

## Step 2 — Boot the server

Aegis requires you to set the Postgres password explicitly. There is no insecure default —
this is a deliberate security choice.

```bash
export POSTGRES_PASSWORD="$(openssl rand -base64 24)"
docker compose -f deploy/docker/docker-compose.yml up -d
```

Expected output:

```
[+] Running 3/3
 ✔ Network aegis-kms_default     Created
 ✔ Container aegis-postgres      Started
 ✔ Container aegis-server        Started
```

Watch the logs in another terminal so you can see audit events as you make requests:

```bash
docker compose -f deploy/docker/docker-compose.yml logs -f aegis-server
```

You should see `Boot complete` after ~2 seconds.

---

## Step 3 — Verify the server is up

The fastest check: open the Swagger UI in your browser.

```bash
open http://localhost:8080/docs/
# (Linux: xdg-open; or paste in a browser tab)
```

You should see Swagger UI with every Aegis endpoint listed: `POST /v1/keys`,
`POST /v1/keys/{id}/sign`, `POST /v1/keys/{id}/encrypt`, etc.

If the page doesn't load, check the log tail from Step 2 — most failures are
configuration issues (e.g. `POSTGRES_PASSWORD` not set in the shell).

---

## Step 4 — Set shell variables

You'll use these in every step.

```bash
export AEGIS=http://localhost:8080
export USER_HEADER="X-Aegis-User: alice"
```

`X-Aegis-User: alice` is the **dev-mode auth header** — every request you make will be
attributed to the principal `alice`. Production deployments use JWT bearer auth (covered in
the [full walkthrough](../USAGE.md#step-18-switch-from-dev-auth-to-jwt-for-production)).

---

## Step 5 — Create your first key

Create a 256-bit AES key named `quickstart-demo`:

```bash
RESPONSE=$(curl -s -X POST "$AEGIS/v1/keys" \
  -H "$USER_HEADER" \
  -H "Content-Type: application/json" \
  -d '{
    "spec": {
      "name":       "quickstart-demo",
      "algorithm":  "AES",
      "sizeBits":   256,
      "objectType": "SymmetricKey"
    }
  }')
echo "$RESPONSE" | jq
```

Expected output:

```json
{
  "id": "8a3f1e25-6b0a-4f5d-8e92-1c4f6a83b2d9",
  "spec": {
    "name":       "quickstart-demo",
    "algorithm":  "AES",
    "sizeBits":   256,
    "objectType": "SymmetricKey"
  },
  "state":          "PreActive",
  "currentVersion": 1,
  "createdAt":      "2026-05-09T01:23:45Z"
}
```

The key is in state **`PreActive`**. By design, you can't sign or encrypt yet — a key
starts pre-active so a policy engine, auditor, or human operator has a chance to review
before it goes live. We'll activate it in Step 6.

Capture the `id` for the rest of the walkthrough:

```bash
export KEY_ID=$(echo "$RESPONSE" | jq -r '.id')
echo "KEY_ID=$KEY_ID"
```

---

## Step 6 — Activate the key

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/activate" -H "$USER_HEADER" | jq
```

Expected output:

```json
{
  "id":           "8a3f1e25-...",
  "state":        "Active",
  "activatedAt":  "2026-05-09T01:24:01Z"
}
```

The key is now usable for crypto operations.

---

## Step 7 — Sign a message

We'll sign the message `"hello"` with RSA-PSS-SHA-256.

```bash
MSG_B64=$(echo -n 'hello' | base64)

SIG_RESPONSE=$(curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/sign" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"messageBase64\":\"$MSG_B64\",\"algorithm\":\"RsaPssSha256\"}")
echo "$SIG_RESPONSE" | jq
```

Expected output:

```json
{
  "signatureBase64": "kY3Z0bH9eXqPQ8a7cF6V4t5RmN1pL2rS3sO9wJxK8uM=",
  "algorithm":       "RsaPssSha256",
  "keyVersion":      1
}
```

Capture the signature:

```bash
export SIG=$(echo "$SIG_RESPONSE" | jq -r '.signatureBase64')
```

Look at your log-tail terminal — you should see a fresh audit row:

```
{"ts":"...","actor":"alice","actorKind":"Human","op":"Sign","keyId":"...","outcome":"Success","keyVersion":1,"alg":"RsaPssSha256"}
```

Every state change *and* every crypto operation generates an audit row.

---

## Step 8 — Verify the signature

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/verify" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"messageBase64\":\"$MSG_B64\",\"signatureBase64\":\"$SIG\",\"algorithm\":\"RsaPssSha256\"}" \
  | jq
```

Expected output:

```json
{
  "valid":     true,
  "algorithm": "RsaPssSha256"
}
```

Try a tampered message — change `'hello'` to `'helloo'`:

```bash
TAMPERED_B64=$(echo -n 'helloo' | base64)

curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/verify" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"messageBase64\":\"$TAMPERED_B64\",\"signatureBase64\":\"$SIG\",\"algorithm\":\"RsaPssSha256\"}" \
  | jq
```

Expected output (HTTP status is **still 200** — `valid: false` is a successful
verification *result*, not an error):

```json
{
  "valid":     false,
  "algorithm": "RsaPssSha256"
}
```

That's the cryptographic guarantee working: even a one-byte change to the message produces
`valid: false`.

---

## Step 9 — Encrypt and decrypt with an encryption context

`encrypt` takes an additional **encryption context** — a free-form `Map[String, String]` that's
bound to the ciphertext as additional authenticated data (AAD). The same context must be supplied
to `decrypt` or the call fails with `CryptographicFailure`. This is AWS KMS's `EncryptionContext`
model — useful for tying a ciphertext to its tenant / dataset / purpose.

```bash
PT_B64=$(echo -n 'secret invoice payload' | base64)

CIPHERTEXT=$(curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/encrypt" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"plaintextBase64\":\"$PT_B64\",\"context\":{\"dataset\":\"q2\",\"tenant\":\"acme\"}}" \
  | jq -r '.ciphertextBase64')

# Decrypt with the *same* context — succeeds
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/decrypt" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"ciphertextBase64\":\"$CIPHERTEXT\",\"context\":{\"dataset\":\"q2\",\"tenant\":\"acme\"}}" \
  | jq -r '.plaintextBase64' | base64 -d
# → secret invoice payload

# Decrypt with a *different* context — fails (CryptographicFailure)
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/decrypt" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"ciphertextBase64\":\"$CIPHERTEXT\",\"context\":{\"dataset\":\"q3\"}}" \
  | jq
```

The mismatched-context call returns:

```json
{ "error": "CryptographicFailure", "message": "encryption context mismatch" }
```

---

## Step 10 — Wrap and unwrap a DEK (envelope encryption)

For data too large for a single `encrypt` call (or for tools like `aws-encryption-sdk` that expect
envelope-encrypted blobs), wrap a Data Encryption Key under the Aegis KEK:

```bash
DEK_B64=$(head -c 32 /dev/urandom | base64)   # a 256-bit DEK

WRAPPED=$(curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/wrap" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"dekBase64\":\"$DEK_B64\"}" \
  | jq -r '.wrappedDekBase64')

# Unwrap to recover the original DEK — bytes-identical
UNWRAPPED=$(curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/unwrap" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"wrappedDekBase64\":\"$WRAPPED\"}" \
  | jq -r '.dekBase64')

diff <(echo "$DEK_B64") <(echo "$UNWRAPPED") && echo "round-trip OK"
```

Use the unwrapped DEK locally with `openssl` / your AES library of choice; persist the *wrapped*
form alongside your ciphertext. Rotating the KEK (Step 11) re-wraps without re-encrypting any of
the payload data.

---

## Step 11 — Rotate the key

Rotation increments the key's `currentVersion`. The dev backend produces deterministic-shape output
keyed by `KeyId` only, so signatures + ciphertexts produced before the rotation continue to verify
and decrypt — that's the contract the AWS KMS adapter preserves too:

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/rotate" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{"policy":"Manual"}' \
  | jq
```

Expected output:

```json
{
  "id":             "8a3f1e25-...",
  "state":          "Active",
  "currentVersion": 2,
  "rotatedAt":      "2026-05-09T01:30:12Z"
}
```

Verify that the signature from Step 7 *still* validates against the rotated key:

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/verify" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"messageBase64\":\"$MSG_B64\",\"signatureBase64\":\"$SIG\",\"algorithm\":\"RsaPssSha256\"}" \
  | jq
# → { "valid": true, "algorithm": "RsaPssSha256" }
```

Other policy shapes the server accepts: `TimeBased:7days`, `OpCountBased:10000`. Aegis records
the policy on the audit row; the auto-scheduler that *drives* rotation from the policy is
roadmapped for a later release.

---

## Step 12 — Mark a key as compromised (operator override)

This is the breakglass operation. From `Compromised` every cryptographic call — including
`verify` — refuses with `IllegalOperation`. The audit row carries `severity=Critical` and the
operator-supplied `reason`.

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/compromise" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{"reason":"discovered in S3 audit leak 2026-05-08"}' \
  | jq
```

Expected output:

```json
{
  "id":            "8a3f1e25-...",
  "state":         "Compromised",
  "compromisedAt": "2026-05-09T01:31:00Z",
  "reason":        "discovered in S3 audit leak 2026-05-08"
}
```

Subsequent calls now refuse:

```bash
curl -s -X POST "$AEGIS/v1/keys/$KEY_ID/sign" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"messageBase64\":\"$MSG_B64\",\"algorithm\":\"RsaPssSha256\"}" \
  | jq
# → { "error": "IllegalOperation", "message": "Key 8a3f1e25-... is Compromised" }
```

Compromise is **one-way** — there's no `un-compromise` operation. Cut a fresh key with a new
`create` + `activate`.

---

## Step 13 — Watch the observability surfaces

While the server is running, every operation you've made is visible on three surfaces. Open each
in a browser tab:

| Surface | URL | What you see |
|---|---|---|
| **Swagger UI** | <http://localhost:8080/docs/> | Live OpenAPI 3.1 spec for every endpoint. "Try it out" lets you fire requests from the browser. |
| **Prometheus metrics** | <http://localhost:8080/metrics> | `aegis_keys_op_total{operation="Sign"}`, latency histograms, error counters, plus the standard JVM / GC / process collectors. |
| **OpenAPI YAML** | <http://localhost:8080/docs/docs.yaml> | The raw spec — feed it to Postman, Insomnia, or `openapi-generator`. |

For full traces, point the OpenTelemetry SDK at any OTLP collector by setting env vars on the
container (`OTEL_TRACES_EXPORTER=otlp`, `OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318`,
`OTEL_SERVICE_NAME=aegis-server`). The full env-var matrix is in
[Operations → Observability](../operations/observability.md).

---

## Step 14 — (Optional) Preview unreleased work with the `:main` image

The wedge demo below — risk scorer, decision adapter, auto-responder — shipped in **v0.2.0**, so
the default `:0.2.0` image you've been running already has it. You can skip straight to Step 15.

To preview work that's landed on `main` but isn't tagged yet, use the `:main` floating image
(rebuilt by CI on every push to `main`):

```bash
docker compose -f deploy/docker/docker-compose.yml down
IMAGE_TAG=main docker compose -f deploy/docker/docker-compose.yml up -d
docker compose -f deploy/docker/docker-compose.yml logs -f aegis-server
```

If you'd rather build from source, that path is:

```bash
sbt 'server / Docker / publishLocal'
IMAGE_TAG=0.2.0-SNAPSHOT docker compose -f deploy/docker/docker-compose.yml up -d
```

(Requires JDK 21 + `sbt` locally. Replace `0.2.0-SNAPSHOT` with whatever `sbt-dynver` reports if
your `main` is ahead of the last tag.)

Re-export your shell vars from Step 4 if you opened a new terminal:

```bash
export AEGIS=http://localhost:8080
export USER_HEADER="X-Aegis-User: alice"
```

---

## Step 15 — Trigger a rate-spike anomaly

This is what makes Aegis-KMS different from AWS KMS or Vault: every request is **scored** against
the actor's behavioural baseline, and the auto-responder can **revoke the key in real time** when
the score crosses a threshold. You'll trip the `RateSpike` detector by signing 100 messages in 60
seconds, then watch Aegis revoke the key on its own.

First, create a fresh, activated key for the demo:

```bash
WEDGE_ID=$(curl -s -X POST "$AEGIS/v1/keys" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d '{"spec":{"name":"wedge-demo","algorithm":"RSA","sizeBits":2048,"objectType":"PrivateKey"}}' \
  | jq -r '.id')
curl -s -X POST "$AEGIS/v1/keys/$WEDGE_ID/activate" -H "$USER_HEADER" > /dev/null
echo "WEDGE_ID=$WEDGE_ID — ready to fire"
```

Now sign 100 messages as fast as `curl` can issue them — this exceeds the default 30-requests-in-60s
rate-spike threshold by 3×, which is the boundary at which the detector escalates to **High
severity**:

```bash
MSG_B64=$(echo -n 'spike' | base64)

for i in $(seq 1 100); do
  curl -s -o /dev/null -X POST "$AEGIS/v1/keys/$WEDGE_ID/sign" \
    -H "$USER_HEADER" -H "Content-Type: application/json" \
    -d "{\"messageBase64\":\"$MSG_B64\",\"algorithm\":\"RsaPssSha256\"}"
done
echo "fired 100 sign requests"
```

Now look at your log-tail terminal. Scroll back through the burst and you'll see two new things
in the audit rows that weren't there in Step 7:

```
{"ts":"...","actor":"alice","op":"Sign","keyId":"...","outcome":"Success",
 "context":{
   "risk.score":"0.13",
   "risk.factors":"RateSpike:0.13"
 }}
```

`risk.score` is the per-request risk roll-up in `[0.0, 1.0]`. `risk.factors` is the list of
detectors that fired, each with its contribution. As you sign more messages in the window, the
score climbs.

---

## Step 16 — Watch the auto-responder revoke the key

Once the rate factor reaches 3× the threshold (≥ 90 requests in 60s), the `BaselineDetector`
emits a `High` severity `RateSpike` recommendation, and the **AutoResponder** matches its default
rule (`RateSpike + High → Revoke`) and revokes the key. Grep your log for the system-actor audit
row:

```bash
docker compose -f deploy/docker/docker-compose.yml logs aegis-server \
  | grep '"principal":{"subject":"aegis-system"'
```

Expected output:

```
{"ts":"...","principal":{"subject":"aegis-system","kind":"Service"},
 "operation":"Revoke","resource":"key:8a3f1e25-...",
 "outcome":"AnomalyAlert(detector=RateSpike, severity=High, rec=<uuid>, action=Revoke) Success revoked key=8a3f1e25-...",
 "context":{
   "auto.response.rule":"RateSpike:High:Revoke",
   "auto.response.actor":"alice",
   "auto.response.recId":"<uuid>",
   "auto.response.detectorMsg":"100 requests in 60s (threshold=30)"
 }}
```

A few things to notice in this row:

- `principal.subject = "aegis-system"` — Aegis revoked the key under its own identity, not under
  yours. This is greppable for operators reviewing what the responder did.
- `operation = "Revoke"` — the actual KMIP operation that was performed.
- `outcome` starts with `AnomalyAlert(...)` — a structured marker SIEM systems can route on.
- `context.auto.response.actor = "alice"` — the offending actor whose behaviour tripped the rule.
- The whole row is in the same audit stream as your manual `Sign` calls, so a SIEM ingesting
  Aegis's audit log sees the alert and the response in the same timeline.

Try to sign once more with the now-revoked key:

```bash
curl -s -X POST "$AEGIS/v1/keys/$WEDGE_ID/sign" \
  -H "$USER_HEADER" -H "Content-Type: application/json" \
  -d "{\"messageBase64\":\"$MSG_B64\",\"algorithm\":\"RsaPssSha256\"}" | jq
```

Expected output:

```json
{ "error": "IllegalOperation", "message": "Key 8a3f1e25-... is Deactivated" }
```

That's the full wedge demo: behavioural baseline → risk score → decision → audit → auto-action,
all in one local docker-compose stack, no external dependencies, no AI required.

---

## Step 17 — See the risk-decision behaviour directly

You don't have to wait for a rate-spike to see the decision adapter at work. The decision
adapter has two thresholds: requests scoring `≥ 0.60` get `StepUp` (HTTP 401) and requests
scoring `≥ 0.85` get `Deny` (HTTP 403, error code `PermissionDenied` with a `"risk: …"` prefix
in the message).

Watch the Prometheus error counter increment for the auto-responder-driven denials:

```bash
curl -s http://localhost:8080/metrics | grep '^aegis_keys_op_errors_total'
```

Expected output (after running the wedge demo above):

```
aegis_keys_op_errors_total{operation="Sign",code="IllegalOperation"} 1.0
aegis_keys_op_errors_total{operation="Sign",code="PermissionDenied"} 0.0
```

The `PermissionDenied` counter will be non-zero on this label once you exercise a request that
the **decision adapter** (not the post-revoke `IllegalOperation`) blocks. Try a fresh actor on
many fresh keys to score high without burst:

```bash
# Burst a different actor against many keys — trips ScopeBaseline + RateSpike together
for i in $(seq 1 50); do
  KID=$(curl -s -X POST "$AEGIS/v1/keys" \
    -H "X-Aegis-User: stranger-$i" -H "Content-Type: application/json" \
    -d "{\"spec\":{\"name\":\"k$i\",\"algorithm\":\"AES\",\"sizeBits\":256,\"objectType\":\"SymmetricKey\"}}" \
    | jq -r '.id')
  curl -s -X POST "$AEGIS/v1/keys/$KID/activate" -H "X-Aegis-User: stranger-$i" > /dev/null
done
curl -s http://localhost:8080/metrics | grep '^aegis_keys_op_errors_total'
```

The full Prometheus / OTel / metrics tour is in
[Operations → Observability](../operations/observability.md).

---

## Step 18 — Stop the server

```bash
docker compose -f deploy/docker/docker-compose.yml down
```

This stops both containers. Add `-v` to also remove the Postgres volume (deletes all keys):

```bash
docker compose -f deploy/docker/docker-compose.yml down -v
```

---

## What you just did

In ~15 minutes you:

- Booted Aegis-KMS with a Postgres event journal
- Created a key (in safe `PreActive` state by default)
- Activated the key (explicit transition)
- Signed a message with RSA-PSS-SHA-256 + verified (and saw tamper detection work)
- Encrypted with an `EncryptionContext` AAD + saw context-mismatch refusal
- Wrapped + unwrapped a 256-bit DEK (envelope encryption)
- Rotated the key and confirmed the prior signature still validates
- Marked the key as `Compromised` and saw every subsequent crypto op refuse
- Opened the Swagger UI, scraped `/metrics`, watched audit rows on stdout in real time
- **Tripped the `RateSpike` anomaly detector and watched Aegis auto-revoke the offending key —
  the wedge demo that distinguishes Aegis from every role-centric KMS**

Every operation was attributed to a principal (`alice`, `stranger-N`, or the system actor
`aegis-system`), scored against a behavioural baseline, gated by the risk decision adapter,
recorded in the audit journal with `risk.score` + `outcome.decision` context, exposed as a
Prometheus metric on `/metrics`, and traced as an OpenTelemetry span (when an OTel exporter is
wired in).

## Where to next

<div class="grid cards" markdown>

-   :material-walk: **Want the full hands-on tour?**

    The [Usage Walkthrough](../USAGE.md) is the same flow extended to 20 steps:
    encrypt + decrypt with EncryptionContext, wrap + unwrap a DEK, rotate, mark as
    compromised, inspect the audit log + Prometheus + Jaeger, switch to JWT auth, and
    configure AWS KMS as the Root of Trust.

-   :material-book-open-variant: **Want to understand how it works?**

    [Architecture](../ARCHITECTURE.md) covers the decorator stack, the actor model, the
    two-tier module split, and the request lifecycle end-to-end.

-   :material-code-tags: **Want to embed Aegis in your JVM app?**

    Library jars on Maven Central are coming in v0.1.2. For now, see
    [Developer Guide → Quickstart](../development/developer-guide.md#2-first-build) to
    `sbt publishLocal` from source.

-   :material-account-tie: **Want to compare to AWS KMS / Vault / OpenBao?**

    [Comparison](../about/comparison.md) — including a clear *"do not pick Aegis if…"*
    section.

</div>
