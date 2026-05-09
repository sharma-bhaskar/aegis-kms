# Quickstart

**Goal:** in ~5 minutes, get Aegis-KMS running on your machine and use it to sign + verify a
message. Step 0 → Step 9, every command runnable, every output shown.

For a deeper hands-on tour covering every operation (encrypt, decrypt, wrap, unwrap, rotate,
compromise, audit log, metrics, traces, CLI, JWT, AWS KMS), see the
[full walkthrough](../USAGE.md) (~20 minutes).

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

## Step 9 — Stop the server

```bash
docker compose -f deploy/docker/docker-compose.yml down
```

This stops both containers. Add `-v` to also remove the Postgres volume (deletes all keys):

```bash
docker compose -f deploy/docker/docker-compose.yml down -v
```

---

## What you just did

In ~5 minutes you:

- Booted Aegis-KMS with a Postgres event journal
- Created a key (in safe `PreActive` state by default)
- Activated the key (explicit transition)
- Signed a message with RSA-PSS-SHA-256
- Verified the signature (and saw the tamper detection work)
- Watched audit rows land on stdout in real time

Every operation was attributed to `alice` (the principal you passed via `X-Aegis-User`),
recorded in the audit journal, exposed as a Prometheus metric on `/metrics`, and traced as
an OpenTelemetry span (when an OTel exporter is wired in).

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
