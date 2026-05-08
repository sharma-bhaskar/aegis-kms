# Using Aegis-KMS

End-to-end walkthroughs for the four audiences Aegis-KMS is built for. Pick the one that matches how you'll consume the KMS. Architecture context lives in [ARCHITECTURE.md](ARCHITECTURE.md); this document is about *using* the system.

> **Status note.** Aegis-KMS is pre-alpha. As of v0.1.1 the full key-lifecycle + crypto surface is real:
> create / activate / destroy, sign / verify, encrypt / decrypt, wrap / unwrap, rotate, compromise — all
> wired through REST and the `aegis` CLI. Sections marked 🚧 below describe v0.2.0+ design previews
> (`aegis policy`, `aegis audit tail`, `aegis agent issue`, KMIP, MCP, backup/restore, JWK publication).
> See [ARCHITECTURE.md §11 Status](ARCHITECTURE.md#11-status) for the canonical status table.

---

## Contents

1. [App developer — REST + SDK](#1-app-developer--rest--sdk)
2. [Operator — `aegis-cli`](#2-operator--aegis-cli)
3. [AI agent — MCP](#3-ai-agent--mcp)
4. [Storage / database / backup vendor — KMIP](#4-storage--database--backup-vendor--kmip)
5. [Common patterns](#5-common-patterns)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. App developer — REST + SDK

You have an application that needs to sign payloads, encrypt secrets at rest, or manage envelope-encrypted data, and you want a managed key with rotation, audit, and policy handled for you.

### 1.1 Authentication

Aegis-KMS verifies OIDC bearer tokens issued by your organization's existing identity provider. Any RFC 7523-compliant IdP works:

- Okta, Auth0, Google Workspace, Microsoft Entra (Azure AD)
- AWS IAM Identity Center / Cognito
- Keycloak, Authentik, Authelia (self-hosted)
- GitHub, GitLab (for CI workloads)

Service accounts use the standard client-credentials flow; humans use authorization-code (with PKCE) or device-code. Aegis-KMS is the **resource server**; it does not issue user tokens itself. The only tokens it issues are short-lived **agent JWTs** (see §3).

```bash
export AEGIS_URL=https://aegis.your-org.internal
export AEGIS_TOKEN=$(your-oidc-flow)              # or a CI workload identity token
```

### 1.2 Create a key

```bash
curl -X POST $AEGIS_URL/v1/keys \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "alias": "invoice-signing",
    "spec": {
      "algorithm": "EC",
      "curve":     "P-256",
      "usage":     ["Sign", "Verify"]
    },
    "rotation": { "policy": "time", "every": "P90D" }
  }'
```

The response includes the new `KeyId` and the initial state (`PreActive`). Supported specs:

| `algorithm` | Variants | Typical use |
| --- | --- | --- |
| `AES` | 128, 192, 256 | Symmetric encrypt/decrypt, AEAD, envelope DEKs |
| `RSA` | 2048, 3072, 4096 | Wrap/unwrap, sign/verify |
| `EC`  | `P-256`, `P-384`, `P-521`, `secp256k1` | Sign/verify, ECDH |
| `EdDSA` | `Ed25519`, `Ed448` | Sign/verify |
| `HMAC` | 256, 384, 512 | MAC, JWT signing (HS*) |

### 1.3 Activate

A key starts in `PreActive` so a policy engine, auditor, or human operator has a chance to review before it goes live. Activation is a separate explicit transition.

```bash
curl -X POST $AEGIS_URL/v1/keys/<id>/activate \
  -H "Authorization: Bearer $AEGIS_TOKEN"
```

### 1.4 Use

The seven cryptographic operations on `/v1/keys/{id}/{op}` all share the auth + error shape; only the
request/response bodies differ. State gates: `sign` / `encrypt` / `wrap` require `Active`; `verify` /
`decrypt` / `unwrap` are permitted on `Active` and `Deactivated` (so material produced before a rotation
remains readable); `Compromised` and `Destroyed` refuse every op.

**Sign / verify** — `RsaPssSha256` and `EcdsaSha256` ship in v0.1.1.

```bash
curl -X POST $AEGIS_URL/v1/keys/<id>/sign \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{"messageBase64":"<base64>","algorithm":"RsaPssSha256"}'
# → {"signatureBase64":"...","algorithm":"RsaPssSha256"}

curl -X POST $AEGIS_URL/v1/keys/<id>/verify \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{"messageBase64":"...","signatureBase64":"...","algorithm":"RsaPssSha256"}'
# → {"valid":true,"algorithm":"RsaPssSha256"}     (200 even when valid:false)
```

**Encrypt / decrypt** — the `context` map is bound as additional authenticated data (AAD), mirroring AWS
KMS's `EncryptionContext`. The same context must be supplied to `decrypt`; a mismatch returns
`CryptographicFailure`.

```bash
curl -X POST $AEGIS_URL/v1/keys/<id>/encrypt \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{"plaintextBase64":"<base64>","context":{"dataset":"q2","tenant":"acme"}}'
# → {"ciphertextBase64":"...","context":{...}}

curl -X POST $AEGIS_URL/v1/keys/<id>/decrypt \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{"ciphertextBase64":"...","context":{"dataset":"q2","tenant":"acme"}}'
# → {"plaintextBase64":"...","context":{...}}
```

**Wrap / unwrap** — KMIP-style envelope encryption of a Data Encryption Key (DEK). No AAD; see §5.1 for the
typical pattern.

```bash
curl -X POST $AEGIS_URL/v1/keys/<id>/wrap \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{"dekBase64":"<base64>"}'
# → {"wrappedDekBase64":"..."}

curl -X POST $AEGIS_URL/v1/keys/<id>/unwrap \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{"wrappedDekBase64":"..."}'
# → {"dekBase64":"..."}
```

### 1.5 SDK — Scala

```scala
import cats.effect.IO
import dev.aegiskms.sdk.{AegisClient, AegisConfig}
import dev.aegiskms.core.{KeySpec, RotationPolicy}

val client = AegisClient[IO](
  AegisConfig(
    url   = "https://aegis.your-org.internal",
    token = sys.env("AEGIS_TOKEN")
  )
)

val program: IO[Array[Byte]] =
  for
    k   <- client.keys.create(
             KeySpec.ec256("invoice-signing"),
             rotation = RotationPolicy.everyDays(90)
           )
    _   <- client.keys.activate(k.id)
    sig <- client.keys.sign(k.id, message = invoicePayload)
  yield sig
```

### 1.6 SDK — Java

```java
import dev.aegiskms.sdk.AegisClient;
import dev.aegiskms.sdk.AegisConfig;
import dev.aegiskms.core.KeySpec;

AegisClient client = AegisClient.create(
    AegisConfig.builder()
        .url("https://aegis.your-org.internal")
        .token(System.getenv("AEGIS_TOKEN"))
        .build()
);

var key = client.keys().create(KeySpec.ec256("invoice-signing")).join();
client.keys().activate(key.id()).join();
byte[] signature = client.keys().sign(key.id(), payload).join();
```

### 1.7 Rotation

Rotation is a server-side concern. Old versions stay legal for `Verify` and `Decrypt` so existing
ciphertexts and signatures keep working — your application code does not change. The legal source state
is `Active` only. Manual rotation:

```bash
curl -X POST $AEGIS_URL/v1/keys/<id>/rotate \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{"policy":"Manual"}'
# → ManagedKey with currentVersion bumped by one
```

The `policy` value is recorded on the rotation event and audit row. Accepted shapes: `"Manual"`,
`"TimeBased:7days"`, `"OpCountBased:10000"`. The auto-scheduler driven by the `TimeBased` /
`OpCountBased` variants lands in v0.2.0 — explicit calls today should pass `"Manual"`.

### 1.8 Compromise (operator override)

A discovered key compromise needs to be locked down faster than the normal deactivate flow. `compromise`
is a one-way transition that refuses every cryptographic operation thereafter — `sign`, `verify`,
`encrypt`, `decrypt`, `wrap`, and `unwrap` all return `IllegalOperation`. Legal from `PreActive`,
`Active`, or `Deactivated`; `Destroyed` is refused.

```bash
curl -X POST $AEGIS_URL/v1/keys/<id>/compromise \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{"reason":"discovered in S3 audit leak 2026-05-08"}'
# → ManagedKey with state=Compromised
```

The `reason` is mandatory and non-empty (a blank justification is rejected with `400 InvalidField`); it
ends up on the audit row at `severity=Critical` so SIEM ingestion can route on it.

### 1.9 Decommission

```bash
# stop accepting new ops (verify/decrypt still work)
curl -X POST $AEGIS_URL/v1/keys/<id>/deactivate -H "Authorization: Bearer $AEGIS_TOKEN"

# terminal — destroys wrapped material; audit row preserved forever
curl -X POST $AEGIS_URL/v1/keys/<id>/destroy -H "Authorization: Bearer $AEGIS_TOKEN"
```

---

## 2. Operator — `aegis-cli`

Day-to-day key management without writing code. Built on `aegis-sdk-scala`, so anything the CLI does is also available programmatically.

### 2.1 Login

```bash
aegis login                          # OIDC device-code flow against your IdP
aegis whoami                         # confirm identity and roles
aegis context use prod               # switch between configured deployments
```

Configuration lives at `~/.aegis/config.toml`:

```toml
[contexts.prod]
url       = "https://aegis.prod.your-org.internal"
issuer    = "https://auth.your-org.internal"
client_id = "aegis-cli"

[contexts.dev]
url       = "http://localhost:8080"
issuer    = "http://localhost:8081"
client_id = "aegis-cli-dev"
```

### 2.2 Key lifecycle

The verbs that ship today (v0.1.1) — note `aegis keys` is plural:

```bash
aegis keys create --alg AES-256 --name invoice-signing
aegis keys get <id>
aegis keys activate <id>
aegis keys rotate --id <id>                                 # bumps currentVersion
aegis keys rotate --id <id> --policy TimeBased:7days        # records the policy
aegis keys compromise --id <id> --reason "leaked in S3"     # lockdown override
aegis keys destroy <id>
```

### 2.3 Crypto operations

```bash
aegis keys sign     --id <id> --message "hello"   [--alg RsaPssSha256]
aegis keys sign     --id <id> --message @file.bin                       # @-prefix reads from disk
aegis keys verify   --id <id> --message "hello" --signature <b64>  [--alg RsaPssSha256]
aegis keys encrypt  --id <id> --plaintext "secret"  [--context dataset=q2,tenant=acme]
aegis keys decrypt  --id <id> --ciphertext <b64>    [--context dataset=q2,tenant=acme]
aegis keys wrap     --id <id> --dek @raw-dek.bin
aegis keys unwrap   --id <id> --wrapped <b64>
```

Exit codes follow `kubectl` conventions: `0` success, `3` `valid:false` from `verify`, `4`
`ItemNotFound`, `5` `PermissionDenied`, `1` everything else.

### 2.4 Policy 🚧

> **Design preview.** The `aegis policy` verbs are planned for v0.2.0. Today policy is configured at boot
> via the IAM allowlist — see `RoleBasedPolicyEngine` and the role mapping in `aegis-server`.

```bash
aegis policy show <role>
aegis policy attach <role> --key <id> --ops sign,verify
aegis policy detach <role> --key <id>
```

### 2.5 Audit 🚧

> **Design preview.** `aegis audit tail` and the query API land in v0.2.0 (PR F2.b). Until then the audit
> feed is whatever the configured `AuditSink` writes — stdout in v0.1.1.

```bash
aegis audit --actor alice@org --since 24h
aegis audit --resource <key-id> --since 7d
aegis audit --action KeyDestroyed --since 30d
aegis audit --agent <agent-sub> --include-parent       # all of an agent's actions, with parent human resolved
aegis audit --outcome Denied --since 24h               # who tried what they shouldn't have
```

### 2.6 Agent credentials 🚧

> **Design preview.** `aegis agent issue` lands in v0.2.0 (PR A1) when the issuance HTTP endpoint exists.
> v0.1.1 ships the `JwtIssuer` plumbing but not the operator surface.

```bash
aegis agent issue \
  --parent alice@org \
  --scopes "key:<id>:sign,key:<id>:verify" \
  --ttl 1h
# returns a JWT
```

Issued JWTs are minted by the IAM module, signed with a dedicated agent-signing key (separate from any managed key), and tied to `alice@org` as parent. Revocation is immediate via `aegis agent revoke <jti>`.

### 2.7 Backup and disaster recovery 🚧

```bash
aegis backup create --output kms-backup-$(date +%F).enc      # wraps DB + audit log
aegis backup verify kms-backup-2026-04-26.enc
aegis backup restore kms-backup-2026-04-26.enc --to <new-deployment>
```

Backups are encrypted under the configured Root of Trust. Restoring requires access to the same RoT (or a recovery KEK pre-shared at backup time).

---

## 3. AI agent — MCP

You want Claude, GPT, or another MCP-aware agent to use Aegis-KMS as a tool, with credentials scoped to specific keys and operations and every action linked back to a real human in the audit log.

### 3.1 The model

- **Identity.** Every agent action carries a `Principal.Agent(sub, parentHuman, scopes)`. The `parentHuman` is the operator who issued the credential; it is mandatory. There is no anonymous agent identity.
- **Scope.** An agent's JWT names the exact keys, operations, and time window it is allowed to use. The IAM module enforces this on every call before `KeyService` runs.
- **Audit.** Every call records both the agent identity and the parent human. `aegis audit --actor alice@org` includes everything Alice's agents did.

### 3.2 Issue an agent credential

As an operator:

```bash
aegis agent issue \
  --parent alice@org \
  --scopes "key:k-invoice-2026:sign,key:k-invoice-2026:verify" \
  --ttl 1h
# eyJhbGciOi...
```

For unattended agents (CI, scheduled workers), use a longer TTL with an explicit revocation plan; for interactive Claude sessions, an hour is usually plenty.

### 3.3 Configure the MCP client

**Claude Desktop** (`claude_desktop_config.json`):

```jsonc
{
  "mcpServers": {
    "aegis-kms": {
      "command": "aegis-mcp-bridge",
      "args": [
        "--url",       "https://aegis.your-org.internal",
        "--token-env", "AEGIS_AGENT_JWT"
      ]
    }
  }
}
```

**HTTP/SSE-mode hosts** (Cursor, custom MCP clients):

```yaml
servers:
  aegis-kms:
    transport: sse
    endpoint: https://aegis.your-org.internal/mcp
    headers:
      Authorization: Bearer ${AEGIS_AGENT_JWT}
```

### 3.4 Tools the agent sees

The MCP server publishes a curated tool set. Each tool is annotated with the permissions it requires and the side effects it produces, so MCP host UIs (e.g. Claude's tool-use approval prompt) can surface the impact to the operator before allowing the call.

| Tool | Effect | Requires scope |
| --- | --- | --- |
| `list_keys` | Read | `key:*:read` |
| `get_key`   | Read | `key:<id>:read` |
| `create_key` | State change + audit | `key:create` (often gated) |
| `sign`      | Crypto op + audit | `key:<id>:sign` |
| `verify`    | Crypto op + audit | `key:<id>:verify` |
| `encrypt`   | Crypto op + audit | `key:<id>:encrypt` |
| `decrypt`   | Crypto op + audit | `key:<id>:decrypt` |
| `wrap`      | Crypto op + audit | `key:<id>:wrap` |
| `unwrap`    | Crypto op + audit | `key:<id>:unwrap` |
| `rotate`    | State change + audit | `key:<id>:rotate` (typically operator-only) |
| `compromise` | State change + Critical-severity audit | `key:<id>:compromise` (operator-only — agents should never have this) |
| `audit_query` | Read audit log | `audit:read` (often denied to agents) |

Calls outside the agent's scope return a hard `403 AccessDenied`. The LLM sees a structured error; the audit log records `outcome=Denied`.

### 3.5 Worked example

The operator gives Claude an hour-long credential to sign exactly one set of keys. Claude is asked to sign 50 invoices. Each `sign` call:

1. arrives over MCP with the agent JWT,
2. is authenticated and scope-checked by IAM,
3. runs through the same `KeyService.sign` path as any REST call,
4. produces a `KeyUsed` audit event with `actor=Principal.Agent(claude-session-…, alice@org, [...])`.

The next morning Alice runs `aegis audit --actor alice@org --since 24h --include-agents` and sees all 50 entries grouped under her identity.

---

## 4. Storage / database / backup vendor — KMIP

Your existing product already speaks KMIP. Aegis-KMS replaces a proprietary KMS (Vault Enterprise, Thales CipherTrust, Gemalto SafeNet, Townsend Alliance Key Manager, Fortanix DSM) with no application code changes on your side.

### 4.1 Connection profile

```
Host:      aegis.your-org.internal
Port:      5696                (the IANA-registered KMIP port)
TLS:       1.3 only, mTLS required
Versions:  KMIP 1.4 / 2.0 / 2.1 / 2.2 / 3.0 (auto-negotiated)
Encoding:  TTLV (binary), JSON variant available on request
```

### 4.2 Provision the client cert

```bash
aegis cert issue \
  --cn   netapp-cluster-1 \
  --san  10.0.5.10 \
  --role storage-encryption \
  --validity 365d \
  --output netapp-cluster-1.p12
```

The certificate is signed by the Aegis-KMS internal CA; its CN is the principal name and its `role` claim drives the IAM policy for KMIP requests.

### 4.3 Configure the appliance

The exact UI varies by vendor; the inputs are always the same:

| Vendor | Where |
| --- | --- |
| NetApp ONTAP | `security key-manager external add-servers ...` |
| Dell EMC PowerStore / Unity | Settings → Encryption → External Key Manager |
| Pure Storage FlashArray | Settings → Software → External Key Management |
| Oracle TDE | `ADMINISTER KEY MANAGEMENT SET ENCRYPTION KEY ... USING ALGORITHM AES256 IDENTIFIED BY EXTERNAL STORE;` with `WALLET_ROOT` pointing at the KMIP wallet |
| MSSQL EKM | Provider DLL configured against the KMIP server |
| MongoDB Enterprise | `kmip.serverName` / `kmip.serverCAFile` / `kmip.clientCertificateFile` |
| Veeam | Backup Infrastructure → Encryption Keys → KMS Server |
| Veritas NetBackup | KMS Configuration → External KMS |

### 4.4 KMIP operations supported

```
Discover Versions       Create                  Encrypt
Query                   Create Key Pair         Decrypt
Locate                  Register                Sign
Get                     Rekey                   Signature Verify
Get Attributes          Activate                MAC
Add Attribute           Revoke                  MAC Verify
Modify Attribute        Destroy                 RNG Retrieve
Delete Attribute        Archive
                        Recover
```

### 4.5 Verify

```bash
aegis kmip ping                                  # discovers versions
aegis kmip locate --by alias=netapp-vol-key      # confirms a key is present
aegis kmip stats                                 # request rate, version negotiation, error breakdown
```

---

## 5. Common patterns

### 5.1 Envelope encryption

Encrypt large data with a per-message DEK; wrap the DEK under a long-lived KEK in Aegis-KMS. Cheap to
rotate KEKs; cheap to encrypt large payloads. The `wrap` / `unwrap` operations shipped in v0.1.1 are the
primitive — generate the DEK on the client side (any CSPRNG), use it inline for the bulk encryption, then
`wrap` it for storage. (A server-side `generateDataKey` that returns plaintext + wrapped form together is
a v0.2.0 follow-up — until then, generating the DEK locally is one extra call.)

```scala
for
  dek      <- IO(SecureRandom.getInstanceStrong.generateSeed(32))   // fresh 256-bit DEK
  cipher    = AesGcm.encrypt(dek, payload)
  wrapped  <- client.keys.wrap(kekId, dek)                          // KEK protects the DEK
  _         = java.util.Arrays.fill(dek, 0.toByte)                  // wipe plaintext DEK
yield (cipher, wrapped)

// later, to read:
for
  dek      <- client.keys.unwrap(kekId, wrapped)
  payload   = AesGcm.decrypt(dek, cipher)
  _         = java.util.Arrays.fill(dek, 0.toByte)
yield payload
```

If your data is small (≤4 KB on the AWS-backed deployment), skip the envelope and use `encrypt` /
`decrypt` directly with an `EncryptionContext`-bound AAD — see §1.4.

### 5.2 JWT signing with HS*/RS*/EdDSA keys

```bash
# create an Ed25519 key for OIDC token signing
aegis key create oidc-signing --spec ed25519 --usage sign,verify
aegis key activate <id>

# expose the public JWK for token verifiers
curl $AEGIS_URL/v1/keys/<id>/public-jwk -H "Authorization: Bearer $AEGIS_TOKEN"
```

Your token issuer signs JWTs by calling `sign`; relying parties pull the public JWK at `/.well-known/jwks.json` (proxied from Aegis-KMS).

### 5.3 Database TDE master key

For Postgres, MySQL, MongoDB, etc., the master encryption key lives in Aegis-KMS over KMIP; DEKs (per-tablespace, per-database, per-collection) are managed by the database itself, wrapped under the KMIP key. Rotating the master key is an Aegis-KMS operation; the database rewraps DEKs without re-encrypting data.

### 5.4 TLS termination keys

```bash
aegis key create tls-edge-2026 --spec rsa-3072 --usage sign,verify
# get a CSR signed by your CA, mount the public cert at the proxy
# the private key never leaves Aegis-KMS — sign-as-a-service
```

Your edge proxy (Envoy, HAProxy, NGINX with `ngx_http_ssl_module` + a delegate plugin) calls `sign` for the TLS handshake. The private key is never on disk at the edge.

### 5.5 BYOK / customer-managed keys

```bash
# customer wraps their key under your import wrapping key
curl $AEGIS_URL/v1/import-wrapping-keys/<scheme>/public-key -o wrap.pub

# customer wraps:
openssl pkeyutl -encrypt -inkey wrap.pub -pubin -in customer-key.bin -out wrapped.bin

# operator imports:
aegis key import \
  --alias       customer-acme-key \
  --wrapped     wrapped.bin \
  --wrap-scheme RSA-OAEP-SHA256 \
  --usage       encrypt,decrypt
```

The wrapping key pair is generated inside the Root of Trust; only the public half ever leaves the KMS, so the customer's plaintext key never transits in clear.

---

## 6. Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `401 InvalidToken` from REST | OIDC issuer mismatch or expired token | `aegis whoami`; re-run your IdP flow |
| `403 AccessDenied` on a `sign` call | IAM policy doesn't grant `key:<id>:sign` to the principal | `aegis policy show <role>`; attach if appropriate |
| KMIP client can't connect | Wrong port (5696), TLS 1.2 only, or client cert not trusted | `openssl s_client -connect aegis...:5696 -tls1_3`; check `aegis cert list` |
| KMIP client sees `Permission Denied` on `Encrypt` | Cert's `role` claim doesn't allow this operation | `aegis cert get <fingerprint>`; reissue with the right role |
| MCP agent gets `Tool denied` | Scope on the agent JWT doesn't include the requested op | `aegis agent inspect <jti>`; reissue with broader scope or narrower task |
| `KeyState: Deactivated` rejecting `sign` | Key is verify-only after a rotation or manual deactivate | Use the new active version, or reactivate (if policy allows) |
| `IllegalOperation: Key is Compromised` on **any** crypto op | Operator ran `aegis keys compromise --id <id>` | One-way state. Check the audit row at `severity=Critical` for the reason; rotate the upstream consumers off this key. |
| `CryptographicFailure: encryption-context mismatch` on `decrypt` | Different `context` map than the one used at `encrypt` time | The map values must match exactly; this is AAD, not advisory metadata. |
| `aegis backup restore` fails with `RootOfTrustMismatch` | Target deployment's RoT differs from backup's | Configure the target with the same RoT, or use a recovery KEK pre-shared at backup time |
| Audit log missing recent entries | Audit sink unavailable; events queued as `PendingAuditDelivery` | Check `aegis audit health`; the sweeper will deliver once the sink is reachable |

For deeper debugging, every request carries an `X-Request-Id` (or KMIP `Unique Identifier`) that joins the structured operational log line, the audit event, and any client-side trace into one timeline. Quote it in support tickets.

---

## See also

- [README](../README.md) — overview, quickstarts, comparison table.
- [ARCHITECTURE.md](ARCHITECTURE.md) — module layout, wire planes, key lifecycle, audit model, security model.
- [Animated walkthrough](https://sharma-bhaskar.github.io/aegis-kms/architecture.html) — interactive request lifecycle.
