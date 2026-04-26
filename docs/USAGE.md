# Using Aegis-KMS

End-to-end walkthroughs for the four audiences Aegis-KMS is built for. Pick the one that matches how you'll consume the KMS. Architecture context lives in [ARCHITECTURE.md](ARCHITECTURE.md); this document is about *using* the system.

> **Status note.** Aegis-KMS is pre-alpha. Some commands and SDK methods below describe the system as designed; see [ARCHITECTURE.md §11 Status](ARCHITECTURE.md#11-status) for what's implemented today.

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

Sign:

```bash
curl -X POST $AEGIS_URL/v1/keys/<id>/sign \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"<base64>","algorithm":"ECDSA-SHA256"}'
```

Encrypt:

```bash
curl -X POST $AEGIS_URL/v1/keys/<id>/encrypt \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"<base64>","aad":"<base64-optional>"}'
```

Generate a data key (envelope encryption — see §5.1):

```bash
curl -X POST $AEGIS_URL/v1/keys/<id>/generate-data-key \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keySpec":"AES_256"}'
# returns both plaintext and ciphertext of a fresh DEK
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

Rotation is a server-side concern. Once a `RotationPolicy` is set, Aegis-KMS creates a new version of the key on schedule. Old versions stay legal for `Verify` and `Decrypt` so existing ciphertexts and signatures keep working. Your application code does not change.

You can also rotate manually:

```bash
curl -X POST $AEGIS_URL/v1/keys/<id>/rotate \
  -H "Authorization: Bearer $AEGIS_TOKEN"
```

### 1.8 Decommission

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

```bash
aegis key create invoice-signing --spec ec-p256 --usage sign,verify --rotate-every 90d
aegis key activate <id>
aegis key list --state Active
aegis key get <id>                    # full detail incl. version history
aegis key rotate <id>
aegis key deactivate <id>
aegis key destroy <id>
```

### 2.3 Policy

```bash
aegis policy show <role>
aegis policy attach <role> --key <id> --ops sign,verify
aegis policy detach <role> --key <id>
```

### 2.4 Audit

```bash
aegis audit --actor alice@org --since 24h
aegis audit --resource <key-id> --since 7d
aegis audit --action KeyDestroyed --since 30d
aegis audit --agent <agent-sub> --include-parent       # all of an agent's actions, with parent human resolved
aegis audit --outcome Denied --since 24h               # who tried what they shouldn't have
```

### 2.5 Agent credentials

```bash
aegis agent issue \
  --parent alice@org \
  --scopes "key:<id>:sign,key:<id>:verify" \
  --ttl 1h
# returns a JWT
```

Issued JWTs are minted by the IAM module, signed with a dedicated agent-signing key (separate from any managed key), and tied to `alice@org` as parent. Revocation is immediate via `aegis agent revoke <jti>`.

### 2.6 Backup and disaster recovery

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
| `rotate`    | State change + audit | `key:<id>:rotate` (typically operator-only) |
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

Encrypt large data with a per-message DEK; encrypt the DEK with a long-lived KEK in Aegis-KMS. Cheap to rotate KEKs; cheap to encrypt large payloads.

```scala
for
  // ask Aegis for a fresh DEK, returns plaintext + ciphertext form
  dek      <- client.keys.generateDataKey(kekId, KeySpec.aes256)
  cipher   =  AesGcm.encrypt(dek.plaintext, payload)
  // store cipher + dek.ciphertext side by side; throw away dek.plaintext
  _        <- IO(zero(dek.plaintext))
yield (cipher, dek.ciphertext)

// later, to read:
for
  plain    <- client.keys.decrypt(kekId, dek.ciphertext)   // unwrap DEK
  payload  =  AesGcm.decrypt(plain, cipher)
yield payload
```

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
| `aegis backup restore` fails with `RootOfTrustMismatch` | Target deployment's RoT differs from backup's | Configure the target with the same RoT, or use a recovery KEK pre-shared at backup time |
| Audit log missing recent entries | Audit sink unavailable; events queued as `PendingAuditDelivery` | Check `aegis audit health`; the sweeper will deliver once the sink is reachable |

For deeper debugging, every request carries an `X-Request-Id` (or KMIP `Unique Identifier`) that joins the structured operational log line, the audit event, and any client-side trace into one timeline. Quote it in support tickets.

---

## See also

- [README](../README.md) — overview, quickstarts, comparison table.
- [ARCHITECTURE.md](ARCHITECTURE.md) — module layout, wire planes, key lifecycle, audit model, security model.
- [Animated walkthrough](https://sharma-bhaskar.github.io/aegis-kms/architecture.html) — interactive request lifecycle.
