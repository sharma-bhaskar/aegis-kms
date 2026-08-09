# Kubernetes deployment

The Helm chart lives at `deploy/helm/aegis-kms`. It brings up `aegis-server`, optionally a Postgres
StatefulSet, and the Service / Ingress / PDB / HPA around them.

## Secure by default, which means it will not install blind

`helm install` with no values **fails on purpose**:

```
Error: postgres.auth.existingSecret is required — create it with
`kubectl create secret generic <name> --from-literal=postgres-password=...`.
The chart will not generate a database password that only Helm knows about.
```

That is the intended behaviour. The chart defaults to production-shaped settings — HMAC auth,
role-based policy, Postgres journal and audit, and `AEGIS_SECURITY_PREFLIGHT=enforce` — because a
Helm release is network-reachable by definition. A chart that installed cleanly with dev auth and
an allow-all policy would be handing you an open KMS.

**The chart never generates secrets.** A signing key that exists only in Helm release state is
invisible to your secret manager and silently rotates on re-install, which would invalidate every
agent token already issued.

## Install

```bash
kubectl create secret generic aegis-jwt \
  --from-literal=hmac-secret="$(openssl rand -base64 48)"

kubectl create secret generic aegis-pg \
  --from-literal=postgres-password="$(openssl rand -base64 32)"

helm install aegis deploy/helm/aegis-kms \
  --set aegis.auth.hmac.existingSecret=aegis-jwt \
  --set postgres.auth.existingSecret=aegis-pg \
  --set aegis.crypto.awsKms.region=eu-west-2 \
  --set aegis.crypto.awsKms.kekArn=arn:aws:kms:eu-west-2:123456789012:key/abcd-1234
```

Then:

```bash
kubectl rollout status deploy/aegis-aegis-kms
helm test aegis
```

`helm test` does more than check the port is open — it asserts `/metrics` returns Prometheus
exposition including JVM metrics, which only happens once the HTTP plane and meter registry are
genuinely up.

## Evaluation cluster

`values-dev.yaml` trades safety for convenience — dev auth, dev policy, software root of trust,
`preflight=warn`:

```bash
kubectl create secret generic aegis-pg --from-literal=postgres-password="$(openssl rand -base64 32)"
kubectl create secret generic aegis-keystore --from-literal=keystore-password="$(openssl rand -base64 24)"

helm install aegis deploy/helm/aegis-kms \
  -f deploy/helm/aegis-kms/values-dev.yaml \
  --set postgres.auth.existingSecret=aegis-pg
```

Note that even the dev profile keeps `audit.kind=postgres`. That is deliberate: the agent registry
(`GET /v1/agents`), the audit-read API, and the LLM advisor all ride on the `AuditQuery` SPI that
only the Postgres sink implements. A demo that silently answers `501` for those is not
demonstrating the product.

## Choosing a root of trust

| `aegis.crypto.kind` | Extra values required | Notes |
| --- | --- | --- |
| `aws-kms` | `awsKms.region`, `awsKms.kekArn` | Bind IAM via `serviceAccount.annotations` (IRSA) |
| `gcp-kms` | `gcpKms.{projectId,location,keyRing,cryptoKey}` | Bind via Workload Identity. Cloud KMS keys are single-purpose — set `gcpKms.signingKey` if you sign |
| `software` | `persistence.enabled=true`, `software.existingSecret` | Real crypto, but keys live in the pod's heap. Evaluation only |
| `in-memory` | — | Not cryptography. Rejected when `preflight=enforce` |

The chart refuses combinations the server would reject at boot, so you get a `helm install` error
with a fix in it rather than a `CrashLoopBackOff`:

- `auth.kind=dev` with `preflight=enforce`
- `crypto.kind=software` without `persistence.enabled` — a regenerated keystore makes everything
  wrapped by the previous key permanently unrecoverable
- `crypto.kind=in-memory` with `preflight=enforce`

## Production checklist

- **Use a managed database.** The in-chart Postgres is a single replica with no backups, no
  failover, and no PITR. Set `postgres.enabled=false` and point `postgres.external.*` at a real
  one — the event journal is the source of truth for every key Aegis manages.
- **Pin the image.** `image.tag` defaults to `main`, which moves. Pin a digest.
- **Terminate TLS.** Set `ingress.enabled=true` with a cert-manager cluster-issuer annotation.
  Serving a KMS over plaintext HTTP is not a supported configuration.
- **Leave `preflight: enforce` alone.** A crashed pod is cheaper than an open KMS.
- **Think before enabling `autoResponse.killFleet`.** One false positive revokes every agent
  credential under the offending agent's parent operator, with no human in the loop.

## Known gaps

- **Probes use `/metrics`.** Aegis has no dedicated health endpoint yet, so liveness and readiness
  both scrape `/metrics`. It is a true check that the HTTP plane is serving — the same binding —
  but heavier than a purpose-built `/healthz`, and it couples probe behaviour to the metrics route.
- **No NetworkPolicy.** The chart does not restrict pod-to-pod traffic; apply your own.
- **Single-region.** No multi-region or HA topology guidance yet — that is tracked for v1.0.0.
