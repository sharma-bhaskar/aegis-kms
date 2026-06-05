# Releasing Aegis-KMS

This is the operator runbook for cutting a tagged release. The `release.yml`
GitHub Actions workflow does the heavy lifting on every `v*` tag push:

1. CI gate (compile, scalafmt, scalafix, test) — same checks as the main
   branch CI.
2. Publish library jars to Maven Central (`dev.aegiskms %% aegis-core` and
   friends) via `sbt-ci-release`. Skipped automatically if the signing
   secrets aren't configured.
3. Publish the `aegis-server` Docker image to
   `ghcr.io/<owner>/aegis-server:<version>` using the built-in `GITHUB_TOKEN`.
4. Build the `aegis-cli` universal tarball and attach it to a GitHub Release.

The version number is derived by `sbt-dynver` from the tag — `v0.1.1` →
`0.1.1` for the artifacts. Don't add a `version :=` line to `build.sbt`;
that would override the derived value and ship every tag as
`0.1.0-SNAPSHOT`.

## One-time setup (you, the maintainer, must do this once)

The Docker + GitHub Release path runs out of the box on a fresh repository.
The Maven Central path requires four secrets that only you can set up.

### 1. Sonatype OSSRH account on `s01.oss.sonatype.org`

If `dev.aegiskms` is already provisioned, skip to step 2. If not:

1. Sign up at https://central.sonatype.com (or https://issues.sonatype.org
   for the legacy OSSRH JIRA flow if your namespace is on the older host).
2. Open a "New Project" ticket claiming the `dev.aegiskms` group ID. The
   reviewer will check that you control `aegiskms.dev` (DNS TXT verification)
   or the GitHub `sharma-bhaskar` namespace.
3. Once approved, generate a **user token** (NOT your account password) at
   https://central.sonatype.com/account → Tokens. The token's username and
   password are the values you'll set as GitHub Action secrets below.

### 2. GPG signing key

Maven Central rejects unsigned artifacts. `sbt-ci-release` expects the
private key as a base64-encoded blob in an env var.

```bash
# Generate a 4096-bit RSA key. Pick a passphrase you'll remember.
gpg --full-generate-key

# Find the key id (the long hex string) and publish the public half to a
# keyserver so verifiers can fetch it.
gpg --list-secret-keys --keyid-format LONG
gpg --keyserver keyserver.ubuntu.com   --send-keys <KEY_ID>
gpg --keyserver keys.openpgp.org       --send-keys <KEY_ID>
gpg --keyserver pgp.mit.edu            --send-keys <KEY_ID>

# Export the private key and base64-encode it (no line wrapping).
gpg --armor --export-secret-keys <KEY_ID> | base64 | pbcopy
```

Save the base64 blob; it goes into `PGP_SECRET` below.

### 3. GitHub Action secrets

In the GitHub repo, go to **Settings → Secrets and variables → Actions →
New repository secret** and add:

| Secret name | Value |
| --- | --- |
| `PGP_SECRET` | The base64 blob from step 2. |
| `PGP_PASSPHRASE` | The passphrase you chose for the GPG key. |
| `SONATYPE_USERNAME` | The user-token name from step 1. |
| `SONATYPE_PASSWORD` | The user-token value from step 1. |

The release workflow gates the Maven publish step on `PGP_SECRET != ''`; if
any of these are missing the workflow ships the Docker image + CLI tarball
only and adds a `::notice` to the run output instead of failing.

## Cutting a release

Once setup is done, releasing is one command per tag:

```bash
# 1. Update CHANGELOG: rename the `## Unreleased` section to `## 0.1.1 — YYYY-MM-DD`,
#    open a fresh `## Unreleased` block above it. Commit the change to main.

# 2. Tag and push. sbt-dynver reads the tag verbatim, minus the `v` prefix.
git tag v0.1.1
git push origin v0.1.1
```

That's it. Watch the workflow at
https://github.com/sharma-bhaskar/aegis-kms/actions/workflows/release.yml. On
success:

- `aegis-core_3` etc. appear at https://central.sonatype.com/artifact/dev.aegiskms/aegis-core_3
  (allow ~10 min for staging → release sync).
- The Docker image is at `ghcr.io/sharma-bhaskar/aegis-server:<version>` (e.g. `:0.2.0`). For a
  **stable** `vX.Y.Z` tag the workflow also publishes the floating `:X.Y` and `:latest` aliases;
  pre-release tags (e.g. `v0.3.0-rc.1`) get the exact tag only — no `:latest`.
- A release page on GitHub carries the CLI tarball and auto-generated changelog notes.

## Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Workflow's "Publish to Maven Central" step is skipped with a `::notice` | One of the four secrets above is unset | Set them in repo settings; subsequent tags will publish |
| Sonatype rejects with "Missing: gpg signature for ..." | GPG key not propagated to the keyserver yet | Re-run `gpg --keyserver ... --send-keys` against multiple servers; wait 10 min and retry the workflow |
| Sonatype rejects with "Invalid POM: missing description" | One of the modules lost its `description :=` line | Restore in `build.sbt`; the `ThisBuild / description` fallback should also catch this |
| Tag pushed but workflow didn't fire | Branch protection or workflow `on:` filter | Verify the tag matches `v*`; check the Actions tab for queued runs |
| Docker tag missing the `v` prefix | Intentional — the workflow strips `v` so `v0.1.1 → ghcr.io/...:0.1.1` | This is the documented format |

For deeper diagnostics, the workflow run page captures the full sbt output
including the staged Sonatype URL.

## Pre-release / SNAPSHOT versions

Pushes to `main` (without a tag) automatically produce
`0.1.1+<n>-<sha>-SNAPSHOT` artifacts via `sbt-dynver`. These are useful for
internal smoke tests but are not published anywhere by default. To publish a
SNAPSHOT manually from your laptop:

```bash
# Set the same env vars the workflow sets (PGP_SECRET, etc.).
sbt ci-release
```

The Sonatype snapshot repo accepts these without manual staging.
