#!/usr/bin/env bash
# apply-pr-backlog.sh — split the working tree into one commit per PR.
#
# Reads BUILD-PR-PLAN.md as the source of truth for which files belong to which PR.
# Adds the listed paths and commits with a PR-tagged message. Does NOT push — that's
# the operator's job (`git push` per branch, or open as GitHub PRs).
#
# Usage:
#   ./apply-pr-backlog.sh           # commit every pending PR in order
#   ./apply-pr-backlog.sh F1 F2     # only commit named PRs
#   DRY_RUN=1 ./apply-pr-backlog.sh # print git commands without running them
#
# The script is idempotent in the trivial sense: if a PR's files have already been
# committed, `git add` is a no-op and `git diff --cached --quiet` short-circuits the
# commit. It will not amend or rebase. Re-running after a partial failure picks up
# from the first PR with pending changes.

set -euo pipefail

cd "$(dirname "$0")"

# --- Pekko/FUSE workaround: remove a stale .git/index.lock that the FUSE mount
# --- sometimes leaves behind read-only. No-op if no lock exists.
if [[ -f .git/index.lock ]]; then
  echo "removing stale .git/index.lock"
  chmod +w .git/index.lock 2>/dev/null || true
  rm -f .git/index.lock 2>/dev/null || \
    echo "  warning: could not remove .git/index.lock (FUSE mount?); git will report a clearer error if this is a real problem"
fi

run() {
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    printf '+ '; printf '%q ' "$@"; printf '\n'
  else
    "$@"
  fi
}

# Commit a PR. Args: PR-tag, "subject line", path1 path2 ...
commit_pr() {
  local tag="$1"; shift
  local subject="$1"; shift
  local paths=("$@")

  echo
  echo "=== ${tag}: ${subject} ==="

  # Filter to paths that actually exist — a path missing from the working tree is a
  # plan/code mismatch and we want to surface that loudly rather than silently skip.
  local missing=()
  local present=()
  for p in "${paths[@]}"; do
    if [[ -e "$p" ]]; then
      present+=("$p")
    else
      missing+=("$p")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "ERROR: ${tag} references paths not present in the working tree:"
    printf '  - %s\n' "${missing[@]}"
    echo "Fix BUILD-PR-PLAN.md or the working tree before re-running."
    exit 1
  fi

  run git add -- "${present[@]}"

  if git diff --cached --quiet; then
    echo "no staged changes for ${tag} — already committed?"
    return 0
  fi

  run git commit -m "${tag}: ${subject}"
}

# Filter: if the user passed PR names on the cmdline, only run those.
wants() {
  if [[ $# -eq 0 ]] && [[ ${#TARGETS[@]} -eq 0 ]]; then return 0; fi
  if [[ ${#TARGETS[@]} -eq 0 ]]; then return 0; fi
  local pr="$1"
  local t
  for t in "${TARGETS[@]}"; do
    [[ "$t" == "$pr" ]] && return 0
  done
  return 1
}

TARGETS=("$@")

# ---------------------------------------------------------------------------
# PR D1 — Docs refresh (rebrand + positioning)
# ---------------------------------------------------------------------------
# Landed first because these were already pending in the working tree before this
# batch and will conflict with any branch we open later if left uncommitted.
if wants D1; then
  commit_pr "D1" "rebrand to Aegis + refreshed positioning" \
    README.md \
    docs/POSITIONING.md
fi

# ---------------------------------------------------------------------------
# PR F1 — Pekko Typed KeyOpsActor + EventJournal SPI
# ---------------------------------------------------------------------------
if wants F1; then
  commit_pr "F1" "actor-backed KeyService over EventJournal SPI" \
    modules/aegis-core/src/main/scala/dev/aegiskms/core/KeyEvent.scala \
    modules/aegis-persistence/src/main/scala/dev/aegiskms/persistence/EventJournal.scala \
    modules/aegis-server/src/main/scala/dev/aegiskms/app/KeyOpsActor.scala \
    modules/aegis-server/src/main/scala/dev/aegiskms/app/ActorBackedKeyService.scala \
    modules/aegis-server/src/test/scala/dev/aegiskms/app/KeyOpsActorSpec.scala
fi

# ---------------------------------------------------------------------------
# PR F2 — Audit sink + AuditingKeyService decorator
# ---------------------------------------------------------------------------
if wants F2; then
  commit_pr "F2" "audit sink + AuditingKeyService decorator" \
    modules/aegis-audit/src/main/scala/dev/aegiskms/audit/AuditingKeyService.scala \
    modules/aegis-audit/src/main/scala/dev/aegiskms/audit/InMemoryAuditSink.scala \
    modules/aegis-audit/src/main/scala/dev/aegiskms/audit/StdoutAuditSink.scala \
    modules/aegis-audit/src/test/scala/dev/aegiskms/audit/AuditingKeyServiceSpec.scala
fi

# ---------------------------------------------------------------------------
# PR F3 — IAM allowlist policy engine + AuthorizingKeyService
# ---------------------------------------------------------------------------
if wants F3; then
  commit_pr "F3" "RoleBasedPolicyEngine + AuthorizingKeyService" \
    modules/aegis-iam/src/main/scala/dev/aegiskms/iam/RoleBasedPolicyEngine.scala \
    modules/aegis-iam/src/main/scala/dev/aegiskms/iam/AuthorizingKeyService.scala \
    modules/aegis-iam/src/test/scala/dev/aegiskms/iam/RoleBasedPolicyEngineSpec.scala \
    modules/aegis-iam/src/test/scala/dev/aegiskms/iam/AuthorizingKeyServiceSpec.scala
fi

# ---------------------------------------------------------------------------
# PR L1 — AWS KMS RootOfTrust adapter (layered mode)
# ---------------------------------------------------------------------------
if wants L1; then
  commit_pr "L1" "AWS KMS RootOfTrust adapter via AwsKmsPort seam" \
    modules/aegis-crypto/src/main/scala/dev/aegiskms/crypto/aws/AwsKmsPort.scala \
    modules/aegis-crypto/src/main/scala/dev/aegiskms/crypto/aws/AwsKmsRootOfTrust.scala \
    modules/aegis-crypto/src/test/scala/dev/aegiskms/crypto/aws/AwsKmsRootOfTrustSpec.scala
fi

# ---------------------------------------------------------------------------
# PR W1 — Anomaly detector MVP (sliding-window baseline)
# ---------------------------------------------------------------------------
if wants W1; then
  commit_pr "W1" "BaselineDetector MVP + TappedAuditSink fan-out" \
    modules/aegis-agent-ai/src/main/scala/dev/aegiskms/agent/AgentRecommendation.scala \
    modules/aegis-agent-ai/src/main/scala/dev/aegiskms/agent/BaselineDetector.scala \
    modules/aegis-agent-ai/src/main/scala/dev/aegiskms/agent/RecommendationSink.scala \
    modules/aegis-agent-ai/src/main/scala/dev/aegiskms/agent/TappedAuditSink.scala \
    modules/aegis-agent-ai/src/test/scala/dev/aegiskms/agent/BaselineDetectorSpec.scala \
    modules/aegis-agent-ai/src/test/scala/dev/aegiskms/agent/TappedAuditSinkSpec.scala
fi

# ---------------------------------------------------------------------------
# PR C1 — CLI MVP
# ---------------------------------------------------------------------------
if wants C1; then
  commit_pr "C1" "CLI MVP over java.net.http.HttpClient" \
    modules/aegis-cli/src/main/scala/dev/aegiskms/cli/HttpPort.scala \
    modules/aegis-cli/src/main/scala/dev/aegiskms/cli/WireFormats.scala \
    modules/aegis-cli/src/main/scala/dev/aegiskms/cli/AegisHttpClient.scala \
    modules/aegis-cli/src/main/scala/dev/aegiskms/cli/Config.scala \
    modules/aegis-cli/src/main/scala/dev/aegiskms/cli/Commands.scala \
    modules/aegis-cli/src/main/scala/dev/aegiskms/cli/Cli.scala \
    modules/aegis-cli/src/test/scala/dev/aegiskms/cli/AegisHttpClientSpec.scala \
    modules/aegis-cli/src/test/scala/dev/aegiskms/cli/CommandsSpec.scala \
    modules/aegis-cli/src/test/scala/dev/aegiskms/cli/CliSpec.scala \
    modules/aegis-cli/src/test/scala/dev/aegiskms/cli/ConfigSpec.scala
fi

# ---------------------------------------------------------------------------
# PR I1 — Integration: actor + audit + IAM + W1 wired into Server.scala
# ---------------------------------------------------------------------------
# This is the only PR that MODIFIES existing files. The plan + script land it last so
# every prior PR's tests pass against the unmodified Server.scala.
if wants I1; then
  commit_pr "I1" "wire actor + audit + IAM + W1 into Server" \
    modules/aegis-server/src/main/scala/dev/aegiskms/app/DevPolicyEngine.scala \
    modules/aegis-server/src/main/scala/dev/aegiskms/app/Server.scala \
    modules/aegis-iam/src/main/scala/dev/aegiskms/iam/AuthorizingKeyService.scala \
    modules/aegis-server/src/test/scala/dev/aegiskms/app/IntegrationWiringSpec.scala \
    BUILD-PR-PLAN.md \
    apply-pr-backlog.sh
fi

echo
echo "done. review with:  git log --oneline"
echo "push when ready:    git push        # or push branch-by-branch"
