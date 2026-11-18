#!/usr/bin/env bash
# Copyright (c) 2026 Reflex
# SPDX-License-Identifier: MIT
# Conventional commits since the previous tag -> ArtifactHub "artifacthub.io/changes" YAML on stdout.
# feat=added, fix=fixed, fix(security)=security, perf/refactor=changed, "!"=breaking; docs/chore/ci/test/build/style skipped.
set -euo pipefail
prev=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || true)
if [ -z "$prev" ]; then printf -- '- kind: added\n  description: "Initial release"\n'; exit 0; fi
out=$(git log --no-merges --format=%s "$prev..HEAD" | awk '
  match($0, /^[a-z]+(\([^)]*\))?!?: /) {
    head = substr($0, 1, RLENGTH - 2); desc = substr($0, RLENGTH + 1)
    type = head; sub(/[(!].*/, "", type)
    kind = ""
    if (type == "feat") kind = "added"
    else if (type == "fix") kind = (head ~ /\(security\)/) ? "security" : "fixed"
    else if (type == "perf" || type == "refactor") kind = "changed"
    if (head ~ /!$/) { kind = (kind == "" ? "changed" : kind); desc = "BREAKING: " desc }
    if (kind == "") next
    gsub(/"/, "\\\"", desc)
    printf "- kind: %s\n  description: \"%s\"\n", kind, desc
  }')
echo "${out:-- kind: changed
  description: \"Maintenance release\"}"
