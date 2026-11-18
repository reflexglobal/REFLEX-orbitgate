#!/usr/bin/env bash
# Copyright (c) 2026 Reflex
# SPDX-License-Identifier: MIT
# Fail if any commit in range $1 doesn't follow Conventional Commits (https://www.conventionalcommits.org).
set -euo pipefail
re='^(feat|fix|docs|chore|refactor|perf|test|build|ci|style|revert)(\([a-z0-9._/-]+\))?!?: .+'
bad=$(git log --no-merges --format='%h %s' "$1" | while read -r h s; do [[ $s =~ $re ]] || echo "$h $s"; done)
[ -z "$bad" ] && exit 0
echo "Not Conventional Commits (type(scope)!: subject):"; echo "$bad"; exit 1
