#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# 試験には python3 が必要。初回はネットから公開ベクトル・Gradle・依存を取得する。
set -euo pipefail
core_root="$(cd -- "$(dirname -- "$0")" && pwd)"
project_root="$(cd -- "$core_root/../../../.." && pwd)"
export JAVA_HOME="${JAVA_HOME:-$HOME/miniconda3/envs/atakdev}"
export GRADLE_USER_HOME="$project_root/out/distributak/.gradle-home"
mkdir -p "$GRADLE_USER_HOME"
cd "$core_root"
exec ./gradlew --no-daemon --project-cache-dir "$project_root/out/distributak/.gradle-project" "-Duser.home=$project_root/out/distributak" "$@"
