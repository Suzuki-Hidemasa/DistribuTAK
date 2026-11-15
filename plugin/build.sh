#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
plugin_root="$(cd -- "$(dirname -- "$0")" && pwd)"
project_root="$(cd -- "$plugin_root/../../../.." && pwd)"
export JAVA_HOME="${JAVA_HOME:-$HOME/miniconda3/envs/atakdev}"
export GRADLE_USER_HOME="$project_root/out/distributak/.gradle-home"
export ANDROID_USER_HOME="$project_root/out/distributak/plugin/.android-home"
unset ANDROID_PREFS_ROOT ANDROID_SDK_HOME
mkdir -p "$ANDROID_USER_HOME"
takdev_cache="$project_root/out/distributak/plugin/.takdev"
mkdir -p "$takdev_cache"
if [[ ! -e "$plugin_root/.takdev" ]]; then
    ln -s "$takdev_cache" "$plugin_root/.takdev"
fi
cd "$plugin_root"
if [ "$#" -eq 0 ]; then set -- assembleCivDebug; fi
# 核の既存の wrapper を使う。独立した核のビルドにも影響を与えない。
exec ../core/gradlew --no-daemon --project-cache-dir "$project_root/out/distributak/plugin/.gradle-project" \
    "-Duser.home=$project_root/out/distributak/plugin" "$@"
