#!/usr/bin/env bash
# tools/agents の補助スクリプトが共通で使う設定。source して使う。

AGMSG_SCRIPTS="${AGMSG_SCRIPTS:-$HOME/.agents/skills/agmsg/scripts}"
DISTRIBUTAK_TEAM="${DISTRIBUTAK_TEAM:-DISTRIBUTAK}"
TOOLS_AGENTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$TOOLS_AGENTS_DIR/../.." && pwd)"

die() { echo "$(basename "$0"): $*" >&2; exit 1; }

[ -x "$AGMSG_SCRIPTS/send.sh" ] || die "agmsg が見つからない（$AGMSG_SCRIPTS）"

# agmsg が登録に使う形（F:/Users/... のような Windows のパス）にそろえる
to_mixed_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}
