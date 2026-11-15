#!/usr/bin/env bash
# 受信の監視を持たないエージェント（Codex）が、メッセージが届くまで待って読む。
#
# 使い方: wait-msg.sh <自分の名前> [待つ秒数（既定 1200）]
#   届いたら未読を表示して既読にし、0 で終わる。時間切れは 2 で終わる。
#   登録したプロジェクト（spawn-agent.sh の --project）で実行する。
#   別の場所から呼ぶときは DISTRIBUTAK_PROJECT に登録したパスを入れる。
set -euo pipefail
source "$(dirname "$0")/common.sh"

ME="${1:?使い方: wait-msg.sh <自分の名前> [秒]}"
TIMEOUT="${2:-1200}"
TYPE="${DISTRIBUTAK_AGENT_TYPE:-codex}"
PROJECT="$(to_mixed_path "${DISTRIBUTAK_PROJECT:-$(pwd)}")"

set +e
"$AGMSG_SCRIPTS/drivers/types/codex/watch-once.sh" "$PROJECT" "$TYPE" \
  --name "$ME" --team "$DISTRIBUTAK_TEAM" --timeout "$TIMEOUT"
rc=$?
set -e

case "$rc" in
  0) "$AGMSG_SCRIPTS/inbox.sh" "$DISTRIBUTAK_TEAM" "$ME" ;;
  2) echo "時間切れ（${TIMEOUT} 秒）。まだ届いていない。もう一度待つか、待っている理由を送る。"; exit 2 ;;
  *) die "watch-once.sh が失敗した（終了コード $rc。project=$PROJECT type=$TYPE name=$ME）" ;;
esac
