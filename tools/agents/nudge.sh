#!/usr/bin/env bash
# 待機中の Codex（受信の監視がない）に、受信箱を読むよう tmux で入力を送る。
# agmsg でメッセージを送ったあとに使う。Claude Code のエージェントは監視で受け取るので要らない。
#
# 使い方: nudge.sh <名前> [入力する文（既定: $agmsg）]
#   ペインは spawn-agent.sh の記録（out/agents/panes/<名前>）で探し、なければペインの名前（タイトル）で探す。
set -euo pipefail
source "$(dirname "$0")/common.sh"

NAME="${1:?使い方: nudge.sh <名前> [入力する文]}"
TEXT="${2:-\$agmsg}"

if [ -z "${TMUX:-}" ] && [ -n "${PSMUX_SESSION:-}" ]; then
  export TMUX="psmux,$PSMUX_SESSION"
fi
[ -n "${TMUX:-}" ] || die "tmux の中で動かしていない"

PANE=""
REC="$REPO_ROOT/out/agents/panes/$NAME"
[ -f "$REC" ] && PANE="$(cut -f1 "$REC")"
if [ -z "$PANE" ] || ! tmux list-panes -a -F '#{pane_id}' | grep -qx "$PANE"; then
  PANE="$(tmux list-panes -a -F '#{pane_id} #{pane_title}' | awk -v n="$NAME" '$2 == n { print $1; exit }')"
fi
[ -n "$PANE" ] || die "名前が $NAME のペインがない（tmux list-panes -a -F '#{pane_id} #{pane_title}' で確かめる）"

# Git Bash（MSYS）は Windows のプログラムへの引数の "/goal …" をパスに書き換える（"C:/Program Files/Git/goal …"）。止める
MSYS_NO_PATHCONV=1 tmux send-keys -t "$PANE" -l "$TEXT"
# Codex は速い連続入力を貼り付けとみなし、直後の Enter を改行として取り込む。間をあけて送る
sleep 1
tmux send-keys -t "$PANE" Enter
echo "nudged $NAME ($PANE)"
