#!/usr/bin/env bash
# spawn-agent.sh で起動したエージェントを止めて、ペインを閉じ、agmsg の登録を外す。
#
# 使い方: despawn-agent.sh <名前> [オーケストレーターの名前（既定 claude）]
#   Windows（psmux）では spawn-agent.sh の記録（out/agents/panes/<名前>）を使う。
#   1. Claude Code のエージェントには、まず agmsg の despawn.sh で ctrl:despawn を送る。
#      受信の監視（watch.sh）が自分で役割を外して終わるのを待つ（Codex には監視がないので送らない）。
#      actas のロックが見つからないと despawn.sh は何も送らない（2026-10-27 の psmux ではこうなった）。
#      そのときは 3 で止める。
#   2. ペインを閉じ、agmsg の reset.sh で登録を外す。
#   3. それでもその名前の監視が残っていたら、そのプロセスだけを止める。
#      Windows ではペインを閉じても子のプロセスまでは止まらず、監視が取り残されることがある
#      （2026-10-27。opus-reviewer の watch.sh が残り、ワークツリーを消せなかった）。
#   記録がなければ agmsg の despawn.sh を使う（Codex は終了の合図に応えられないので --force）。
set -euo pipefail
source "$(dirname "$0")/common.sh"

NAME="${1:?使い方: despawn-agent.sh <名前> [自分の名前]}"
ME="${2:-claude}"

if [ -z "${TMUX:-}" ] && [ -n "${PSMUX_SESSION:-}" ]; then
  export TMUX="psmux,$PSMUX_SESSION"
fi

# <場所> <種類> <名前> で動いている agmsg の watch.sh の PID を1行ずつ出す
leftover_watchers() {
  local project="$1" type="$2" name="$3"
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      powershell.exe -NoProfile -Command \
        "Get-CimInstance Win32_Process -Filter \"Name='bash.exe'\" | ForEach-Object { \"{0}\`t{1}\" -f \$_.ProcessId, \$_.CommandLine }" \
        2>/dev/null | tr -d '\r' ;;
    *)
      ps -eo pid=,args= | sed -E 's/^ *([0-9]+) /\1\t/' ;;
  esac | awk -F'\t' -v tail=" $project $type $name" '
    index($2, "agmsg/scripts/watch.sh") && substr($2, length($2) - length(tail) + 1) == tail { print $1 }'
}

kill_pid() {
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) taskkill //T //F //PID "$1" >/dev/null 2>&1 ;;
    *) kill "$1" 2>/dev/null ;;
  esac
}

REC="$REPO_ROOT/out/agents/panes/$NAME"
if [ -f "$REC" ]; then
  IFS=$'\t' read -r PANE PROJECT TYPE < "$REC"

  if [ "$TYPE" = claude-code ]; then
    # 監視が自分で終わるのを待つ。時間切れ（終了コード 3）でも、続けて閉じる
    "$AGMSG_SCRIPTS/despawn.sh" "$DISTRIBUTAK_TEAM" "$ME" "$NAME" --timeout 30 || true
  fi

  tmux kill-pane -t "$PANE" 2>/dev/null || echo "ペイン $PANE はもうない"
  "$AGMSG_SCRIPTS/reset.sh" "$PROJECT" "$TYPE" "$NAME"
  rm -f "$REC"

  LEFT="$(leftover_watchers "$PROJECT" "$TYPE" "$NAME")"
  for pid in $LEFT; do
    if kill_pid "$pid"; then
      echo "残っていた監視を止めた: PID $pid（$NAME）"
    else
      echo "残っていた監視を止められなかった: PID $pid（$NAME）。手で止める" >&2
    fi
  done
  echo "status=despawned name=$NAME pane=$PANE"
  exit 0
fi

case "$NAME" in
  astra-*) "$AGMSG_SCRIPTS/despawn.sh" "$DISTRIBUTAK_TEAM" "$ME" "$NAME" --force ;;
  *)       "$AGMSG_SCRIPTS/despawn.sh" "$DISTRIBUTAK_TEAM" "$ME" "$NAME" ;;
esac
