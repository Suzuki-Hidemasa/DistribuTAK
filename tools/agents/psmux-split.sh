#!/usr/bin/env bash
# Windows の psmux で、ペインを分割して agmsg の起動スクリプトを Git Bash で動かす。
# spawn-agent.sh が agmsg の spawn.sh に --terminal のひな形として渡す（直接は使わない）。
#
# spawn.sh の tmux の道は `bash -l <起動スクリプト>` を psmux に渡すが、psmux は bash を
# Windows の PATH で探すので WSL の bash.exe が起動し、起動スクリプトが見つからずにペインが閉じる。
# psmux は空白を含むパスも扱えないので、Git Bash を短いパス名（8.3 形式）で渡す。
#
# 使い方: psmux-split.sh <起動スクリプト>
#   環境変数: DISTRIBUTAK_SPAWN_NAME（ペインの名前）・DISTRIBUTAK_SPAWN_PROJECT・DISTRIBUTAK_SPAWN_TYPE・DISTRIBUTAK_SPLIT（h|v）
set -euo pipefail
source "$(dirname "$0")/common.sh"

BOOT="${1:?起動スクリプトがない}"
NAME="${DISTRIBUTAK_SPAWN_NAME:?DISTRIBUTAK_SPAWN_NAME がない}"
PROJECT="${DISTRIBUTAK_SPAWN_PROJECT:?DISTRIBUTAK_SPAWN_PROJECT がない}"
TYPE="${DISTRIBUTAK_SPAWN_TYPE:?DISTRIBUTAK_SPAWN_TYPE がない}"
DIR="-h"; [ "${DISTRIBUTAK_SPLIT:-h}" = "v" ] && DIR="-v"

# spawn-agent.sh が spawn.sh のために外した TMUX を戻す。元からなければセッション名から補う
if [ -n "${DISTRIBUTAK_ORIG_TMUX:-}" ]; then
  export TMUX="$DISTRIBUTAK_ORIG_TMUX"
elif [ -z "${TMUX:-}" ] && [ -n "${PSMUX_SESSION:-}" ]; then
  export TMUX="psmux,$PSMUX_SESSION"
fi
[ -n "${TMUX:-}" ] || die "tmux（psmux）の中で動かしていない（TMUX も PSMUX_SESSION もない）"

GIT_BASH="$(cygpath -d "$(command -v bash)")"

# psmux はときどき、端末のつながっていないペインを作る。そのペインでは Codex が
# 「Error: stdout is not a terminal」ですぐに終わるか、bash が起動スクリプトの最初に進まずに止まる。
# 同じペインで待っても起動し直しても直らず、Git Bash を通さずに PowerShell から起動しても起きた
# （2026-10-27 に確かめた。ADR 0014 の経過）。そこで、起動できたかを確かめ、だめならペインごと作り直す。
#
# 確かめ方: 起動スクリプトの写しをペインで動かす。写しの最初に目印のファイルを作る行を足す。
# 起動スクリプトはエージェントが終わると自分（写し）を消すので、
#   目印がある・写しが残っている → エージェントが動いている（成功）
#   写しが消えている             → エージェントがすぐに終わった（失敗）
#   目印がない                   → bash が止まった（失敗）
# 待つ秒数は DISTRIBUTAK_SPAWN_SETTLE（既定 6 秒）、試す回数は DISTRIBUTAK_SPAWN_TRIES（既定 3 回）
#
# DISTRIBUTAK_SPAWN_INPLACE=1 のときは分割せず、spawn-agent.sh を実行したペインでそのまま起動する。
# 2026-10-30、分割で作ったペインで Codex が続けて起動できず（9回中9回）、端末のつながったペインで
# 実行すれば Codex がその端末を受け継げたため（spawn.sh はひな形を前面の bash -c で動かす）。
# そのペインはエージェントのペインになり、despawn-agent.sh で閉じる。
if [ "${DISTRIBUTAK_SPAWN_INPLACE:-0}" = 1 ]; then
  # TMUX_PANE がないシェル（psmux の外の端末など）でも起動はできる。記録のペインは「-」にし、閉じるのは人が行う
  PANE="${TMUX_PANE:--}"
  [ "$PANE" = "-" ] && echo "psmux-split: TMUX_PANE がないので、ペインを記録せずにこの端末で起動する（終わったら端末は人が閉じる）" >&2
  [ "$PANE" = "-" ] || tmux select-pane -t "$PANE" -T "$NAME" 2>/dev/null || true
  mkdir -p "$REPO_ROOT/out/agents/panes"
  printf '%s\t%s\t%s\n' "$PANE" "$PROJECT" "$TYPE" > "$REPO_ROOT/out/agents/panes/$NAME"
  echo "pane=$PANE name=$NAME（その場で起動）"
  cd "$PROJECT"
  exec bash -l "$BOOT"
fi

SETTLE="${DISTRIBUTAK_SPAWN_SETTLE:-6}"
TRIES="${DISTRIBUTAK_SPAWN_TRIES:-3}"
BOOT_COPY_DIR="$REPO_ROOT/out/agents/boot"
mkdir -p "$BOOT_COPY_DIR"

PANE=""
for try in $(seq 1 "$TRIES"); do
  COPY="$BOOT_COPY_DIR/$NAME-$try.sh"
  MARK="$BOOT_COPY_DIR/$NAME-$try.started"
  rm -f "$MARK"
  { head -n 1 "$BOOT"; printf ': > %q\n' "$MARK"; tail -n +2 "$BOOT"; } > "$COPY"
  chmod +x "$COPY"
  PANE="$(tmux split-window "$DIR" -P -F '#{pane_id}' -c "$PROJECT" "$GIT_BASH" -l "$(cygpath -m "$COPY")")"
  [ -n "$PANE" ] || die "ペインを分割できなかった"
  tmux select-pane -t "$PANE" -T "$NAME" 2>/dev/null || true

  result="止まった"
  for t in $(seq 1 $((SETTLE * 2))); do
    sleep 1
    if [ ! -e "$COPY" ]; then result="すぐに終わった"; break; fi
    if [ -e "$MARK" ] && [ "$t" -ge "$SETTLE" ]; then result="ok"; break; fi
  done
  rm -f "$MARK"
  [ "$result" = ok ] && break
  echo "psmux-split: ${try}回目のペイン $PANE で起動できなかった（$result）。ペインを閉じて作り直す" >&2
  tmux kill-pane -t "$PANE" 2>/dev/null || true
  rm -f "$COPY"
  PANE=""
done
[ -n "$PANE" ] || die "${TRIES}回ペインを作り直しても起動できなかった（$NAME）"
rm -f "$BOOT"

# nudge.sh・despawn-agent.sh が使う記録（ペイン・場所・種類）
mkdir -p "$REPO_ROOT/out/agents/panes"
printf '%s\t%s\t%s\n' "$PANE" "$PROJECT" "$TYPE" > "$REPO_ROOT/out/agents/panes/$NAME"
echo "pane=$PANE name=$NAME"
