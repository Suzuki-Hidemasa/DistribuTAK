#!/usr/bin/env bash
# 役割を決めて、tmux のペインを分割してエージェントを起動する（agmsg の spawn.sh を包む）。
# モデル・effort・サンドボックスは役割ごとにここで固定する（CLAUDE.md「エージェントの体制」、PRC-163 の ADR 0014）。
#
# 使い方:
#   spawn-agent.sh <役割> [--name <名前>] [--project <パス>] (--goal-file <ファイル> | --goal <文>)
#                  [--split h|v] [--window] [--solo] [--dry-run]
#
#   役割:
#     worker          作業者。Codex・gpt-6.1-sol・effort medium。名前の既定は astra-worker（2026-10-30 に Astra から Sol に変えた。名前はそのまま）
#     astra-reviewer  レビュアー。Codex・gpt-6-astra・effort high。名前の既定は astra-reviewer
#     fable-reviewer  レビュアー。Claude Code・claude-fable-5-2・effort medium。名前の既定は fable-reviewer
#                     （2026-11-11 利用者の決定: Claude のレビュアーは Fable 5.2 に固定。effort は同日 high から medium に変更。PRC-163 の ADR 0014 経過）
#     sonnet-worker   作業者（Codex の使用量が尽きたときの代わり）。Claude Code・claude-sonnet-5-5・effort high。
#                     名前の既定は sonnet-worker。コードを書くためガードを外す（worker-claude-env.json の env）
#                     （2026-11-13 利用者の決定: Codex が足りなくなったら作業は Sonnet 5.5 high、レビューは Fable 5.2 medium だけ。PRC-163 の ADR 0014 経過）
#                     --solo は一者のレビュー（Codex の使用量が戻るまで）。effort は medium のまま（2026-11-14 利用者の決定。high は使用量が多すぎる。PRC-163 の ADR 0014 経過）
#     opus-reviewer   使えない（2026-11-11 から Claude のレビュアーは fable-reviewer に固定）
#
#   --project  エージェントを動かす場所（既定: いまの場所）。作業者にはオーケストレーターが作ったワークツリーを渡す
#   --goal-file / --goal  目標（Codex は /goal の目標にする。Claude のレビュアーは最初の指示にする）。必須
#   --dry-run  起動せずに、spawn.sh に渡す引数とオプションのファイルを表示する
set -euo pipefail
source "$(dirname "$0")/common.sh"

ROLE="${1:?使い方: spawn-agent.sh <worker|astra-reviewer|fable-reviewer> [--name N] [--project P] (--goal-file F | --goal T)}"
shift
NAME=""
PROJECT="$(pwd)"
GOAL=""
GOAL_FILE=""
SPLIT="h"
WINDOW=0
DRY_RUN=0
SOLO=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --name)      NAME="${2:?--name に名前がない}"; shift 2 ;;
    --project)   PROJECT="${2:?--project にパスがない}"; shift 2 ;;
    --goal-file) [ -f "${2:-}" ] || die "目標のファイルがない: ${2:-}"; GOAL="$(cat "$2")"; GOAL_FILE="$2"; shift 2 ;;
    --goal)      GOAL="${2:?--goal に文がない}"; shift 2 ;;
    --split)     SPLIT="${2:?--split に h か v がない}"; shift 2 ;;
    --window)    WINDOW=1; shift ;;
    --dry-run)   DRY_RUN=1; shift ;;
    --solo)      SOLO=1; shift ;;
    *) die "知らないオプション: $1" ;;
  esac
done
[ -n "$GOAL" ] || die "目標（--goal-file か --goal）がない。Astra には必ず /goal の目標を渡す"
[ -d "$PROJECT" ] || die "--project の場所がない: $PROJECT"
PROJECT="$(to_mixed_path "$(cd "$PROJECT" && pwd)")"
AGMSG_DIR="$(to_mixed_path "$(cd "$AGMSG_SCRIPTS/.." && pwd)")"

case "$ROLE" in
  worker)
    TYPE=codex; MODEL=gpt-6.1-sol; EFFORT=medium; NAME="${NAME:-astra-worker}"
    ROLE_JA="作業者"; SKILL=".agents/skills/distributak-worker/SKILL.md" ;;
  astra-reviewer)
    TYPE=codex; MODEL=gpt-6-astra; EFFORT=high; NAME="${NAME:-astra-reviewer}"
    ROLE_JA="レビュアー（Astra）"; SKILL=".agents/skills/distributak-reviewer/SKILL.md" ;;
  sonnet-worker)
    TYPE=claude-code; MODEL=claude-sonnet-5-5; EFFORT=high; NAME="${NAME:-sonnet-worker}"
    ROLE_JA="作業者（Sonnet）"; SKILL=".agents/skills/distributak-worker/SKILL.md" ;;
  opus-reviewer)
    die "opus-reviewer は使えない。Claude のレビュアーは fable-reviewer（Fable 5.2・medium）に固定（2026-11-11 利用者の決定。PRC-163 の ADR 0014 経過）" ;;
  fable-reviewer)
    TYPE=claude-code; MODEL=claude-fable-5-2; EFFORT=medium; NAME="${NAME:-fable-reviewer}"
    ROLE_JA="レビュアー（Fable）"; SKILL=".claude/skills/review-debate/SKILL.md" ;;
  *) die "知らない役割: $ROLE（worker・sonnet-worker・astra-reviewer・fable-reviewer のどれか）" ;;
esac

# 指摘を戻すときに作業者が目標のファイルをたどれるよう、パスも起動の指示に入れる
if [ -n "$GOAL_FILE" ]; then
  GOAL="目標のファイル: $(to_mixed_path "$(cd "$(dirname "$GOAL_FILE")" && pwd)/$(basename "$GOAL_FILE")")
${GOAL}"
fi

# spawn.sh に渡す追加の引数（agmsg の spawn_options の書式）。役割ごとに作る
OPTS_FILE="$(mktemp "${TMPDIR:-/tmp}/distributak-spawn-${NAME}-XXXX.yaml")"
trap 'rm -f "$OPTS_FILE"' EXIT
if [ "$TYPE" = codex ]; then
  # workspace-write のサンドボックスで、承認は自動のレビューに回す（人の承認待ちで止まらないように）。
  # agmsg の DB はワークスペースの外なので、書き込める場所に足す
  cat > "$OPTS_FILE" <<EOF
codex:
  -c: model_reasoning_effort=$EFFORT
  --approve-for-me: true
  --add-dir: $AGMSG_DIR
EOF
  BOOT="あなたは DistribuTAK プロジェクトの${ROLE_JA}（agmsg の名前 ${NAME}、チーム ${DISTRIBUTAK_TEAM}）。
最初に AGENTS.md・CLAUDE.md・${SKILL} を読む。
次の「目標」を /goal の目標として設定し（create_goal ツールを使う）、それから作業を始める。
推測はしない。分からないところは tools/agents/ask.sh で claude に問い合わせて待つ。
目標:
${GOAL}"
elif [ "$ROLE" = sonnet-worker ]; then
  # 作業者なのでコードの編集のガード（hooks/guard_code_edit.py）を外す。env は設定のファイルで渡す
  cat > "$OPTS_FILE" <<EOF
claude-code:
  --effort: $EFFORT
  --permission-mode: auto
  --settings: $(to_mixed_path "$TOOLS_AGENTS_DIR/worker-claude-env.json")
EOF
  BOOT="あなたは DistribuTAK プロジェクトの${ROLE_JA}（agmsg の名前 ${NAME}、チーム ${DISTRIBUTAK_TEAM}）。
最初に AGENTS.md・CLAUDE.md・${SKILL} を読む（Codex 向けの書き方は Claude Code に読み替える。/goal の代わりに下の目標を守る）。
推測はしない。分からないところは tools/agents/ask.sh で claude に問い合わせて待つ。コミットはしない。
目標:
${GOAL}"
else
  cat > "$OPTS_FILE" <<EOF
claude-code:
  --effort: $EFFORT
  --permission-mode: auto
EOF
  BOOT="あなたは DistribuTAK プロジェクトの${ROLE_JA}（agmsg の名前 ${NAME}、チーム ${DISTRIBUTAK_TEAM}）。
最初に ${SKILL} と docs/agents/review-debate.md を読み、その手順で進める。
依頼:
${GOAL}"
fi

ARGS=("$TYPE" "$NAME" --project "$PROJECT" --team "$DISTRIBUTAK_TEAM" --model "$MODEL" --fresh --boot-prompt "$BOOT")
if [ "$WINDOW" = 1 ]; then ARGS+=(--window); else ARGS+=(--split "$SPLIT"); fi

if [ "$DRY_RUN" = 1 ]; then
  echo "== spawn.sh の引数 =="; printf '  %q\n' "${ARGS[@]}"
  echo "== オプション（$OPTS_FILE）=="; cat "$OPTS_FILE"
  exit 0
fi

[ -n "${TMUX:-}${PSMUX_SESSION:-}" ] || die "tmux の中で動かしていない。tmux（psmux）のセッションの中から起動する（Astra はペインを分割して起動する決まり）"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    # Windows の psmux では spawn.sh の tmux の道が WSL の bash を起動してしまう。
    # TMUX を外して spawn.sh の「ひな形」の道を使い、psmux-split.sh でペインを分割する。
    # 外す前の TMUX は DISTRIBUTAK_ORIG_TMUX で psmux-split.sh に渡して戻す
    DISTRIBUTAK_ORIG_TMUX="${TMUX:-}" \
    DISTRIBUTAK_SPAWN_NAME="$NAME" DISTRIBUTAK_SPAWN_PROJECT="$PROJECT" DISTRIBUTAK_SPAWN_TYPE="$TYPE" DISTRIBUTAK_SPLIT="$SPLIT" \
    AGMSG_SPAWN_OPTIONS_FILE="$OPTS_FILE" \
      env -u TMUX "$AGMSG_SCRIPTS/spawn.sh" "${ARGS[@]}" \
        --terminal "bash $(printf '%q' "$TOOLS_AGENTS_DIR/psmux-split.sh") {cmd}"
    ;;
  *)
    AGMSG_SPAWN_OPTIONS_FILE="$OPTS_FILE" "$AGMSG_SCRIPTS/spawn.sh" "${ARGS[@]}"
    ;;
esac
