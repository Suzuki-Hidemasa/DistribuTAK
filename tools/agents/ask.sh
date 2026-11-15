#!/usr/bin/env bash
# 問い合わせを送り、返事が届くまで待って表示する（send-file.sh と wait-msg.sh を続けて行う）。
#
# 使い方: ask.sh <自分の名前> <相手の名前> <本文のファイル | -> [待つ秒数（既定 1200）]
set -euo pipefail
DIR="$(dirname "$0")"

ME="${1:?使い方: ask.sh <自分> <相手> <本文のファイル | -> [秒]}"
TO="${2:?相手の名前がない}"
SRC="${3:?本文のファイルがない}"
TIMEOUT="${4:-1200}"

"$DIR/send-file.sh" "$ME" "$TO" "$SRC"
"$DIR/wait-msg.sh" "$ME" "$TIMEOUT"
