#!/usr/bin/env bash
# agmsg の本文をファイルから送る。本文に # や改行を含んでも切れない。
#
# 使い方: send-file.sh <自分の名前> <相手の名前> <本文のファイル | ->
#   - を渡すと標準入力から読む。
set -euo pipefail
source "$(dirname "$0")/common.sh"

FROM="${1:?使い方: send-file.sh <自分> <相手> <本文のファイル | ->}"
TO="${2:?相手の名前がない}"
SRC="${3:?本文のファイルがない}"

if [ "$SRC" = "-" ]; then
  BODY="$(cat)"
else
  [ -f "$SRC" ] || die "本文のファイルがない: $SRC"
  BODY="$(cat "$SRC")"
fi
[ -n "$BODY" ] || die "本文が空"

"$AGMSG_SCRIPTS/send.sh" "$DISTRIBUTAK_TEAM" "$FROM" "$TO" "$BODY"
