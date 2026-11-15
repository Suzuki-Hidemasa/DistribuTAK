---
name: review-debate
description: DistribuTAK プロジェクトで Fable 5.2 のレビュアー（agmsg の名前 fable-reviewer）として、GPT-6-Astra のレビュアー（astra-reviewer）と討論してレビューの結論を出す手順。fable-reviewer として起動されたとき、または out/reviews/<ID>/request.md のレビューを頼まれたときに使う。
---

# Fable のレビュアーの手順

Claude のレビュアーは Fable 5.2（`claude-fable-5-2`）・effort medium に固定（high は使用料が高い。Opus は使わない）。

手順の正本は `docs/agents/review-debate.md`。まずそれと `CLAUDE.md`（特に「ガードレール」）を読む。

- 自分の名前は `fable-reviewer`、相手は `astra-reviewer`、結論の送り先は `claude`（チーム `DISTRIBUTAK`）。
- 受信は agmsg の監視（Monitor）で届く。届かないときは `~/.agents/skills/agmsg/scripts/inbox.sh DISTRIBUTAK fable-reviewer`。
  監視は時間で切れる（「Monitor expired」の知らせが来る）。切れたら、起動したときと同じコマンドで張り直す
  （`~/.agents/skills/agmsg/scripts/watch.sh` を、agmsg の actas で使ったのと同じ引数で。ワークツリーの中で即終了するときは `AGMSG_RESOLVE_PROJECT=0` を付け、本体の場所で起動する）。
- 相手が応答しないときは `docs/agents/review-debate.md` 3章「相手が応答しないとき」に従う。
- 送るときは本文をファイルに書いて `tools/agents/send-file.sh fable-reviewer <相手> <ファイル>`。
- 相手の astra-reviewer は Codex で、受信の監視を持たない。`wait-msg.sh` で待っていれば受け取るが、数分たっても反応がなければ
  `tools/agents/nudge.sh astra-reviewer` で受信箱を読ませる。
- 一者で行うとき（`--solo`）は、相手がいない。`r1` を書いたあと、そのまま `conclusion.md` を書いて `claude` に送る。

## 進め方

1. `out/reviews/<ID>/request.md` を読み、対象の差分（`git diff <範囲>`）と関係するドキュメントを読む。
2. 1回目: astra-reviewer の `r1` を読まずに `out/reviews/<ID>/r1-fable-reviewer.md` を書き、相手に「r1 完了: <パス>」を送る。
3. 相手の「r1 完了」を待ち、2回目の `r2-fable-reviewer.md` を書いて送る。
4. 3回目は、残った食い違いだけを短くやり取りする（1点につき1往復まで）。
5. `conclusion.md` を下書きして astra-reviewer に送り、合意を得たら `claude` に「結論 <パス>（合意）」を送って終える。

## 決まり

- リポジトリのファイルを変えない。書くのは `out/reviews/<ID>/` だけ。コミット・push・ブランチの切り替えもしない。
  （フック `tools/agents/hooks/guard_code_edit.py` を登録しているときは、コード・設定のファイルの書き換えを止める。）
- 実機に触れない。秘密・端末の識別子を指摘に書き写さない。
- 根拠のない指摘は書かない。ドキュメントで決まっていない点は「未決」に分ける。
- ガードレールに反するものは必ず必修にする。
