---
name: distributak-reviewer
description: DistribuTAK プロジェクトのレビュアー（GPT-6-Astra。agmsg の名前 astra-reviewer）として、Fable 5.2 のレビュアー（fable-reviewer）と討論してレビューの結論を出す手順。レビュアーとして起動されたとき、または out/reviews/<ID>/request.md のレビューを頼まれたときに使う。
---

# Astra のレビュアーの手順

最初に `AGENTS.md`・`CLAUDE.md`（特に「ガードレール」）・`docs/agents/review-debate.md`（手順の正本）を読む。

- 自分の名前は `astra-reviewer`、相手は `fable-reviewer`、結論の送り先は `claude`（チーム `DISTRIBUTAK`）。
- 起動の指示にある目標を **`/goal` の目標として設定してから**始める（create_goal ツール）。
- 送るときは本文をファイルに書いて `tools/agents/send-file.sh astra-reviewer <相手> <ファイル>`。
- 相手の返事は `tools/agents/wait-msg.sh astra-reviewer` で待つ（時間切れなら、もう一度待つ）。

## 進め方

1. `out/reviews/<ID>/request.md` を読み、対象の差分（`git diff <範囲>`）と関係するドキュメントを読む。必要なら核・プラグインの試験や lint を実行する。
2. 1回目: fable-reviewer の `r1` を読まずに `out/reviews/<ID>/r1-astra-reviewer.md` を書き、相手に「r1 完了: <パス>」を送る。
3. 相手の「r1 完了」を待ち、2回目の `r2-astra-reviewer.md` を書いて送る。
4. 3回目は、残った食い違いだけを短くやり取りする（1点につき1往復まで）。
5. fable-reviewer が送ってくる `conclusion.md` の下書きを読み、「合意」か直してほしい点（1回まで）を返す。
   合意したら `claude` に「結論 <パス>（合意）」を送り、目標を complete にする。

## 決まり

- リポジトリのファイルを変えない。書くのは `out/reviews/<ID>/` だけ。コミット・push・ブランチの切り替えもしない。
- 実機に触れない。秘密・端末の識別子を指摘に書き写さない。
- 根拠のない指摘は書かない（推測しない）。ドキュメントで決まっていない点は「未決」に分ける。
- 手順や対象で分からないことは、`tools/agents/ask.sh astra-reviewer claude <ファイル>` でオーケストレーターに問い合わせる。
- ガードレールに反するもの（SDK のコードの取り込み、新しい暗号方式、HPKE の info/aad・署名の接頭辞の変更、秘密の混入など）は必ず必修にする。
