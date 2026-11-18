---
id: DTAK-28
title: NamingScreenTest の再接続待ちが全体実行で時々落ちる（AdministrationButtonsTest も巻き込む）
status: Done
assignee:
  - '@claude'
created_date: '2026-11-18 08:28'
updated_date: '2026-11-18 10:16'
labels:
  - testing
dependencies: []
references:
  - DTAK-21
  - DTAK-24
ordinal: 28000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DTAK-21・24 の確認で全プラグイン試験を流したとき（5 分 31 秒かかった 1 回目）、NamingScreenTest.reconnect の「名前の確認を待てませんでした。確認待ち=true、保持役=true、接続=false」で 2 件落ちた（NamingScreenTest.namingNeedsReconnectAndSeparateSaveConfirmation と、reconnect を使う AdministrationButtonsTest.failureBeforeGrantSaveKeepsCommunicationAndStoredMembership）。2 クラスだけの再実行と全体の再実行では通った。再接続の握手の時間依存（DTAK-21 と同じ型の疑い）。製品の欠陥か試験の待ちの不足かを調べ、試験の問題なら直す。着手は別の許可を待つ。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 原因が特定され、記録されている
- [x] #2 この試験が全体実行を繰り返しても落ちない（回数は計画で決める）
- [x] #3 核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0、NewApi 0
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. 原因: 全体実行（CPU 負荷）で、NamingScreenTest.reconnect の再接続の握手が完了しない。2 つのノードの仮の時計を LanProofRenewalTest.until が毎回同じ +100 ms ずつ進めるため、両側の 5 秒の再送と最初のパケットの送信が毎回重なる。18 回以上の再送のあと 90 秒の試行の予算（ATTEMPT_NANOS）が両側で切れ、exhausted=true・attempt=null になり、再送が止まる。
2. 修正（試験だけ）: reconnect の待ちを、A を +100 ms、M を +137 ms ずつ進める untilStaggered に替える（AdministrationButtonsTest.prepare も reconnect 経由で直る）。
3. 確認: 6 プロセスの CPU 負荷下で reconnect を繰り返す一時の試験を使い、修正前（元の待ち）と修正後を比べる。一時の試験は消す。
4. 核・プラグインの全試験、lintCivDebug、NewApi、git diff --check。
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
原因（AC#1）: 負荷下で reconnect を 60 回流すと、元の待ちは 3/60・4/60・13/60 回失敗。失敗時の診断は、両ノードとも exhausted=true・active/candidate/pending/attempt=null、受け取った最初のパケットは各側 12〜14 件。仮の時計を互い違いにずらした版は同じ負荷で 0/60。仕組みは診断からの推定（時計が同じ歩幅で進み再送が重なる）。製品のコードは変えない。

確認: 修正は NamingScreenTest.untilStaggered（A +100 ms・M +137 ms）。負荷下（6 プロセス）で reconnect を繰り返し、修正前は 60 回中 3・4・13 回、修正後は 60 回で 0 と 200 回で 0。全体実行は核 1,675 件・プラグイン 799 件で失敗・スキップ 0、lintCivDebug 通過、NewApi 0、git diff --check 問題なし。AC#2 の回数は『負荷下 reconnect 200 回＋全体実行 1 回』とした。
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
NamingScreenTest.reconnect の待ちを、仮の時計を別々の歩幅（A +100 ms・M +137 ms）で進める untilStaggered に替えた（PR #32、試験だけ）。原因は、同じ歩幅だと両側の再送が毎回重なり、負荷下で 90 秒の試行の予算が握手の前に切れること。負荷下で reconnect を繰り返し、修正前 60 回中 3〜13 回失敗、修正後 60 回と 200 回で 0。核 1,675 件・プラグイン 799 件で失敗・スキップ 0、lintCivDebug 通過、NewApi 0、CI の 3 ジョブ成功。
<!-- SECTION:FINAL_SUMMARY:END -->
