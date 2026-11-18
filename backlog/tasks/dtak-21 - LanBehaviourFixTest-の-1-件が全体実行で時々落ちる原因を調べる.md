---
id: DTAK-21
title: LanBehaviourFixTest の 1 件が全体実行で時々落ちる原因を調べる
status: In Progress
assignee:
  - '@claude'
created_date: '2026-11-17 10:33'
updated_date: '2026-11-18 08:28'
labels:
  - testing
dependencies: []
references:
  - DTAK-9
  - DTAK-19
priority: medium
ordinal: 21000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
LanBehaviourFixTest.peerWithoutSessionDoesNotAdvanceReviewAndRenewsAfterConnecting が、全体実行で時々時間切れで落ちる（単独や再実行では通る）。DTAK-9 第8b 回の前と、DTAK-19 の作業者の最初の全試験で各 1 回。製品の欠陥か試験の時間依存かは未確認。原因を調べ、時間依存なら試験を直す。製品の欠陥なら別に起票する。DTAK-9・DTAK-19 から持ち越し。利用者の決定（2026-11-17）: 別タスクにする。着手は別の許可を待つ。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 原因が特定され、記録されている
- [x] #2 試験が全体実行を繰り返しても落ちない（回数は計画で決める）
- [x] #3 核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0、NewApi 0
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. 原因の特定: 300 回の繰り返しで 3 件失敗（握手が確立しない 2 件、確立したが更新が届かない 1 件）。握手の再送と、5 秒の仮の時計で制御する更新の再送が、一度だけの時計の進めでは足りないと推定。
2. 修正（試験だけ）: 待つ間に仮の時計を一定の間隔で進める補助（untilAdvancing）を足し、2 つの待ちに使う。
3. 検証: 修正後に 300 回繰り返して失敗 0 を確かめ、全体の試験・lint を通す。DTAK-24 と原因が同じかを記録する。
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
原因: 修正前に 300 回で 3 件失敗（握手が確立しない 2 件、確立したが更新が届かない 1 件）。握手の再送と、5 秒の仮の時計で制御する更新の再送は、仮の時計を進めないと起きない。試験の仮の時計を一度しか進めないため、握手や更新が最初の試行で通らないとき、再送の機会が来ないまま 5 秒の上限に達していた。製品の欠陥ではなく試験の時間依存。修正: 待つ間に仮の時計を 100 回の確認ごとに 5 秒進める補助 untilAdvancing を足し、握手の待ちと更新の待ちに使う。検証: 修正後 300 回で失敗 0。全試験: 核 1,675・プラグイン 799、失敗・スキップ 0、lint 0、NewApi 0。なお全体の 1 回目で別の NamingScreenTest・AdministrationButtonsTest が落ちた（再実行で通る）。DTAK-28 に分けた。
<!-- SECTION:NOTES:END -->
