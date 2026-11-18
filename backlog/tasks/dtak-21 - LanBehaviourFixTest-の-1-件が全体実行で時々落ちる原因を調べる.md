---
id: DTAK-21
title: LanBehaviourFixTest の 1 件が全体実行で時々落ちる原因を調べる
status: To Do
assignee: []
created_date: '2026-11-17 10:33'
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
- [ ] #1 原因が特定され、記録されている
- [ ] #2 試験が全体実行を繰り返しても落ちない（回数は計画で決める）
- [ ] #3 核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0、NewApi 0
<!-- AC:END -->
