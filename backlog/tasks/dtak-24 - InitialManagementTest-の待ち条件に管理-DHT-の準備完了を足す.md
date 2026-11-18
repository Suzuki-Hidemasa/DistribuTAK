---
id: DTAK-24
title: InitialManagementTest の待ち条件に管理 DHT の準備完了を足す
status: To Do
assignee: []
created_date: '2026-11-17 12:40'
labels:
  - testing
dependencies: []
references:
  - DTAK-9
  - DTAK-21
ordinal: 24000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
InitialManagementTest.initialJoinManagementDhtDeliveryPersistsAndFirstUpdatesRoster が、端点の確立と名簿は待つが、DHT 側の peers.isYes を待たない。そのため publishManaged が false になり落ちることがある（観測用の試験で 80 回中 6〜7 回。DTAK-9 第10回の変更とは無関係）。DTAK-21（LanBehaviourFixTest の不安定）と同じ型かは未確定で、同じ調査に入れてよいかも調べる。isYes を 5 秒待つだけでは足りなかったので、待ち時間の延長では直さない。false の分岐を見分けられる診断も足す。利用者の決定（2026-11-17）: 別タスクにする。着手は別の許可を待つ。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 管理 DHT の準備ができたことを待つ条件が試験に入り、publishManaged が false になる分岐を見分けられる診断が出る
- [ ] #2 この試験が全体実行を繰り返しても落ちない（回数は計画で決める）
- [ ] #3 DTAK-21 と原因が同じか別かを記録する
- [ ] #4 核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0、NewApi 0
<!-- AC:END -->
