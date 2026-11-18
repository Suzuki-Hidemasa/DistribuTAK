---
id: DTAK-22
title: 付与の再送で届いた後続の付与一覧によって保持者が止まる欠陥を直す
status: To Do
assignee: []
created_date: '2026-11-17 12:40'
labels:
  - bug
dependencies: []
references:
  - DTAK-9
ordinal: 22000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DTAK-9 第10回の調査（docs/04 §4.5「既知の限界・持ち越し」）で見つかった潜在欠陥。付与の再送で届いた後続の付与一覧が、前の版を保存したあとに届くと、保留の証明が期限切れなのに送信側の管理情報は一致し、長さ 0 の複製から saveMembership の前に例外が出て保持者が止まる。調査用の試験は GrantRetryInvestigationTest にある。経路は ManagedDhtStore.retry から LanDht.step。利用者の決定（2026-11-17）: 別タスクにする。着手は別の許可を待つ。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 再現する試験が先に落ち、直したあとに通る
- [ ] #2 後続の付与一覧が前の版の保存後に届いても、保持者が止まらず通信が続く（または決めた安全な側の扱いになる）
- [ ] #3 核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0、NewApi 0
- [ ] #4 docs/04 §4.5 の既知の限界の記述を直す
<!-- AC:END -->
