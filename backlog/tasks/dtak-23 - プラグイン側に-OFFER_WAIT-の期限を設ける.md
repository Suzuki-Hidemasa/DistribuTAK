---
id: DTAK-23
title: プラグイン側に OFFER_WAIT の期限を設ける
status: To Do
assignee: []
created_date: '2026-11-17 12:40'
labels:
  - enhancement
dependencies: []
references:
  - DTAK-9
ordinal: 23000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DTAK-9 第10回の調査で、プラグイン側に OFFER_WAIT の期限がないことが分かった（docs/04 §4.5「既知の限界・持ち越し」）。相手が応答しないとき待ちが終わらない恐れがある。期限の長さと、期限が切れたときの扱い（取り消し・再試行・表示）は、設計で決める。新しい暗号・形式は足さない。利用者の決定（2026-11-17）: 別タスクにする。着手は別の許可を待つ。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 期限の長さと切れたときの扱いを docs/04 に書き、レビューで必修の指摘が残っていない
- [ ] #2 期限が切れる試験と、期限内に応答が来る試験が通る
- [ ] #3 核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0、NewApi 0
<!-- AC:END -->
