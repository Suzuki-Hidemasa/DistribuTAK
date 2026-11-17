---
id: DTAK-19
title: >-
  既存の出力から短い識別値を外す: rememberPublicGroup の画面表示と LanSupport.receipt の受信ログ（DTAK-9 9b
  から持ち越し）
status: In Progress
assignee:
  - '@claude'
created_date: '2026-11-17 08:33'
updated_date: '2026-11-17 08:40'
labels:
  - security
dependencies: []
priority: medium
ordinal: 19000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ガードレールは識別子・ハッシュを文書・ログに書かないと定めている。9b より前からある次の 2 つの出力に、短い識別値が出る。(1) 状態画面の rememberPublicGroup の短い識別値の表示。(2) LanSupport.receipt（36 行付近、LanController.drainInbox から呼ばれる）の受信ログの短い相手の識別値。利用者の決定（2026-11-17）: 別タスクで消す・伏せる。9b の機微値の検査記録 out/agents/dtak9-r9b-privacy-inspection.md に未解消として載っている。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 状態画面と受信ログから短い識別値が出ない（件数・種類の表示は可）
- [ ] #2 出していないことを確かめる試験が、記録を実際に検査する形である
- [ ] #3 既存の試験を弱めない。核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0
<!-- AC:END -->
