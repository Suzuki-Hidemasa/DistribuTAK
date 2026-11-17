---
id: DTAK-18
title: 旧保存（版 5）の停止印が壊れているとき、起動後に CLEAR へ作り直されて通信が開く（DTAK-9 9a から持ち越し）
status: To Do
assignee: []
created_date: '2026-11-17 08:33'
labels:
  - security
dependencies: []
priority: high
ordinal: 18000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
旧保存（版 5）に有効な所属があり、移行の停止印が確保されている状態で、両方のスロットの先頭の 1 ビットを反転すると、起動前の検査は INVALID になるが、起動後は CLEAR に作り直され通信が開く。安全に関わる可能性がある。原因の候補は inspectLegacy() に INVALID の分岐がないこと。利用者の決定（2026-11-17）: DTAK-9 とは別のタスクにして、第10回より先に直す。実機へ入れる前に塞ぐ。参照: docs/04 §4.5、docs/state-v6-migration.md、out/reviews/dtak9-r9a/。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 停止印が INVALID のとき、起動後も通信を止めたままにする（CLEAR へ作り直さない）
- [ ] #2 上の再現（有効な版 5 の所属＋移行の停止印＋両スロットの先頭 1 ビット反転）が、機能の欠如で落ちる試験として先にある
- [ ] #3 docs/04 §4.5 と docs/state-v6-migration.md が実装と食い違わない
- [ ] #4 核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0、NewApi 0
<!-- AC:END -->
