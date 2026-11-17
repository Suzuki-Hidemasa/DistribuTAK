---
id: DTAK-18
title: 旧保存（版 5）の停止印が壊れているとき、起動後に CLEAR へ作り直されて通信が開く（DTAK-9 9a から持ち越し）
status: Done
assignee:
  - '@claude'
created_date: '2026-11-17 08:33'
updated_date: '2026-11-17 10:21'
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
- [x] #1 停止印が INVALID のとき、起動後も通信を止めたままにする（CLEAR へ作り直さない）
- [x] #2 上の再現（有効な版 5 の所属＋移行の停止印＋両スロットの先頭 1 ビット反転）が、機能の欠如で落ちる試験として先にある
- [x] #3 docs/04 §4.5 と docs/state-v6-migration.md が実装と食い違わない
- [x] #4 核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0、NewApi 0
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
PR #21 で main に入った。StopMarker.canInitializeMigration を 1 か所の判定にし、inspectLegacy と initializeMigration の両方が使う。「初期確保の途中」は未作成と、長さ 0〜256B の全ゼロ領域だけ。それ以外の INVALID は旧形式でも停止し、既存の INVALID の固定文を出して通信の口を開かない。決定 B（片側 CLEAR の再初期化）は、検証できたスロットがすべて CLEAR で版・R が合う場合に限った。FileRegion.read は長さの違いを区別できる形にした。再現の試験は直す前に期待 INVALID・実際 CLEAR で落ちることを確認した。確認: 核 1,650 件、プラグイン 768 件、失敗・スキップ 0、lint エラー 0、NewApi 0、git diff --check 成功。二者のレビュー（Astra・Fable 5.2）は必修なし、推奨・軽微は修正済み。残りのリスク: 片側に有効な CLEAR が残りもう片側が壊れているときは決定 B のとおり通信が開く。読み込み後の破損の表示と口の扱いは DTAK-20 に持ち越した。実機は未確認。
<!-- SECTION:FINAL_SUMMARY:END -->
