---
id: DTAK-9
title: '第13段の残り: グループの管理（管理者の追加と削除・取り消しと鍵の入れ替え）を仕上げる（PRC-21.21 の引き継ぎ）'
status: To Do
assignee: []
created_date: '2026-11-16 00:24'
labels:
  - stage-13
dependencies: []
references:
  - 'PRC-163:backlog/tasks/prc-21.21'
  - 'PRC-163:docs/decisions/0030-device-as-lan-router.md'
  - docs/04-detailed-design.md
priority: medium
ordinal: 9000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRC-163 のタスク PRC-21.21（ADR 0030 答え 167 の第13段）の未了の分。管理者の追加と削除（DT-FN-21・22）、管理者の一覧と取り消しの一覧を DHT で配る（DT-FN-23・DT-SC-07）、メンバーの取り消しとグループの鍵の入れ替え（HPKE で包んだ鍵を DHT に置く。DT-FN-24）、記録の版の番号と古い版を捨てること（DT-FN-28）。第3回の直し（PRC-163 の d3b25e4）までは書いてあり、DTAK-1 でレビューした（必修なし）。第4回（自分の削除）以降はこのリポジトリで進める。DTAK-7 と DTAK-8 はこの段のレビューの後続。実機の確かめは、取り消しが 2 台のグループを変えるため、証明書の更新の確かめ（別タスク。2026-12-03 ごろ以降）との順を決めてから行う。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 核で、管理者の追加と削除・一覧の配布・取り消し・鍵の入れ替え（古い鍵のセッションは 180 秒まで）を PC の試験で確かめている
- [ ] #2 取り消したメンバーが新しい鍵を受け取れず、つながれないことを PC の試験で確かめている
- [ ] #3 核・プラグインの試験と lint が通る（核 core/build.sh clean test、プラグイン cd plugin && ./build.sh assembleCivDebug testCivDebugUnitTest lintCivDebug -x takdevLint、plugin/lint-core.sh で NewApi 0 件、git diff --check）
- [ ] #4 細目は作業者の案と二者の討論のレビューで決め、PRC-163:docs/decisions/0030-device-as-lan-router.md と docs/04-detailed-design.md に書いてある。レビューで必修の指摘が残っていない
- [ ] #5 S20 と Xperia 1 で、片方を取り消して鍵を入れ替え、取り消した側がつながれなくなることを確かめている（グループの消去と作り直しは 2026-12-03 ごろまでしない）
- [ ] #6 logcat に CoT の中身・鍵・招待・TOTP・PSK が出ていない
<!-- AC:END -->
