---
id: DTAK-13
title: '第16段: 複数のグループと hide（PRC-21.24 の引き継ぎ）'
status: To Do
assignee: []
created_date: '2026-11-16 00:24'
labels:
  - stage-16
dependencies:
  - DTAK-9
references:
  - 'PRC-163:backlog/tasks/prc-21.24'
  - 'PRC-163:docs/decisions/0030-device-as-lan-router.md'
priority: medium
ordinal: 13000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ADR 0030 答え 167 の第16段。1 台の EUD が複数のグループに同時に入れるようにする（DT-FN-35・答え 164・165）。異なるグループの間では自分のデータ（自分の位置と自分の ATAK で作った物）だけを送り、あるグループから受けたほかの人の物を別のグループへ送らない。送る物はグループごとに選び、鍵・保存・セッションはグループごとにすべて分ける（答え 165）。hide の印の物を外へ出さない扱い（DT-FN-04・02 の 6.2）もこの段で作る。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 核とプラグインで、グループ A から受けた他人の物がグループ B へ送られないことを PC の試験で確かめている
- [ ] #2 グループごとに鍵・保存・セッションが分かれ、片方を消去してももう片方が残ることを PC の試験で確かめている
- [ ] #3 hide の印の物が DistribuTAK から送られないことを PC の試験で確かめている
- [ ] #4 核・プラグインの試験と lint が通る（核 core/build.sh clean test、プラグイン cd plugin && ./build.sh assembleCivDebug testCivDebugUnitTest lintCivDebug -x takdevLint、plugin/lint-core.sh で NewApi 0 件、git diff --check）
- [ ] #5 細目は作業者の案と二者の討論のレビューで決め、PRC-163:docs/decisions/0030-device-as-lan-router.md と docs/04-detailed-design.md に書いてある。レビューで必修の指摘が残っていない
- [ ] #6 S20 と Xperia 1 で 2 つのグループを作り、グループごとに送る物を選べることを確かめている
- [ ] #7 logcat に CoT の中身・鍵・招待・TOTP・PSK が出ていない
<!-- AC:END -->
