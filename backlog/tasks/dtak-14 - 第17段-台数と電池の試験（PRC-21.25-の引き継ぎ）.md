---
id: DTAK-14
title: '第17段: 台数と電池の試験（PRC-21.25 の引き継ぎ）'
status: To Do
assignee: []
created_date: '2026-11-16 00:24'
labels:
  - stage-17
dependencies:
  - DTAK-13
references:
  - 'PRC-163:backlog/tasks/prc-21.25'
  - 'PRC-163:docs/decisions/0030-device-as-lan-router.md'
priority: low
ordinal: 14000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ADR 0030 答え 167 の第17段。DT-NF-01（2・5・10 台の EUD と電池）を確かめる。実機は利用者の S20 と Xperia 1 の 2 台だけなので、5 台と 10 台は PC の模擬で確かめる。S23 は使わない。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 PC の模擬で 5 台と 10 台の同期（届く時間・送る量）を測り、PRC-163:docs/decisions/0030-device-as-lan-router.md か docs/04-detailed-design.md に書いている
- [ ] #2 S20 と Xperia 1 で、決めた時間つないだままの電池の減りを測って記録している
- [ ] #3 核・プラグインの試験と lint が通る（核 core/build.sh clean test、プラグイン cd plugin && ./build.sh assembleCivDebug testCivDebugUnitTest lintCivDebug -x takdevLint、plugin/lint-core.sh で NewApi 0 件、git diff --check）
- [ ] #4 細目は作業者の案と二者の討論のレビューで決め、ADR 0030 と docs/04-detailed-design.md に書いてある。レビューで必修の指摘が残っていない
<!-- AC:END -->
