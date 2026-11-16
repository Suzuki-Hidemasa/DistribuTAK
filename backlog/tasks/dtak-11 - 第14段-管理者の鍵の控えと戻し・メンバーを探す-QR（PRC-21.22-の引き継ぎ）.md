---
id: DTAK-11
title: '第14段: 管理者の鍵の控えと戻し・メンバーを探す QR（PRC-21.22 の引き継ぎ）'
status: To Do
assignee: []
created_date: '2026-11-16 00:24'
labels:
  - stage-14
dependencies:
  - DTAK-9
references:
  - 'PRC-163:backlog/tasks/prc-21.22'
  - 'PRC-163:docs/decisions/0030-device-as-lan-router.md'
priority: medium
ordinal: 11000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ADR 0030 答え 167 の第14段。管理者の鍵の控えを QR コードで出し、カメラで戻す（DT-FN-30・31）。メンバーを見つける QR コードと管理者の鍵の写しの QR コードの形（答え 100・107。答え 92 の扱いは鍵の写しにだけ当てる）。QR の画面はスクリーンショットを撮らせない（第9段と同じ）。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 核で、QR の 2 つの種類の組み立てと読み取り（確かめる値の合わないものを断る）を PC の試験で確かめている
- [ ] #2 プラグインで、鍵の控えを出して別の EUD で戻し、管理者として振る舞えることを PC の試験で確かめている
- [ ] #3 核・プラグインの試験と lint が通る（核 core/build.sh clean test、プラグイン cd plugin && ./build.sh assembleCivDebug testCivDebugUnitTest lintCivDebug -x takdevLint、plugin/lint-core.sh で NewApi 0 件、git diff --check）
- [ ] #4 細目は作業者の案と二者の討論のレビューで決め、PRC-163:docs/decisions/0030-device-as-lan-router.md と docs/04-detailed-design.md に書いてある。レビューで必修の指摘が残っていない
- [ ] #5 S20 と Xperia 1 の間で、鍵の控えの QR を読んで戻すことと、メンバーを探す QR を読むことを確かめている
- [ ] #6 logcat に CoT の中身・鍵・招待・TOTP・PSK が出ていない（鍵の控えの中身も出ていない）
<!-- AC:END -->
