---
id: DTAK-28
title: NamingScreenTest の再接続待ちが全体実行で時々落ちる（AdministrationButtonsTest も巻き込む）
status: To Do
assignee: []
created_date: '2026-11-18 08:28'
labels:
  - testing
dependencies: []
references:
  - DTAK-21
  - DTAK-24
ordinal: 28000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DTAK-21・24 の確認で全プラグイン試験を流したとき（5 分 31 秒かかった 1 回目）、NamingScreenTest.reconnect の「名前の確認を待てませんでした。確認待ち=true、保持役=true、接続=false」で 2 件落ちた（NamingScreenTest.namingNeedsReconnectAndSeparateSaveConfirmation と、reconnect を使う AdministrationButtonsTest.failureBeforeGrantSaveKeepsCommunicationAndStoredMembership）。2 クラスだけの再実行と全体の再実行では通った。再接続の握手の時間依存（DTAK-21 と同じ型の疑い）。製品の欠陥か試験の待ちの不足かを調べ、試験の問題なら直す。着手は別の許可を待つ。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 原因が特定され、記録されている
- [ ] #2 この試験が全体実行を繰り返しても落ちない（回数は計画で決める）
- [ ] #3 核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0、NewApi 0
<!-- AC:END -->
