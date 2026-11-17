---
id: DTAK-19
title: >-
  既存の出力から短い識別値を外す: rememberPublicGroup の画面表示と LanSupport.receipt の受信ログ（DTAK-9 9b
  から持ち越し）
status: Done
assignee:
  - '@claude'
created_date: '2026-11-17 08:33'
updated_date: '2026-11-17 10:21'
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
- [x] #1 状態画面と受信ログから短い識別値が出ない（件数・種類の表示は可）
- [x] #2 出していないことを確かめる試験が、記録を実際に検査する形である
- [x] #3 既存の試験を弱めない。核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
PR #22 で main に入った。LAN の状態画面は短い識別値の代わりに「グループ: 参加済み」「相手: 未登録／登録済み」を出し、自分の識別値の欄を削除した。受信ログは LAN_TEST_RX count=<件数> とし、LanSupport.shortId を削除した。plugin/README.md を実装に合わせた。LanOutputPrivacyTest（3 件）は、作成直後・加入後・接続後・保存からの再読込の各段階で、描画した文字列を実際に検査する。直す前は検出して落ち、表示を欠落させると赤になることを確認した。LanSupportTest の期待値を新しいログの形に変えた。確認: 核 1,650 件、プラグイン 762 件、失敗・スキップ 0、lint エラー 0、NewApi 0。二者のレビューは必修なし、推奨 1 件は修正済み。作業者の最初の全試験で既存の LanBehaviourFixTest が 1 件時間切れになったが、変更なしの再実行で成功し、原因は未確認。実機は未確認。
<!-- SECTION:FINAL_SUMMARY:END -->
