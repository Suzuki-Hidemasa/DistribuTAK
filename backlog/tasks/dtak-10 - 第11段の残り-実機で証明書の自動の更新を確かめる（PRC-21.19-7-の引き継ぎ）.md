---
id: DTAK-10
title: '第11段の残り: 実機で証明書の自動の更新を確かめる（PRC-21.19 #7 の引き継ぎ）'
status: To Do
assignee: []
created_date: '2026-11-16 00:24'
updated_date: '2026-11-17 12:54'
labels:
  - stage-11
  - device
dependencies: []
references:
  - 'PRC-163:backlog/tasks/prc-21.19'
  - docs/04-detailed-design.md
priority: medium
ordinal: 10000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRC-163 のタスク PRC-21.19（第11段）の残りの受入の条件 #7。第9段の試験のグループの証明書は 2026-11-13 に作り直したもので、残り 1/3 になる 2026-12-03 ごろより後に、S20 と Xperia 1 で自動の更新を確かめる。期限を短くする・閾値を下げる仕組みは作らない（ADR 0030 答え 178 (4)）。それまで 2 台で消去もグループの作り直しもしない。実機に触れるのは利用者かオーケストレーターだけ。未決として、管理者が長く止まり、メンバーの持つ管理者の証明書が切れた場合（04 の 4.4 の末尾）の扱いもここに引き継ぐ。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 S20 と Xperia 1 で、残り 1/3 になったあとに証明書が自動で更新され、残りの日数と更新の回数の表示が変わることを確かめている（2026-12-03 ごろ以降）
- [ ] #2 管理者の証明書が切れた場合の扱い（04 の 4.4 の末尾の未決）を二者のレビューで決め、PRC-163:docs/decisions/0030-device-as-lan-router.md と docs/04-detailed-design.md に書いてある
- [ ] #3 logcat に CoT の中身・鍵・招待・TOTP・PSK が出ていない（起動し直す前から logcat をファイルに流して取る）
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
【AC#2 の決定（2026-11-17）】二者のレビュー（Astra・Fable 5.2。out/reviews/dtak10-ac2/conclusion.md）の合意を受け、利用者が案 A を採ると決めた。文と試験は DTAK-25 で行う。管理者もメンバーも証明書が切れた場合の復旧は DTAK-26 に分けた（利用者が別タスクにすると決めた）。AC#2 は、DTAK-25 が終わり、ADR 0030 への追記（PRC-163 側。利用者が書く）が済んだら印を付ける。
<!-- SECTION:NOTES:END -->
