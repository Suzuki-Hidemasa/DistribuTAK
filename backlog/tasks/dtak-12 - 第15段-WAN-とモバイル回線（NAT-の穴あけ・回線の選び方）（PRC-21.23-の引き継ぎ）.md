---
id: DTAK-12
title: '第15段: WAN とモバイル回線（NAT の穴あけ・回線の選び方）（PRC-21.23 の引き継ぎ）'
status: To Do
assignee: []
created_date: '2026-11-16 00:24'
labels:
  - stage-15
dependencies: []
references:
  - 'PRC-163:backlog/tasks/prc-21.23'
  - 'PRC-163:docs/decisions/0030-device-as-lan-router.md'
  - 'PRC-163:docs/legal.md'
priority: low
ordinal: 12000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ADR 0030 答え 167 の第15段。CGNAT・オーバーレイ・IPv6 を先に試してから NAT の穴あけ、中継と STUN は使わない（DT-FN-10〜14）。見つけ方（QR・TOTP の URL・グループの DHT）、回線の優先と切り替え、ソケットごとの回線（bindSocket。DT-FN-15〜17）。招待に載せる番地の回線（答え 123）、外の網での加入の窓と速度（答え 159 の 2・4。44.9 秒が 10 秒に収まらない件）、DoS のクッキーと上限の値の測り直し、IPv6 の /64 と NAT の送り元の上限。実機の試験は利用者の 2 台での短い試験まで。携帯回線で常に待ち受けて中継するのは legal Q107 (3) の答えを待つ。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 核で、IPv6 と NAT の穴あけ（20 秒・各口 40 回）・回線の切り替え・外の網での加入を、遅れと落としを入れた PC の模擬で確かめている
- [ ] #2 プラグインで、ソケットごとに回線を決め（bindSocket）、Wi-Fi とモバイル回線を切り替えることを PC の試験で確かめている
- [ ] #3 核・プラグインの試験と lint が通る（核 core/build.sh clean test、プラグイン cd plugin && ./build.sh assembleCivDebug testCivDebugUnitTest lintCivDebug -x takdevLint、plugin/lint-core.sh で NewApi 0 件、git diff --check）
- [ ] #4 細目は作業者の案と二者の討論のレビューで決め、PRC-163:docs/decisions/0030-device-as-lan-router.md と docs/04-detailed-design.md に書いてある。レビューで必修の指摘が残っていない
- [ ] #5 S20 と Xperia 1 で、片方をモバイル回線にした短い試験でつながることを確かめている（常に待ち受けて中継する使い方は Q107 (3) の答えまでしない）
- [ ] #6 logcat に CoT の中身・鍵・招待・TOTP・PSK が出ていない
<!-- AC:END -->
