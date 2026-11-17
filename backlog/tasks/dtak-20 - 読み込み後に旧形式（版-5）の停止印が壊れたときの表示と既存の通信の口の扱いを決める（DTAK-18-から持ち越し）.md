---
id: DTAK-20
title: 読み込み後に旧形式（版 5）の停止印が壊れたときの表示と既存の通信の口の扱いを決める（DTAK-18 から持ち越し）
status: To Do
assignee: []
created_date: '2026-11-17 10:21'
labels:
  - security
dependencies: []
references:
  - DTAK-18
priority: medium
type: task
ordinal: 20000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
旧形式（版 5）の保存を読み込んだあと、実行中に停止印が壊れた（読み込み後の破損）ときの扱いが未決。現状は安全側に動く: 保存は IOException で拒否され、新しい通信の口は開かず、再起動すると起動前の検査が INVALID で止まる。ただし storageBlocked と invalidStopMarker は立たないので、INVALID の固定文が必ず出るとは限らない。決めること: (1) 固定文を出すか。(2) すでに開いている通信の口を閉じるか、そのままか。docs/04 §4.5（335 行・757 行付近）はこの場合を決めていない。DTAK-18 の二者のレビュー（out/reviews/dtak18/）から持ち越し。利用者の決定（2026-11-17）: 未決は持ち越しとして Backlog に入れる。DTAK-18 の PR #21 は main に入っている。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 表示（INVALID の固定文を出すか）と、既存の通信の口を閉じるかどうかを、利用者が決めて docs/04 §4.5 に書いてある
- [ ] #2 決めた動きを確かめる試験が、機能の欠如で落ちる形で先にある
- [ ] #3 核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0、NewApi 0
<!-- AC:END -->
