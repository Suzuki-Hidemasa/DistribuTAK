---
id: DTAK-8
title: 保存が成功して公開が失敗すると、準備の状態が CANCELLED になり得る（DTAK-1 の L1）
status: To Do
assignee: []
created_date: '2026-11-16 00:02'
labels:
  - review
  - core
dependencies: []
references:
  - out/reviews/20261116-distributak-stage13-r3fix/conclusion.md
priority: low
ordinal: 8000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DTAK-1 のレビューの軽微 1 件（L1）。対象は GroupAdministration.java の persist（:207-215）、Preparation の expired（:412-418）、publish（:442-447）、cancel（:448）。

【起きること】Preparation.publish の中で persist が保存に成功し、公開で例外になると、phase を進める行は persist の戻りのあとにあるので COMMIT のまま残る。あとで expired() か cancel() を呼ぶと CANCELLED になる。保存した一覧は取り消されていないのに、準備は取り消しに見える。公開の失敗で管理のサービスは止まるので害は小さい。

【直し方の案】保存の前の期限の検査は残す。保存が済んだことを状態（フラグ）に持たせ、そのあとは expired()・cancel() が状態を変えないようにする。persist の契約（Preparation 由来の候補を persist に直接渡してよいか）の決定と同じ変更で直すとよい（案は別に出す）。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 保存が成功して公開が失敗したあと、expired()・cancel() が状態を CANCELLED に変えない試験がある
- [ ] #2 保存の前の期限の検査は今までどおり働く
- [ ] #3 核の試験・lint・NewApi が合格の目安どおり
<!-- AC:END -->
