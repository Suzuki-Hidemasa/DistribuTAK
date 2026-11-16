---
id: DTAK-8
title: 保存が成功して公開が失敗すると、準備の状態が CANCELLED になり得る（DTAK-1 の L1）
status: Done
assignee:
  - '@claude'
created_date: '2026-11-16 00:02'
updated_date: '2026-11-16 00:18'
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
- [x] #1 保存が成功して公開が失敗したあと、expired()・cancel() が状態を CANCELLED に変えない試験がある
- [x] #2 保存の前の期限の検査は今までどおり働く
- [x] #3 核の試験・lint・NewApi が合格の目安どおり
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. 試験を先に書く（PreparationPersistStateTest。5 件）。2. Preparation に saved の印を足し、persist の保存成功の直後に立てる。3. 公開まで成功したら persist が completed() で COMPLETE にする（publish 経由でも直接でも同じ）。4. expired()・cancel() は saved なら状態を変えない。5. 04 §4.5 に契約を書く（案B）。
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
実装: GroupAdministration.persist が保存成功後に Preparation.saved を立て、公開成功後に completed() で COMPLETE にする。Preparation.publish は persist を呼ぶだけにした。expired()・cancel() は saved のとき状態を変えない。保存前の期限の検査（validateCandidate の最初の呼び出し）は変えていない。暗号・保存の版 5・HPKE の info/aad・署名の前置きは変えていない。検証: 核 1,185 件（元の 1,180 件 + 新 5 件）失敗・スキップ 0、プラグイン 416 件失敗・スキップ 0、lintCivDebug 成功、lint-core.sh は NewApi 0、git diff --check 問題なし。
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
案 B で persist の契約を決めた。保存に成功したら Preparation の saved を立て、以後 expired()・cancel() は状態を CANCELLED に戻さない。公開まで成功したら persist が COMPLETE にするので、publish 経由でも persist 直接でも同じ。保存前の期限の検査と、保存失敗時の期限切れ・取り消しは今までどおり。試験 PreparationPersistStateTest（5 件）で確認。核 1,185 件・プラグイン 416 件 失敗・スキップ 0、lintCivDebug 成功、NewApi 0。04 §4.5 に契約を追記。
<!-- SECTION:FINAL_SUMMARY:END -->
