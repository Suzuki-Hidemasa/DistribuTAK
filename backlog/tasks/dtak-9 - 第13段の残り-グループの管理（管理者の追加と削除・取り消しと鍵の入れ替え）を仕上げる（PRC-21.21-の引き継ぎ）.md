---
id: DTAK-9
title: '第13段の残り: グループの管理（管理者の追加と削除・取り消しと鍵の入れ替え）を仕上げる（PRC-21.21 の引き継ぎ）'
status: In Progress
assignee:
  - '@claude'
created_date: '2026-11-16 00:24'
updated_date: '2026-11-16 02:21'
labels:
  - stage-13
dependencies: []
references:
  - 'PRC-163:backlog/tasks/prc-21.21'
  - 'PRC-163:docs/decisions/0030-device-as-lan-router.md'
  - docs/04-detailed-design.md
priority: medium
ordinal: 9000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRC-163 のタスク PRC-21.21（ADR 0030 答え 167 の第13段）の未了の分。管理者の追加と削除（DT-FN-21・22）、管理者の一覧と取り消しの一覧を DHT で配る（DT-FN-23・DT-SC-07）、メンバーの取り消しとグループの鍵の入れ替え（HPKE で包んだ鍵を DHT に置く。DT-FN-24）、記録の版の番号と古い版を捨てること（DT-FN-28）。第3回の直し（PRC-163 の d3b25e4）までは書いてあり、DTAK-1 でレビューした（必修なし）。第4回（自分の削除）以降はこのリポジトリで進める。DTAK-7 と DTAK-8 はこの段のレビューの後続。実機の確かめは、取り消しが 2 台のグループを変えるため、証明書の更新の確かめ（別タスク。2026-12-03 ごろ以降）との順を決めてから行う。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 核で、管理者の追加と削除・一覧の配布・取り消し・鍵の入れ替え（古い鍵のセッションは 180 秒まで）を PC の試験で確かめている
- [ ] #2 取り消したメンバーが新しい鍵を受け取れず、つながれないことを PC の試験で確かめている
- [ ] #3 核・プラグインの試験と lint が通る（核 core/build.sh clean test、プラグイン cd plugin && ./build.sh assembleCivDebug testCivDebugUnitTest lintCivDebug -x takdevLint、plugin/lint-core.sh で NewApi 0 件、git diff --check）
- [ ] #4 細目は作業者の案と二者の討論のレビューで決め、PRC-163:docs/decisions/0030-device-as-lan-router.md と docs/04-detailed-design.md に書いてある。レビューで必修の指摘が残っていない
- [ ] #5 S20 と Xperia 1 で、片方を取り消して鍵を入れ替え、取り消した側がつながれなくなることを確かめている（グループの消去と作り直しは 2026-12-03 ごろまでしない）
- [ ] #6 logcat に CoT の中身・鍵・招待・TOTP・PSK が出ていない
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
第4回（核のみ）: 管理用DHT記録 ManagedDhtRecord（種類2〜6、外側/内側署名、DHT番号再計算）、共通検証器、同版競合・失効集合Rの比較、自己削除の例外、768B判定とTransfer境界、種類4の受け手証明書同梱（R3=A案）、3者試験。続く第5〜9回は DTAK-9 に残す。根拠: out/reviews/20261115-distributak-stage13/proposal-v3.md §3.1-3.3, §10、ADR 0030 答え208-214。
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
第4回（核）の最初の区切りを実装した（未コミットだったものをコミット）。管理用 DHT 記録の外側 ManagedDhtRecord（種類 2〜6）、DhtKeys の種類 2〜6 と版ごとの宛先、ManagedStatus・ManagedRejected、試験 約 21 件追加（核 1,207 件合格、lint-core の NewApi=0）。設計書 04 §4.5 に追記。実測: 失効が最大数値で 7 件のとき 755 バイト（768 に収まる）、8 件で 789 バイト（収まらない）。1 件ごとに 34 バイト増える。未了: 権限（管理者の連鎖）・版の競合・失効の和・自己削除の例外・種類 4 の同梱証明書の検査・三者試験（第4回の残り）、第5回以降。実機（AC 5）は証明書更新の実機試験（2026-12-03 ごろ以降）のあと。

利用者の決定「形式 1 は使用しない」を、第4回の管理用 DHT 記録に反映した（9d8bcd3）。内側の一覧は形式 2 だけを受ける（鍵の包みは形式 2 がないので対象外）。解釈: 新しい DHT 管理記録だけが対象。AdminState の旧形式の扱い（版 5 の保存・第2回の更新経路）は、読めなくしない決まりなので変えていない。核 1,208 件合格、NewApi=0。次は第4回の残り（権限・版の競合・失効の和・自己削除の例外・種類 4 の同梱証明書・三者試験）。
<!-- SECTION:NOTES:END -->
