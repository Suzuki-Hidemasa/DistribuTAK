---
id: DTAK-15
title: 自作の物と大きな CoT の同期（第10段から持ち越し。PRC-21.26 の引き継ぎ）
status: To Do
assignee: []
created_date: '2026-11-16 00:24'
labels:
  - stage-10
dependencies: []
references:
  - 'PRC-163:backlog/tasks/prc-21.26'
  - 'PRC-163:docs/decisions/0030-device-as-lan-router.md'
  - docs/04-detailed-design.md
priority: low
ordinal: 15000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ADR 0030 答え 177 で第10段から持ち越した分。自分の ATAK で作ったマーカーの追加・変更・削除と、1176 バイトを超える CoT を、S20 と Xperia 1 の間で同期する。いまは ATAK の地図の物が「この端末で利用者が作った物」かを公開 API で確かめる根拠が無く、送る種類の表は空（答え 174 (a)）。見え方や通知で推定する案・条件を緩める案・新しい証拠を作る案（U5。答え 172 (1)）は採らない。始める時期は利用者が決める。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 04 の 7 章「送る物の見分け方」の条件 ①〜⑤ を 1 行ごとにそろえた送る種類の表が、根拠つきで二者のレビューで決まり、ADR 0030 と docs/04-detailed-design.md に書いてある。根拠が見つからないときは、その結果を利用者に報告して止める
- [ ] #2 所有の判定と、捕まえる・消す処理のつなぎ（いまは owns が false）と、遅れて読み込まれる既存の物（diag7 R4）の扱いが二者のレビューで決まり、PC の試験で確かめている
- [ ] #3 S20 と Xperia 1 で、自作のマーカーの追加・変更・削除と大きな CoT（1176 バイト超）が両方向に届く。削除は 60〜80 秒たってから件数を読み直す。削除の操作は利用者が行う（答え 174 (2)）
- [ ] #4 logcat に CoT の中身・鍵・招待を出さない。記録は件数と分類だけ
<!-- AC:END -->
