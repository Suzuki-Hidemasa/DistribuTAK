---
id: DTAK-24
title: InitialManagementTest の待ち条件に管理 DHT の準備完了を足す
status: In Progress
assignee:
  - '@claude'
created_date: '2026-11-17 12:40'
updated_date: '2026-11-18 08:28'
labels:
  - testing
dependencies: []
references:
  - DTAK-9
  - DTAK-21
ordinal: 24000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
InitialManagementTest.initialJoinManagementDhtDeliveryPersistsAndFirstUpdatesRoster が、端点の確立と名簿は待つが、DHT 側の peers.isYes を待たない。そのため publishManaged が false になり落ちることがある（観測用の試験で 80 回中 6〜7 回。DTAK-9 第10回の変更とは無関係）。DTAK-21（LanBehaviourFixTest の不安定）と同じ型かは未確定で、同じ調査に入れてよいかも調べる。isYes を 5 秒待つだけでは足りなかったので、待ち時間の延長では直さない。false の分岐を見分けられる診断も足す。利用者の決定（2026-11-17）: 別タスクにする。着手は別の許可を待つ。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 管理 DHT の準備ができたことを待つ条件が試験に入り、publishManaged が false になる分岐を見分けられる診断が出る
- [x] #2 この試験が全体実行を繰り返しても落ちない（回数は計画で決める）
- [x] #3 DTAK-21 と原因が同じか別かを記録する
- [x] #4 核・プラグインの全試験が 0 失敗・0 スキップ、lint エラー 0、NewApi 0
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. 原因の特定: 管理 DHT の公開が false を返す場面を 80 回の繰り返しで再現（約 5%）。状態は PROBING（PONG がまだ戻らない）か UNKNOWN・セッションなし。
2. 修正（試験だけ）: 公開の前に「相手が YES で今のセッションがある」ことを until で待つ。false のときは理由の手がかり（状態・セッション有無・探りの送信数）を表示する。
3. 検証: 修正後に 300 回繰り返して失敗 0 を確かめ、全体の試験・lint を通す。
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
原因: 試験が端点の確立と名簿だけを待ち、DHT 側の探り（PING→PONG で YES、かつ今のセッション）の完了を待たずに publishManaged を呼んでいた。80 回中 4 回、状態が PROBING か UNKNOWN（セッションなし）で false になった。修正: dhtReady（YES かつセッションあり）を until で待ち、false の分岐には状態・セッション有無・探りの送信数・確立の診断を出す（識別子は出さない）。検証: 修正後 300 回で失敗 0。DTAK-21 との関係: どちらも「試験が準備や時間駆動の再送の機会を作らずに待つ」型だが仕組みは別（DTAK-24 は DHT の探りの完了、DTAK-21 は握手の再送と 5 秒の仮の時計で動く更新の再送）。同じ修正では直らないので別のまま。全試験: 核 1,675・プラグイン 799、失敗・スキップ 0、lint 0、NewApi 0。
<!-- SECTION:NOTES:END -->
