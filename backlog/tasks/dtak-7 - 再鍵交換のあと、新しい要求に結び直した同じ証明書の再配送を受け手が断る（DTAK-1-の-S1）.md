---
id: DTAK-7
title: 再鍵交換のあと、新しい要求に結び直した同じ証明書の再配送を受け手が断る（DTAK-1 の S1）
status: To Do
assignee: []
created_date: '2026-11-16 00:02'
labels:
  - review
  - core
dependencies: []
references:
  - out/reviews/20261116-distributak-stage13-r3fix/conclusion.md
priority: medium
ordinal: 7000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DTAK-1 のレビューの推奨 1 件（S1）。対象は core の GroupAdministration.java の受信（:291-296 付近）と Preparation.next（:383-386 付近）。まだ製品につながっていない部分の中の指摘で、必修ではない。

【起きること】受け手が配送を保存したあと、送り手がそれを知る前に再鍵交換になり、送り手が confirm より先に next を呼ぶと、新しい要求番号が作られる。本人証明が形式2だった相手には、発行済みの同じ証明書を新しい要求に結んだ配送が行き、受け手は要求が合わず断る。形式1だった相手には新しい要求が行き、基準の証明書が合わず断る。送り手の confirm は新しいセッションで FIRST の証明書を確かめて確定できるので、準備がいつも止まるわけではない。害は、むだな要求と拒否が 60 秒まで続き得ることと、上位が拒否を失敗と扱うおそれ。

【試験の弱さ】AdministrationDeliveryTest.duplicateAcceptedCertificateDeliveryMustBeIdempotent の「再鍵交換のあとの重複」は、前の配送メッセージをそのまま渡している。送り手が新しいセッションで作る配送は通っていない。

【決めること（04 の 4.5 と試験）】(a) 新しい要求に結び直した同じ証明書の配送を、どこまで成功にするか決めて実装する。(b) 再鍵交換のあとは confirm を先に行い、確定できないときだけ next を呼ぶ、という呼ぶ順を決める。どちらでも、認証・今の管理者との対応・証明書の検証・FIRST の確定の条件は保つ。受領の記録との照合をただ外す案は取らない（DirectDeliveryValidationTest の期待が変わるため）。受け手の再起動のあと（受領の記録が消える）は、形式2更新後の読み戻しの持ち越し（ADR 0030 答え 214 の 10 (h)。期限は第7回）に含め、このタスクの対象にしない。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 04 の 4.5 に、再鍵交換のあとの配送の扱い（(a) か (b)）が書かれている
- [ ] #2 送り手が新しいセッションで作った配送を受け手に渡す試験がある
- [ ] #3 認証・管理者の対応・証明書の検証・FIRST の確定の条件が緩んでいない（別の証明書・古い証明書は成功にならない）
- [ ] #4 核の試験・lint・NewApi が合格の目安どおり
<!-- AC:END -->
