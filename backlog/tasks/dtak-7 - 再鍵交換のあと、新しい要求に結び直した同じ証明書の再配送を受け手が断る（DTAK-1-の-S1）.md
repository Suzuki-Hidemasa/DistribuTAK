---
id: DTAK-7
title: 再鍵交換のあと、新しい要求に結び直した同じ証明書の再配送を受け手が断る（DTAK-1 の S1）
status: Done
assignee:
  - '@claude'
created_date: '2026-11-16 00:02'
updated_date: '2026-11-16 00:33'
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
- [x] #1 04 の 4.5 に、再鍵交換のあとの配送の扱い（(a) か (b)）が書かれている
- [x] #2 送り手が新しいセッションで作った配送を受け手に渡す試験がある
- [x] #3 認証・管理者の対応・証明書の検証・FIRST の確定の条件が緩んでいない（別の証明書・古い証明書は成功にならない）
- [x] #4 核の試験・lint・NewApi が合格の目安どおり
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
実装: RenewalMessage.sameOperation（request_id 以外の一致）を足し、GroupAdministration.receiveCertificateDelivery の受領の記録の照合で sameRequest の代わりに使った。相手・証明書のバイト列の照合、受領の記録の必須は変えていない。文書: 04 §4.5 に扱いと呼ぶ順（confirm を先、確定できないときだけ next）を書いた。呼ぶ順は決まりのみで、プラグインは next/confirm をまだ呼ばない。検証: AdministrationDeliveryTest 4 件合格（新規の再鍵後の再配送・操作番号違い・古い証明書の拒否を含む）、core 1,186 件・失敗/スキップ 0、plugin 416 件・失敗 0、lintCivDebug 合格、lint-core NewApi=0、git diff --check 問題なし。
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
再鍵交換のあと、新しい要求番号に結び直した同じ証明書の配送を、受領の記録と request_id 以外がすべて同じ場合に限り、保存し直さず成功として扱うようにした（(a)）。別の操作番号・古い証明書・受領の記録なしは従来どおり断る。呼ぶ順（confirm を先、確定できないときだけ next）を 04 §4.5 に決まりとして書いた（(b)）。core 1,186 件・plugin 416 件・NewApi 0 で合格。
<!-- SECTION:FINAL_SUMMARY:END -->
