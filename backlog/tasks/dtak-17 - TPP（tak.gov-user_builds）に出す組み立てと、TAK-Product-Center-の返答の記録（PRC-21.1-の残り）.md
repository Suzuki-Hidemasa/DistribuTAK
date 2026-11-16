---
id: DTAK-17
title: TPP（tak.gov/user_builds）に出す組み立てと、TAK Product Center の返答の記録（PRC-21.1 の残り）
status: To Do
assignee: []
created_date: '2026-11-16 00:24'
labels:
  - legal
  - tpp
dependencies:
  - DTAK-3
references:
  - 'PRC-163:backlog/tasks/prc-21.1'
  - 'PRC-163:docs/legal.md'
priority: medium
ordinal: 17000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRC-163 のタスク PRC-21.1（legal Q100 (b)）の未了の分。利用者は 2026-11-11 に TAK Product Center へ問い合わせを送り（返答待ち）、TPP にソースを出すと決めた。2026-11-16 に、TPP（tak.gov/user_builds）は使えることを確認し、TPC の認証は将来のタスクと決まった（DTAK-3）。TPP に出すのはソースの zip（フォルダ 1 つで完結。atak-gradle-takdev 2.+ で TPC の Maven から SDK を取る。NDK・proto・ネイティブのライブラリの扱いを決める）。手元には TPC の Maven の資格情報が無いため、出す前の確かめができない。出すのは利用者の操作。ATAK の SDK のコード・javadoc を repo に入れない。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 作業者が TPP の決まりに合う組み立て（フォルダ 1 つ・gradlew あり）を作り、zip の中身を利用者に見せている（SDK の jar・資格情報・鍵・apk は入れない）
- [ ] #2 利用者が https://tak.gov/user_builds に出した（出す前に利用者へ確認する）
- [ ] #3 TAK Product Center の返答が来たら、PRC-163 の調査記録 8 章と PRC-163:docs/legal.md の Q100 (b) に書いてある（利用者の確認のあと）
<!-- AC:END -->
