---
id: DTAK-27
title: GitHub Actions の CI を作る（核の試験・核の Android API lint・書式と禁止ファイルの確認）
status: In Progress
assignee:
  - claude
created_date: '2026-11-18 05:23'
updated_date: '2026-11-18 05:23'
labels:
  - ci
dependencies: []
ordinal: 27000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
main への PR と main への push で、ATAK の SDK を使わない確認を GitHub Actions で自動に走らせる。ATAK の SDK はリポジトリにもアップロードにも入れられないため（CLAUDE.md ガードレール）、プラグインのビルド・試験・lint は GitHub 上では走らせられない。プラグインの確認は手元（plugin/build.sh）に残る。merge の条件（二者レビュー＋CI）の CI は、この確認を指す。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 .github/workflows/ci.yml が、main を base にする PR と main への push で動く
- [ ] #2 核の試験（core/build.sh clean test）が GitHub 上で通る
- [ ] #3 核の Android API lint（plugin/lint-core.sh。NewApi 0）が GitHub 上で通る
- [ ] #4 git diff --check と、入れてはいけないファイル（apk・jks・keystore・p12・local.properties）の確認が走る
- [ ] #5 ATAK の SDK・秘密・apk を使わない・アップロードしない。権限は contents: read だけ
- [ ] #6 プラグインの確認が GitHub 上で走らないこと、手元で走らせる手順を README か docs に書く
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. .github/workflows/ci.yml を作る。ジョブは 3 つ: core（core/build.sh clean test）、core-api-lint（plugin/lint-core.sh）、hygiene（git diff --check と禁止ファイルの確認）。
2. 権限は contents: read、同じ ref の古い実行は取り消す。
3. Java 17 は setup-java、Android SDK 36 は足りなければ sdkmanager で入れる。
4. docs か README に、GitHub 上で走る範囲と手元で走らせる範囲を書く。
5. PR を出して Actions が通ることを確かめる。
<!-- SECTION:PLAN:END -->
