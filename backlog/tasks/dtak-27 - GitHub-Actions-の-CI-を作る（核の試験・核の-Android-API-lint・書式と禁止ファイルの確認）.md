---
id: DTAK-27
title: GitHub Actions の CI を作る（核の試験・核の Android API lint・書式と禁止ファイルの確認）
status: Done
assignee:
  - claude
created_date: '2026-11-18 05:23'
updated_date: '2026-11-18 05:32'
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
- [x] #1 .github/workflows/ci.yml が、main を base にする PR と main への push で動く
- [x] #2 核の試験（core/build.sh clean test）が GitHub 上で通る
- [x] #3 核の Android API lint（plugin/lint-core.sh。NewApi 0）が GitHub 上で通る
- [x] #4 git diff --check と、入れてはいけないファイル（apk・jks・keystore・p12・local.properties）の確認が走る
- [x] #5 ATAK の SDK・秘密・apk を使わない・アップロードしない。権限は contents: read だけ
- [x] #6 プラグインの確認が GitHub 上で走らないこと、手元で走らせる手順を README か docs に書く
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. .github/workflows/ci.yml を作る。ジョブは 3 つ: core（core/build.sh clean test）、core-api-lint（plugin/lint-core.sh）、hygiene（git diff --check と禁止ファイルの確認）。
2. 権限は contents: read、同じ ref の古い実行は取り消す。
3. Java 17 は setup-java、Android SDK 36 は足りなければ sdkmanager で入れる。
4. docs か README に、GitHub 上で走る範囲と手元で走らせる範囲を書く。
5. PR を出して Actions が通ることを確かめる。
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PR #27（d2a80ac, merge 67b00ef）。PR の Actions と main への push の Actions がどちらも 3 ジョブ成功（core 約 3 分・core-api-lint 約 1 分・hygiene 数秒）。警告「setup-java v4 は非推奨」を受け、v5 に上げた（続きの PR）。DTAK-21 の不安定な試験（LanBehaviourFixTest）は CI でも落ち得る。落ちたら再実行する。
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
GitHub Actions の CI（.github/workflows/ci.yml）を作った。核の試験・核の Android API lint（NewApi 0）・差分の書式と禁止ファイルの確認が、main への PR と push で走る。権限は contents: read だけ。プラグインの確認は ATAK の SDK を入れられないため GitHub 上では走らず、README.md に手元で走らせる範囲を書いた。PR #27 と main への push の Actions がどちらも成功したことで確かめた。
<!-- SECTION:FINAL_SUMMARY:END -->
