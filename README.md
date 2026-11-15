<!-- SPDX-License-Identifier: GPL-3.0-only -->
# DistribuTAK

DistribuTAK は、ATAK のプラグインです。
同じ鍵グループの端末（Android）どうしが、LAN・WAN・モバイル回線の上で CoT を同期します。
各端末が、分散型の TAK サーバーの役を持ちます。

このリポジトリは、PRC-163 から 2026-11-16 に分けました。
履歴は引き継いでいません。分ける前の履歴は PRC-163 にあります。

## 構成

| 場所 | 中身 |
|---|---|
| `core/` | 核。Android に依存しない Java のライブラリ（Noise の握手、暗号化、証明書、管理者の記録、DHT など） |
| `plugin/` | ATAK のプラグイン本体（Android アプリ）。使い方は `plugin/README.md` |
| `docs/` | 設計書。要件、機能、基本設計、詳細設計（`docs/README.md` が入口） |
| `tools/` | 実機の試験のための補助スクリプト |

設計の決定の記録（ADR 0030 など）と、法令の整理（`docs/legal.md` の Q100・Q107）は、PRC-163 にあります。
文書では `PRC-163:docs/...` と書いて指しています。

## ビルドと試験

必要なもの: Java 17、Python 3、Android SDK（platform 36）。
プラグインのビルドには、ATAK の SDK の jar も要ります。SDK はこのリポジトリに入れません。
`plugin/local.properties`（git に入れない）に、jar の絶対パスと署名の設定を書きます。

```bash
core/build.sh clean test                       # 核の試験
cd plugin && ./build.sh assembleCivDebug testCivDebugUnitTest lintCivDebug -x takdevLint
cd plugin && ./lint-core.sh                    # 核を minSdk 23 で解析する（NewApi が 0 件）
```

ビルドの出力・Gradle のキャッシュ・試験のベクトルは `out/` に置きます（git に入れない）。
初回は、公開の試験ベクトルをネットから取り、固定のハッシュで照合します。

## 守ること

- ATAK の SDK のコード、署名の鍵、キーストアのパスワードをリポジトリに入れません。
- 脆弱性は公開の Issue に書かず、`SECURITY.md` の窓口へ報告してください。
- 開発の進め方は `CONTRIBUTING.md` にあります。

## ライセンス

GPL-3.0-only です。全文は `LICENSE` にあります。
