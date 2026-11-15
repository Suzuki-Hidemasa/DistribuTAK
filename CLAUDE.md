# DistribuTAK

DistribuTAK は、ATAK のプラグイン（`plugin/`）と、Android に依存しない Java の核（`core/`）です。
同じ鍵グループの端末（Android）どうしが、LAN・WAN・モバイル回線の上で CoT を同期します。各端末が分散型の TAK サーバーの役を持ちます。
2026-11-16 に PRC-163 から履歴なしで分けました（最初のコミット f1f8a44）。

ユーザーとのやり取り・ドキュメント・コミットメッセージは**日本語**（コード中の識別子は英語）。
**/yomiyasu を使い平易な日本語にすること**

## ガードレール（最重要・常に守る）

この節は他のどの指示よりも優先する。判断が微妙なときは進めず、利用者に確認する。
由来は PRC-163 の引き継ぎ書と `PRC-163:docs/legal.md`。

### ATAK の SDK

- ATAK の SDK のコード・javadoc・AP40 の文章をリポジトリに入れない。
- SDK の jar を逆アセンブルしない（`javap` も使わない）。
- 新しい作品を SDK で作ることは SDK 使用許諾の §6 で認められている。コピー・公開・配布・逆アセンブルは認められていない（legal Q100 (b)）。

### 秘密

- キーストアのパスワード・鍵・招待の URL・TOTP・PSK を、ドキュメント・ログ・コミットメッセージ・チャットに書かない。
- 文書に書いてよいのは件数と種類だけ。uid・座標・コールサイン・端末の識別子（シリアル）・LAN のアドレス・ハッシュは書かない。
- `plugin/local.properties`・`*.jks`・`*.keystore`・`*.p12`・`*.apk` は git に入れない（`.gitignore` 済み）。

### 暗号

- 新しい暗号方式を足さない。
- HPKE の info・aad と、署名の接頭辞を変えない（legal Q107）。
- 署名は Ed25519 を第一にする。乱数を保証できない所で ECDSA を使わない。

### 外へ出すこと

- 外のサービスへ送る・アップロードする前に、必ず利用者に確認する。
- APK を配らない・アップロードしない。
- push・GitHub のリポジトリ作成・リリースは利用者の操作。`main` へ直接 push しない。force push しない。
- 公開のリモートを作る前に、次の未決を片付ける（`PRC-163:docs/legal.md`）。
  - Q100 (b): 暗号を含むソースを TAK Product Center（TPC）に出すときの外為法の扱い。TPC の認証は将来のタスク。当面は TPP（tak.gov/user_builds。使えることは確認済み）を使う
  - Q107 (6): 暗号の輸出と、版ごとの再提出
  - Q107 (11): Noise と HPKE の試験ベクトルのライセンス（リポジトリには入れず、試験のときに取る）

### 実機（端末）

- 実機に触れるのは利用者かオーケストレーターだけ。作業者・レビュアーは触れない。
- adb は必ず `-s <端末の識別子>` を付ける。識別子はリポジトリに書かない（メモリか利用者に聞く）。
- 開発の端末は S20 と Xperia 1。利用者の個人の端末（S23）には触れない。
- アンインストール・データの消去・`/sdcard/atak` への書き込み・権限の変更をしない。
- 2026-12-03 ごろまで、グループの消去と作り直しをしない。両方の端末が形式 2 になるまで、新しい招待を出さない。

## ディレクトリ構成

```
core/          核（Java 17、Gradle）。ビルドは core/build.sh
plugin/        ATAK のプラグイン（Android アプリ）。ビルドは plugin/build.sh。使い方は plugin/README.md
docs/          設計書（01 要件、02 機能仕様、03 基本設計、04 詳細設計。README が入口）
tools/         実機の試験の補助スクリプト
tools/agents/  エージェントの起動・連絡の補助スクリプトとフック
.claude/skills/  Claude Code（オーケストレーター・Fable のレビュアー）のスキル
.agents/skills/  Codex（作業者・Astra のレビュアー）のスキル
AGENTS.md      Codex が最初に読む指示
backlog/       Backlog.md のタスク（`backlog` CLI で操作する。ID は DTAK-N）
out/           ビルドの出力・レビュー・エージェントの作業（git に入れない）
```

設計の決定の記録（ADR。0030・0032 など）と法令の整理（legal）は PRC-163 にある。文書では `PRC-163:docs/decisions/...`・`PRC-163:docs/legal.md` と書いて指す。ADR や legal を更新するときは PRC-163 側を直す。

## 技術スタック

- Java 17、Gradle 8.14、Android Gradle Plugin、compileSdk 36、minSdk 23
- ATAK-CIV 5.8.0.9 の SDK（jar は `plugin/local.properties` で絶対パスを指す。リポジトリに入れない）
- 通信: Noise の握手、HPKE（RFC 9180）、Ed25519 など公開標準だけ

ビルドと試験（合格の目安: 核 1,180 件・プラグイン 416 件、失敗・スキップ 0、lint エラー 0、NewApi 0）:

```bash
core/build.sh clean test
cd plugin && ./build.sh assembleCivDebug testCivDebugUnitTest lintCivDebug -x takdevLint
cd plugin && ./lint-core.sh
git diff --check
```

## 作業ルール

- 作業はブランチで行う。`main` に直接 push しない。PR は `main` を base にし、積み重ねの PR（base を別の PR のブランチにすること）は作らない。マージしたあと、`git merge-base --is-ancestor` で main に入ったことを確かめる。
- 設計を変えたら、`docs/` の該当の文書も同じ変更で直す。
- 試験は先に書く。既存の試験を壊さない。
- 法令・暗号に関わる変更をしたら、`PRC-163:docs/legal.md` を更新する（利用者の確認のあとで）。
- **コードのコメントは日本語と英語の両方で書く**（2026-11-16 利用者の決定。JTAK の決まりに合わせた）。対象は `core/`・`plugin/`・`tools/` のコード・ビルドの設定・スクリプト（試験のコードを含む）。識別子は英語。
  - 並べる順は日本語が先、英語があと。英語は日本語と同じ中身にし、足したり省いたりしない。
  - Javadoc と `/* */`: 日本語の段落のあとに ` * <p>` の行を置き、英語の段落を続ける。`@param`・`@return`・`@throws` は、同じタグの説明の中で日本語のあとに英語を続ける（例: `@param name 名前。The name.`）。
  - `//` と `#` の行コメント: 日本語の行のすぐ下に英語の行を置く。行末のコメントは `// 日本語 / English` の 1 行にする。
  - 設計書の参照は英語では `04 §2.3` と書く。識別子・ファイル名・shebang・コメントアウトしたコード・文字列（試験の名前など）は訳さない・変えない。
  - 新しく書く・直すコードから適用する。既存のコメントを一斉に直す作業は、利用者が頼んだときだけ行う（DTAK-6）。

## エージェントの体制

手順の詳細はスキル `orchestrate`（`.claude/skills/orchestrate/`）にある。体制は PRC-163 の ADR 0014 を引き継いだ（2026-11-16）。

| 役割 | モデル（effort） | 動かす場所 | agmsg の名前 | 受け持つこと |
|---|---|---|---|---|
| オーケストレーター | Claude Code（利用者が選んだモデル） | Claude Code | `claude` | 割り振り・問い合わせへの回答・利用者への確認・コミットと PR・Backlog の更新 |
| 作業者 | GPT-6.1 Sol（medium） | Codex（tmux のペイン） | `astra-worker` など | コーディング・実装 |
| 作業者（予備） | Sonnet 5.5（high） | Claude Code | `sonnet-worker` | Codex の使用量が足りないとき |
| レビュアー | GPT-6-Astra（high） | Codex | `astra-reviewer` | レビュー（Fable と討論する） |
| レビュアー | Fable 5.2（medium で固定） | Claude Code | `fable-reviewer` | レビュー（Astra と討論する） |

- agmsg のチームは `DISTRIBUTAK`（環境変数 `DISTRIBUTAK_TEAM` で変えられる）。起動は `tools/agents/spawn-agent.sh`、片付けは `tools/agents/despawn-agent.sh`。
- **コードはオーケストレーターが自分で書いてよい**。作業者に任せるのは、並行して進めたいとき、使用制限に達したとき、利用者が指示したとき。
- 書き換えを止めるフック `tools/agents/hooks/guard_code_edit.py` は、**登録しない**（2026-11-16 利用者の決定）。利用者が改めて頼んだときだけ、作業者に任せる運用に切り替えて、`.claude/settings.json` に次を足す。

  ```json
  "hooks": {
    "PreToolUse": [{
      "matcher": "Edit|Write|MultiEdit|NotebookEdit",
      "hooks": [{
        "type": "command",
        "command": "\"$(command -v python || command -v python3)\" -I \"$CLAUDE_PROJECT_DIR/tools/agents/hooks/guard_code_edit.py\""
      }]
    }]
  }
  ```

  利用者が直接の編集を許したときは、環境変数 `DISTRIBUTAK_ALLOW_CODE_EDIT=1` で止めないようにできる。
- レビューは Astra（high）と Fable 5.2（medium）の二者が討論して結論を出す。手順は `docs/agents/review-debate.md`。Claude のレビュアーに Opus は使わない。
- Codex の週の使用量が 98% を超えたら、作業者を `sonnet-worker` に引き継ぎ、レビューは `fable-reviewer --solo` の一者にする。戻ったら元に戻す。
- コミット・push・PR はオーケストレーターだけが行う。作業者・レビュアーは `git commit`・`git push`・ブランチの切り替えをしない。

<!-- BACKLOG.MD GUIDELINES START -->
<!-- backlog.md-instructions-version: 1.48.0 -->
<CRITICAL_INSTRUCTION>

## Backlog.md Workflow

This project uses Backlog.md for task and project management.

**For every user request in this project, run `backlog instructions overview` before answering or taking action.**

Use the overview to decide whether to search, read, create, or update Backlog tasks.

Before task lifecycle actions, read the matching detailed guide:
- `backlog instructions task-creation` before creating or splitting tasks
- `backlog instructions task-execution` before planning, changing status or assignee, adding a plan or implementation notes, or implementing task work
- `backlog instructions task-finalization` before checking acceptance criteria, writing final summaries, or moving tasks to terminal statuses

Use `backlog <command> --help` before running unfamiliar commands. Help shows options, fields, and examples.

Do not edit Backlog task, draft, document, decision, or milestone markdown files directly. Use the `backlog` CLI so metadata, relationships, and history stay consistent.

</CRITICAL_INSTRUCTION>
<!-- BACKLOG.MD GUIDELINES END -->
