---
name: orchestrate
description: DistribuTAK プロジェクトのオーケストレーター（Claude Code）の手順。実装を作業者の GPT-6.1 Sol（Codex）や Sonnet 5.5 に tmux のペインで依頼する、作業者・レビュアーからの問い合わせにドキュメントをもとに答える、決まっていないことを利用者に確認する、Astra と Fable 5.2 の二者の討論でレビューする、ときに使う。agmsg で astra-worker・sonnet-worker・astra-reviewer・fable-reviewer からメッセージが届いたとき、レビューが要るとき、実装を並行して進めたいときは、このスキルに従う。
---

# オーケストレーターの手順

体制と決まりは `CLAUDE.md`「エージェントの体制」。ガードレールがすべてに優先する。
agmsg のチームは `DISTRIBUTAK`、自分の名前は `claude`。補助スクリプトは `tools/agents/`。
タスクは Backlog.md（`backlog` CLI。ID は `DTAK-N`）。

**コードはオーケストレーターが自分で書いてよい**。この手順を使うのは、並行して進めたいとき、使用制限に達したとき、利用者が指示したとき、二者のレビューをかけるとき。

## 0. 前提

- WSL（Ubuntu）の tmux のセッションの中で、リポジトリ（またはそのワークツリー）で動いていること。`tools/agents/spawn-agent.sh` がペインを分割して起動する。
  `$TMUX` が空でも `PSMUX_SESSION` があれば、スクリプトが補う。どちらもなければ起動できないので、利用者に tmux の中で起動し直してもらう。
- agmsg の受信は、セッションの開始時に起動する監視（Monitor）で届く。届かないときは `~/.agents/skills/agmsg/scripts/inbox.sh DISTRIBUTAK claude`。
  ワークツリーの中で監視が即終了するときは、`AGMSG_RESOLVE_PROJECT=0` を付けて本体の場所で起動する。監視は 30 分で切れるので、切れたら張り直す。
- エージェントは高くつく。同時に動かすのは、作業者1〜2人とレビュアー2人までにする。終わったら片付ける（6章）。
- PC のメモリがコミット上限に近いと Codex・WSL が落ちる。エージェントは少なくし、落ちたら見張りで気づく。

## 1. 作業を依頼する

1. Backlog のタスク（`backlog task view <ID> --plain`）と、関係するドキュメントを読み、依頼の範囲を決める。
   タスクがなければ `backlog task create` で作る。依頼したらタスクを In Progress にする（`backlog task edit <ID> -s "In Progress"`）。
   ドキュメントで決まっていないことが依頼の前提に入るなら、先に利用者に確認する（3章）。
2. 作業のブランチとワークツリーを作る（このセッションが入っているワークツリーを使うか、`/usr/bin/git worktree add .claude/worktrees/<題名> -b <ブランチ> main`）。
3. 目標のファイルを書く（`<ワークツリー>/out/agents/goals/<名前>-<YYYYMMDD>.md`）。作業者は推測しないので、次を必ず書く。
   - タスク ID（`DTAK-N`）
   - 目標（1〜2文）と完了の条件（何が通れば終わりか。核・プラグインの試験の件数、lint、NewApi など。タスクの受入の条件に合わせる）
   - 対象のファイル・ディレクトリと、触ってはいけないもの
   - 根拠のドキュメント（ファイルと節）。ADR・legal は `PRC-163:docs/...` で示す
   - ガードレールの注意（暗号・SDK・秘密・外へ出すことに関わるか）
   - 実機を使うか。使うなら作業者ではなくオーケストレーターが行う（作業者は触れない）
   - 報告の形（AGENTS.md 3章）
4. 起動する:
   ```
   tools/agents/spawn-agent.sh worker --project <ワークツリー> --goal-file <目標のファイル>
   ```
   2人目は `--name astra-worker-2`。`--dry-run` で渡す引数を確かめられる。
5. 起動した Codex は、目標を `/goal`（create_goal）で設定してから作業を始める。ペインで設定されたことを確かめる
   （`tmux capture-pane -p -t <ペイン>`）。設定されていなければ、`tools/agents/nudge.sh <名前> "/goal <目標の要約>"` で打ち込む。

## 2. 問い合わせに答える

作業者・レビュアーからの問い合わせは agmsg で届く。

1. **ドキュメントを探して答える**。`CLAUDE.md`・`docs/`・`PRC-163:docs/`・Backlog のタスク（`backlog search`）を探す。答えには**根拠のファイルと節**を必ず付ける。
2. ドキュメントで決まっていないことは、**推測で答えない**。
   - 相手に「利用者に確認中。この点に依存しない作業を先に進める」と返す。
   - 利用者に確認する（対話中なら AskUserQuestion。バックグラウンドのジョブなら `needs input:` で止まる）。法令・暗号に関わることは `PRC-163:docs/legal.md` の「要確認事項」にも書く。
   - 利用者の答えは、まずドキュメントに書いてから、そのファイルと節を根拠にして答える。
3. 返事は `tools/agents/send-file.sh claude <名前> <本文のファイル>` で送る（本文に `#` があっても切れない）。
   相手が `wait-msg.sh` で待っていれば自動で受け取る。数分たっても反応がなければ `tools/agents/nudge.sh <名前>` で受信箱を読ませる。

## 3. 利用者に確認するとき

- 何が決まっていないか、どのドキュメントのどこを見たか、選択肢と、それぞれの影響を短く書く。
- 確認の結果は、必ずドキュメントに残す（会話だけで終わらせない）。
- 外へ送る・アップロードする・push する・実機に触れることは、そのつど確認する。

## 4. 完了の報告を受けたら

1. 報告の「確かめたこと」を自分でもう一度実行して確かめる（核・プラグインの試験、lint、`git diff --check`）。
2. 5章のレビューにかける。
3. 必修の指摘があれば、指摘を目標のファイルに書いて作業者に戻す（新しい目標として渡し、`/goal` を設定させる）。
4. 指摘がなくなったら、オーケストレーターがコミット・PR を作る（作業者はコミットしない。push は利用者）。コミットメッセージは日本語。
5. タスクの受入の条件を確かめて印を付け（`backlog task edit <ID> --check-ac <番号>`）、終わりのまとめ（`--final-summary`）を書く。PR がマージされたらタスクを Done にする。手順の細目は `backlog instructions task-finalization`。

## 5. レビュー（Astra と Fable の討論）

Claude のレビュアーは Fable 5.2・medium（`fable-reviewer`）に固定。`opus-reviewer` では起動しない。

**Codex の使用量が足りないとき**: 週の使用量（作業者と Astra のレビュアーで共通。`~/.codex/sessions/` の rate_limits の used_percent）を見る。
- 作業者は Codex（`worker`）を使い、98% を超えたら作業を保存させてから `tools/agents/spawn-agent.sh sonnet-worker --project <ワークツリー> --goal-file <目標>`（Sonnet 5.5・high）に引き継ぐ。区切りのよいところで Codex に戻す。
- レビューは、使用量が戻るまで `spawn-agent.sh fable-reviewer --solo` の一者だけにする（Astra のレビュアーは起動しない。依頼に「一者で結論を出す」と書く）。
- 戻ったら、Fable 5.2・medium と GPT-6-Astra の二者に戻す。

手順の正本は `docs/agents/review-debate.md`。

1. レビューの ID を決め、`<ワークツリー>/out/reviews/<ID>/request.md` を書く（対象・観点・関係するドキュメント）。
2. 二者を起動する:
   ```
   tools/agents/spawn-agent.sh astra-reviewer --project <ワークツリー> --goal "out/reviews/<ID>/request.md のレビューを docs/agents/review-debate.md の手順で行い、fable-reviewer と討論して結論を claude に送る"
   tools/agents/spawn-agent.sh fable-reviewer --project <ワークツリー> --goal "out/reviews/<ID>/request.md のレビューを docs/agents/review-debate.md の手順で行い、astra-reviewer と討論して結論を claude に送る"
   ```
3. 討論には入らない。二者から「結論（合意）」が届くまで待つ。`request.md` の締め切り（書いていなければ 40 分）を過ぎたら、
   二者のペインと `out/reviews/<ID>/` の進み具合を確かめ、止まっている方に `nudge.sh` を1回送る。それでも動かなければ、利用者に知らせる。
4. 結論の「合意できなかった点」「未決」は、オーケストレーターがドキュメントをもとに決めるか、利用者に確認する（2章・3章）。
5. 結論と対応を利用者に報告する。

## 6. 片付け

- 終わったエージェントは `tools/agents/despawn-agent.sh <名前>` で止める（ペインを閉じ、agmsg の登録を外す）。
- ペインの画面は `tmux capture-pane -p -t <ペイン>` で見られる。
- `out/agents/`・`out/reviews/` は git に入らない。残す必要のある結論は docs（設計書）か `PRC-163:docs/legal.md` に書き写す。
