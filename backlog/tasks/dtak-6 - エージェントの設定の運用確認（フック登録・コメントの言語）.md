---
id: DTAK-6
title: エージェントの設定の運用確認（フック登録・コメントの言語）
status: To Do
assignee: []
created_date: '2026-11-15 22:55'
labels:
  - agents
dependencies: []
ordinal: 6000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
引き継いだエージェントの設定について、利用者の判断が要る点。(1) 書き換えを止めるフック guard_code_edit.py を登録するか（登録すると Claude Code 自身の編集も止まる）。(2) コードのコメントを日本語のみとするか、JTAK のように日英にするか。(3) Codex の作業者を初めて起動して tools/agents/spawn-agent.sh の実機の動きを確かめる。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 フックの登録の有無が決まり、CLAUDE.md に反映された
- [ ] #2 コメントの言語の方針が決まり、CLAUDE.md に反映された
- [ ] #3 作業者を1回起動して動作を確かめた
<!-- AC:END -->
