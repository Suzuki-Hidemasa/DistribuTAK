---
id: DTAK-25
title: 管理者の証明書だけが切れた場合の受ける道を docs/04 §4.4 に書き、試験を足す（DTAK-10 AC#2 の案 A）
status: Done
assignee: []
created_date: '2026-11-17 12:54'
updated_date: '2026-11-18 01:00'
labels:
  - stage-11
dependencies: []
references:
  - docs/04-detailed-design.md
  - out/reviews/dtak10-ac2/conclusion.md
ordinal: 25000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DTAK-10 AC#2 の二者レビューの結論（out/reviews/dtak10-ac2/conclusion.md）。メンバーが持つ管理者の枠が期限切れのとき、新しい証明書（同じ身元・検査を通る・発行が新しい）の FIRST を受ける道は、今のコードにすでにある（起動し直した場合は LanController → UdpEndpoint.expectPeerCertificate → checkFirstPeer → storedPeer、動いたままの場合は SessionManager.verify → checkCertificateOrder → adopt）。核に新しい口は足さない。新しい暗号・期限の余裕は足さない（答え 143 のまま）。足すのは、04 §4.4 の末尾の「未決」の文の置き換えと、メンバーの側の道の試験。A で戻れるのは、管理者の証明書だけが切れ、メンバー自身の証明書は有効な間だけで、両方が切れた場合は別タスクで決める。「入り直しで救える」とは書かない。
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 docs/04 §4.4 の未決の文を、今のコードの動きと A が働く前提（握手は管理者から始まる。管理者の側でメンバーの証明書が有効で番地を持つ。メンバー自身の証明書が有効。グループの鍵の版が合っている）に置き換えている。署名者の権限と、つなぐ身元の資格を分けて書いている
- [x] #2 核・プラグインの試験に、管理者の枠だけ期限切れでの新しい FIRST の受け入れ（起動し直した場合・動いたままの場合）が入っている
- [x] #3 断る場合の試験が入っている: 発行が古い・同じ発行で中身が違う・身元が違う・署名が違う・署名者が一覧にない・失効した身元・期限の境目・発行が先の時刻
- [x] #4 保存の失敗を通しで確かめる試験が入っている: 保存の中身と枠が前のまま、通信が止まる
- [x] #5 全試験が成功し、lint エラー 0・NewApi 0・git diff --check 0 である
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-17: ブランチ worktree-dtak25 のコミット a39bd2e（base 69d9b46）。docs/04 §4.4 を置き換え、核の AdministratorFirstValidationTest 25 件・プラグインの LanAdministratorCertificateTest 4 件を追加。製品コードの差分なし。確認（claude が自分で実行）: core/build.sh clean test = 1,675 件・失敗/エラー/スキップ 0（変更前 1,650）、plugin の assemble・test・lint = 775 件・失敗/エラー/スキップ 0（変更前 771）、lint エラー 0、lint-core の NewApi 0、git diff --check 0。正の試験の入力を 1 つずつ変える変異（発行を古く・署名者を一覧から外す・期限ちょうど）で 2 通りとも落ちる（out/agents/dtak25-mutation.log）。保存失敗の通しの試験は、一般メンバーが更新待ちを持てないため null を確かめ、番地は認証済み DATA で先に変わった状態を setPeerAddress で再現した。非 null の更新待ちの巻き戻しは既存の StoredUpdatesTest に任せる。二者レビューは、製品コードが変わらないためかけていない。push・PR・マージは利用者の許可待ち。DTAK-10 AC#2 は、ADR 0030 への追記（PRC-163 側）を利用者が済ませてから印を付ける。

2026-11-18: PR #25 を main へマージ（マージコミット dc63652）。a39bd2e が origin/main の祖先であることを git merge-base --is-ancestor で確認した。
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
docs/04 §4.4 の未決の文を、管理者の証明書だけが切れた場合に新しい FIRST を受けて保存し直す今のコードの動きと前提に置き換え、核 25 件・プラグイン 4 件の試験を足した。製品コードの差分なし。核 1,675 件・プラグイン 775 件で失敗 0、lint エラー 0、NewApi 0、git diff --check 0 を確認。PR #25 を 2026-11-18 にマージ済み。
<!-- SECTION:FINAL_SUMMARY:END -->
