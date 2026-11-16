// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords;
import java.util.Objects;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * 失効の和 R（04 §4.5）。署名の検査を通った失効の一覧に載った対象を、到着順・一覧の勝者・署名者の削除によらず残す。
 * 手元の最新だけの失効（{@code AdminState.revocations()}）とは別に持つ。新しく足せるのは、今の管理者が署名した一覧だけで、
 * すでに足した対象は署名者が外されても消さない。足した結果が上限を超えるときは、古い失効を捨てずに断る。
 * <p>
 * The revocation union R (04 §4.5). Subjects of revocation lists that passed the signature check stay regardless of arrival
 * order, list winner or signer removal. It is kept apart from the latest-only revocations ({@code AdminState.revocations()}).
 * Only lists signed by a current administrator can be added, and subjects already added are not dropped when their signer is
 * removed. When an addition would pass the limit, it is refused and no older revocation is discarded.
 */
public final class RevocationUnion {
    private final byte[] group;
    private final TrustedAdmins trust;
    private final SortedSet<byte[]> subjects=new TreeSet<>(AdminRecords::compareBytes);
    private PreparedAddition pending;

    /**
     * @param group グループの識別子。The group identifier.
     * @param trust 信頼済みの管理者一覧の鎖。The trusted administrator list chain.
     */
    public RevocationUnion(byte[] group,TrustedAdmins trust) {
        this.group=Objects.requireNonNull(group).clone();this.trust=Objects.requireNonNull(trust);
    }

    /**
     * 失効の一覧を足す。署名・宛先・署名者（今の管理者であること）を調べ、載っている対象を和に入れる。
     * <p>
     * Adds a revocation list. Checks the signature, the group and the signer (a current administrator), then merges its subjects.
     *
     * @param list 失効の一覧。The revocation list.
     * @return 和が増えたとき true。True when the union grew.
     * @throws SecurityException 署名・宛先・署名者が正しくないとき。When the signature, group or signer is not valid.
     * @throws AdminRecords.RevocationLimitException 足すと上限を超えるとき。和は変わらない。When the addition would pass the limit; the union is unchanged.
     */
    public synchronized boolean add(AdminRecords.Record list) {
        try(var addition=prepareAddition(list)){return addition.commit();}
    }

    /**
     * 保存前に署名と上限を検査し、公開まで追加枠を予約する。読み取りは止めず、競合する追加は断る。
     * <p>
     * Checks signatures and limits before persistence and reserves capacity until publication. Reads proceed; competing additions are refused.
     *
     * @param list 失効の一覧。The revocation list.
     * @return 公開または取り消す予約。The reservation to publish or cancel.
     */
    public synchronized PreparedAddition prepareAddition(AdminRecords.Record list) {
        if(pending!=null)throw new IllegalStateException("Revocation addition is reserved");
        list.verify(AdminRecords.Kind.REVOCATIONS,group,trust.latest().entries());
        var fresh=new TreeSet<byte[]>(AdminRecords::compareBytes);
        for(byte[] subject:list.entries()){
            if(!subjects.contains(subject)){fresh.add(subject);}
        }
        if(subjects.size()+fresh.size()>AdminRecords.MAX_ENTRIES){throw new AdminRecords.RevocationLimitException();}
        pending=new PreparedAddition(fresh);return pending;
    }

    /**
     * 検査済みの追加。確定時には署名や上限を再検査せず、予約した対象だけを公開する。
     * <p>
     * A checked addition. Commit publishes only reserved subjects without rechecking signatures or capacity.
     */
    public final class PreparedAddition implements AutoCloseable {
        private final SortedSet<byte[]> fresh;
        private PreparedAddition(SortedSet<byte[]> fresh){this.fresh=fresh;}
        public boolean commit(){synchronized(RevocationUnion.this){
            if(pending!=this)throw new IllegalStateException("Revocation reservation is inactive");
            subjects.addAll(fresh);pending=null;return !fresh.isEmpty();
        }}
        public void close(){synchronized(RevocationUnion.this){if(pending==this)pending=null;}}
    }

    /**
     * 対象が和に入っているか。
     * <p>
     * Whether the subject is in the union.
     *
     * @param subject 対象の識別子（32 バイト）。The subject identifier (32 bytes).
     * @return 入っているとき true。True when present.
     */
    public synchronized boolean contains(byte[] subject){return subjects.contains(subject);}

    /**
     * 和に入っている対象の数。
     * <p>
     * The number of subjects in the union.
     *
     * @return 件数。The count.
     */
    public synchronized int size(){return subjects.size();}

    /**
     * 一覧が和の対象をすべて含むか（和を包含するか）。
     * <p>
     * Whether the list contains every subject in the union (covers the union).
     *
     * @param list 失効の一覧。The revocation list.
     * @return すべて含むとき true。True when every subject is included.
     */
    public synchronized boolean covers(AdminRecords.Record list) {
        for(byte[] subject:subjects){
            if(!list.hasEntry(subject)){return false;}
        }
        return true;
    }
}
