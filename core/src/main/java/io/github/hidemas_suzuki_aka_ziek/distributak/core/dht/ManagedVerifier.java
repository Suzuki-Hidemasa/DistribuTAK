// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import java.time.Clock;
import java.util.Arrays;
import java.util.Objects;

/**
 * 管理用 DHT 記録の権限・版・競合の判定（04 §4.5）。構文・鍵・署名は {@link ManagedDhtRecord#verifyStructure} が先に調べる。
 * ここでは、信頼済みの管理者一覧の鎖（{@link TrustedAdmins}）と時計に照らして、受け入れるかどうかを決める。
 * 判定だけを行い、状態も保存も変えない。種類 4（鍵の包み）と種類 6（告知）はまだ扱わず、INVALID を返す。
 * <p>
 * Judges the authority, version and conflicts of a managed DHT record (04 §4.5). Syntax, keys and signatures are checked
 * first by {@link ManagedDhtRecord#verifyStructure}. This class decides acceptance against the trusted administrator list
 * chain ({@link TrustedAdmins}) and the clock. It only judges; neither state nor storage changes. Kind 4 (wrapped key)
 * and kind 6 (announcement) are not handled yet and return INVALID.
 */
public final class ManagedVerifier {
    /** 先の時刻として許す幅（5 分）。 / How far ahead a signing time may be (five minutes). */
    public static final long FUTURE_SKEW_MILLIS=300_000L;
    private final TrustedAdmins trust;
    private final Clock clock;
    /**
     * @param trust 信頼済みの管理者一覧の鎖。The trusted administrator list chain.
     * @param clock 時計。The clock.
     */
    public ManagedVerifier(TrustedAdmins trust,Clock clock){this.trust=Objects.requireNonNull(trust);this.clock=Objects.requireNonNull(clock);}

    /**
     * 候補を、手元の記録（なければ null）と比べて判定する。候補は構文と署名の検査を通ったものとする。
     * <p>
     * Judges the candidate against the held record (null when none). The candidate is assumed to have passed the syntax
     * and signature checks.
     *
     * @param candidate 受け取った記録。The received record.
     * @param held 同じ鍵で手元にある記録。The record held under the same key, or null.
     * @return 判定。The verdict.
     */
    public ManagedVerdict judge(ManagedDhtRecord candidate,ManagedDhtRecord held) {
        try{return decide(candidate,held);}
        catch(RuntimeException invalid){return ManagedVerdict.INVALID;}
    }

    private ManagedVerdict decide(ManagedDhtRecord candidate,ManagedDhtRecord held) {
        int kind=candidate.kind();
        if(kind!=DhtKeys.LATEST_ADMINS&&kind!=DhtKeys.LATEST_REVOCATIONS&&kind!=DhtKeys.ADMIN_HISTORY)return ManagedVerdict.INVALID;
        long now=clock.millis();
        var inner=candidate.inner();
        // 期限と先の時刻。外側と内側の両方を見る。
        // Expiry and future time, for both the outer and the inner layer.
        if(now>=candidate.expiresAt()||candidate.signedAt()>now+FUTURE_SKEW_MILLIS||inner.signedAt()>now+FUTURE_SKEW_MILLIS)return ManagedVerdict.INVALID;
        var latest=trust.latest();
        boolean listKind=kind!=DhtKeys.LATEST_REVOCATIONS;
        long next=latest.version()+1;
        // 足りない版は、先に取る。外側が先の版を名指すとき、一覧が 2 つ以上先のとき。
        // Fetch missing versions first: the outer names a later version, or the list is two or more ahead.
        if(candidate.adminVersion()>latest.version()||(listKind&&inner.version()>next))return ManagedVerdict.needsVersion(next);
        // 外側の権限。名指す版が信頼済みで、写しが一致し、署名者が今の管理者であること。
        // Outer authority: the named version is trusted, its digest matches, and the signer is a current administrator.
        var named=trust.at(candidate.adminVersion());
        if(named==null)return ManagedVerdict.INVALID;
        if(!Crypto.equal(Crypto.blake2s(named.signedBytes()),candidate.adminDigest()))return ManagedVerdict.INVALID;
        if(!latest.hasEntry(candidate.signer()))return ManagedVerdict.INVALID;
        if(listKind){
            var verdict=judgeList(candidate,inner,latest);
            if(verdict!=null)return verdict;
        }else{
            var verdict=judgeRevocations(candidate,inner,latest,held);
            if(verdict!=null)return verdict;
        }
        return rank(candidate,inner,held);
    }

    /**
     * 管理者の一覧（種類 2・5）の規則。ここで決まれば判定を返し、順位の比べに進むなら null を返す。
     * <p>
     * Rules for administrator lists (kinds 2 and 5). Returns a verdict when decided here, or null to go on to ranking.
     */
    private ManagedVerdict judgeList(ManagedDhtRecord candidate,AdminRecords.Record inner,AdminRecords.Record latest) {
        long version=inner.version(),current=latest.version();
        if(version<current){
            // 過去の版は、信頼済みの一覧そのものだけ。種類 2 は古いので OLD、種類 5 は一致しなければ INVALID。
            // A past version must be the trusted list itself. Kind 2 is merely OLD; kind 5 is INVALID unless identical.
            var trusted=trust.at(version);
            if(candidate.kind()==DhtKeys.LATEST_ADMINS)return ManagedVerdict.OLD;
            return trusted!=null&&Arrays.equals(trusted.encode(),inner.encode())?null:ManagedVerdict.INVALID;
        }
        if(version==current&&Arrays.equals(latest.encode(),inner.encode()))return null;
        if(version==current&&AdminRecords.compare(inner,latest)<=0)return ManagedVerdict.OLD;
        // 次の版と、同じ版の競合は、直前の版から鎖でつながり、外側がその版を名指すこと。
        // The next version and a same-version competitor must chain from the previous version, with the outer naming it.
        if(!trust.continuesChain(inner)||candidate.adminVersion()!=version-1)return ManagedVerdict.INVALID;
        return null;
    }

    /**
     * 失効の一覧（種類 3）の規則。
     * <p>
     * Rules for the revocation list (kind 3).
     */
    private ManagedVerdict judgeRevocations(ManagedDhtRecord candidate,AdminRecords.Record inner,AdminRecords.Record latest,ManagedDhtRecord held) {
        inner.verify(AdminRecords.Kind.REVOCATIONS,candidate.group(),latest.entries());
        // 手元の R の署名者が外されたあとは、同じ版か低い版の R では取り替えない。
        // Once the signer of the held R was removed, an R of the same or a lower version does not replace it.
        if(held!=null){
            var heldInner=held.inner();
            if(!latest.hasEntry(heldInner.signer())&&inner.version()<=heldInner.version())return ManagedVerdict.OLD;
        }
        return null;
    }

    /**
     * 手元の記録との順位。内側の順位（版→署名時刻→中身）が先で、外側の番号と時刻は内側が同じときだけ使う。
     * <p>
     * Ranking against the held record. The inner rank (version, signing time, payload) comes first; the outer sequence
     * and time are used only when the inner records are identical.
     */
    private static ManagedVerdict rank(ManagedDhtRecord candidate,AdminRecords.Record inner,ManagedDhtRecord held) {
        if(held==null)return ManagedVerdict.ACCEPTED;
        int order=AdminRecords.compare(inner,held.inner());
        if(order>0)return ManagedVerdict.ACCEPTED;
        if(order<0)return ManagedVerdict.OLD;
        if(Arrays.equals(candidate.encode(),held.encode()))return ManagedVerdict.DUPLICATE;
        int outer=Long.compare(candidate.signedAt(),held.signedAt());
        if(outer==0)outer=Long.compare(candidate.publicationSeq(),held.publicationSeq());
        return outer>0?ManagedVerdict.ACCEPTED:ManagedVerdict.DUPLICATE;
    }
}
