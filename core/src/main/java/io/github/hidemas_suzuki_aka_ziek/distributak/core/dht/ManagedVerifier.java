// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminBinding;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.KeyAnnouncement;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import java.time.Clock;
import java.util.Arrays;
import java.util.Objects;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.List;

/**
 * 管理用 DHT 記録の権限・版・競合の判定（04 §4.5）。構文・鍵・署名は {@link ManagedDhtRecord#verifyStructure} が先に調べる。
 * ここでは、信頼済みの管理者一覧の鎖（{@link TrustedAdmins}）と時計に照らして、受け入れるかどうかを決める。
 * 判定だけを行い、状態も保存も変えない。種類 4・6 は失効の和と依存本体を使って調べる。
 * <p>
 * Judges the authority, version and conflicts of a managed DHT record (04 §4.5). Syntax, keys and signatures are checked
 * first by {@link ManagedDhtRecord#verifyStructure}. This class decides acceptance against the trusted administrator list
 * chain ({@link TrustedAdmins}) and the clock. It only judges; neither state nor storage changes. Kinds 4 and 6 are
 * checked using the revocation union and dependency bodies.
 */
public final class ManagedVerifier {
    /** 先の時刻として許す幅（5 分）。 / How far ahead a signing time may be (five minutes). */
    public static final long FUTURE_SKEW_MILLIS=300_000L;
    private final TrustedAdmins trust;
    private final Clock clock;
    private final RevocationUnion revocations;
    private final ManagedDependencies dependencies;
    /**
     * @param trust 信頼済みの管理者一覧の鎖。The trusted administrator list chain.
     * @param clock 時計。The clock.
     */
    public ManagedVerifier(TrustedAdmins trust,Clock clock){this(trust,clock,null,null);}
    /**
     * 告知・失効本体と失効の和も使う検証器。引数は読み取りだけに使う。
     * <p>
     * Verifier with announcement and revocation bodies plus the revocation union. Arguments are used read-only.
     */
    public ManagedVerifier(TrustedAdmins trust,Clock clock,RevocationUnion revocations,ManagedDependencies dependencies){
        this.trust=Objects.requireNonNull(trust);this.clock=Objects.requireNonNull(clock);
        this.revocations=revocations;this.dependencies=dependencies;
    }

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
        try{return decide(candidate,held,null,false);}
        catch(RuntimeException invalid){return ManagedVerdict.INVALID;}
    }

    /**
     * 認証済みセッションの身元と、署名者の検証済みの対応も調べる STORE の入口。
     * <p>
     * STORE entry point that also checks the authenticated session identity against the signer's verified binding.
     * @param candidate 候補。The candidate.
     * @param held 手元の記録。The held record.
     * @param memberId 認証済みの身元（32 バイト）。The authenticated member identity (32 bytes).
     * @return 判定。The verdict.
     */
    public ManagedVerdict judgeStore(ManagedDhtRecord candidate,ManagedDhtRecord held,byte[] memberId) {
        try{
            if(memberId==null||memberId.length!=32)return ManagedVerdict.INVALID;
            return decide(candidate,held,memberId,true);
        }catch(RuntimeException invalid){return ManagedVerdict.INVALID;}
    }

    private ManagedVerdict decide(ManagedDhtRecord candidate,ManagedDhtRecord held,byte[] memberId,boolean store) {
        int kind=candidate.kind();
        if(kind==DhtKeys.WRAPPED_KEY||kind==DhtKeys.KEY_ANNOUNCEMENT)return judgeKey(candidate,held,memberId,store);
        if(kind!=DhtKeys.LATEST_ADMINS&&kind!=DhtKeys.LATEST_REVOCATIONS&&kind!=DhtKeys.ADMIN_HISTORY)return ManagedVerdict.INVALID;
        long now=clock.millis();
        var inner=candidate.inner();
        // 期限と先の時刻。外側と内側の両方を見る。
        // Expiry and future time, for both the outer and the inner layer.
        if(now>=candidate.expiresAt()||tooFarAhead(candidate.signedAt())||tooFarAhead(inner.signedAt()))return ManagedVerdict.INVALID;
        var latest=trust.latest();
        boolean listKind=kind!=DhtKeys.LATEST_REVOCATIONS;
        long next=latest.version()+1;
        boolean currentSigner=latest.hasEntry(candidate.signer());
        boolean selfRemoval=listKind&&!inner.hasEntry(inner.signer())
                &&!(currentSigner&&inner.version()<=latest.version()&&trust.at(inner.version())!=null
                &&Arrays.equals(inner.encode(),trust.at(inner.version()).encode()));
        var named=trust.at(candidate.adminVersion());
        // 例外は名指した前版と内外の署名を検証してから使う。再送でも期限を変えない。
        // Use exceptions only after checking the named predecessor and both signatures. Retries never change expiry.
        boolean namedMatches=named!=null&&Crypto.equal(Crypto.blake2s(named.signedBytes()),candidate.adminDigest());
        if(selfRemoval){
            if(!namedMatches||candidate.adminVersion()!=inner.version()-1||!named.hasEntry(inner.signer())
                    ||!Crypto.equal(inner.signer(),candidate.signer())||!inner.hasValidSignature())return ManagedVerdict.INVALID;
            if(store&&!boundTo(named,candidate.signer(),memberId))return ManagedVerdict.INVALID;
            if(held!=null&&Arrays.equals(inner.encode(),held.inner().encode())&&!Arrays.equals(candidate.encode(),held.encode()))return ManagedVerdict.INVALID;
            if(!currentSigner){
                return inner.version()==latest.version()&&Arrays.equals(inner.encode(),latest.encode())&&held!=null
                        &&Arrays.equals(candidate.encode(),held.encode())?ManagedVerdict.DUPLICATE:ManagedVerdict.INVALID;
            }
            if(inner.version()!=next||!trust.continuesChain(inner))return ManagedVerdict.INVALID;
        }
        // 自己削除の欠番は上で断る。通常の欠番は、今の管理者かを調べる前に保留にする。
        // Self-removal gaps are rejected above. Ordinary gaps are deferred before checking current administrator authority.
        if(!selfRemoval&&(candidate.adminVersion()>latest.version()||(listKind&&inner.version()>next)))return ManagedVerdict.needsVersion(next);
        if(!selfRemoval&&!currentSigner){
            // 勝ち直しは種類 2 の同版競合だけ。候補の権限は鎖を確かめたあとで使う。
            // Winning back is limited to kind-2 same-version competition; candidate authority follows chain validation.
            if(kind!=DhtKeys.LATEST_ADMINS||inner.version()!=latest.version()||!namedMatches
                    ||candidate.adminVersion()!=inner.version()-1||!inner.hasEntry(candidate.signer())
                    ||AdminRecords.compare(inner,latest)<=0||!trust.continuesChain(inner))return ManagedVerdict.INVALID;
        }
        // 外側の権限。名指す版が信頼済みで、写しが一致し、署名者が今の管理者であること。
        // Outer authority: the named version is trusted, its digest matches, and the signer is a current administrator.
        if(named==null)return ManagedVerdict.INVALID;
        if(!namedMatches)return ManagedVerdict.INVALID;
        if(store&&!boundTo(currentSigner?latest:named,candidate.signer(),memberId))return ManagedVerdict.INVALID;
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
     * 保留枠の分類用に内外の署名者の現在資格を調べる。記録の受理は行わない。
     * <p>
     * Checks current inner and outer signer qualifications for pending-slot classification without accepting a record.
     */
    int pendingSignerQualifications(ManagedDhtRecord record) {
        try{
            var latest=trust.latest();
            byte[] innerSigner=record.kind()==DhtKeys.KEY_ANNOUNCEMENT?record.announcement().signer():record.inner().signer();
            return (latest.hasEntry(record.signer())?1:0)|(latest.hasEntry(innerSigner)?2:0);
        }catch(RuntimeException invalid){return 0;}
    }

    private static boolean boundTo(AdminRecords.Record list,byte[] signer,byte[] memberId) {
        var binding=list.binding(signer);
        return binding!=null&&binding.state()==AdminBinding.State.BOUND&&Crypto.equal(binding.memberId(),memberId);
    }

    private boolean tooFarAhead(long time){
        long now=clock.millis();return time>now&&time-now>FUTURE_SKEW_MILLIS;
    }
    private ManagedVerdict adminReference(long version,byte[] digest) {
        var latest=trust.latest();
        if(version>latest.version())return ManagedVerdict.needsVersion(Math.addExact(latest.version(),1));
        var named=trust.at(version);
        return named!=null&&Crypto.equal(Crypto.blake2s(named.signedBytes()),digest)?null:ManagedVerdict.INVALID;
    }
    private record AnnouncementCheck(ManagedVerdict verdict,AdminRecords.Record body){}
    private AnnouncementCheck checkAnnouncement(KeyAnnouncement announcement,byte[] group) {
        if(!Crypto.equal(announcement.group(),group)||!announcement.hasValidSignature()||tooFarAhead(announcement.signedAt()))
            return new AnnouncementCheck(ManagedVerdict.INVALID,null);
        var authority=adminReference(announcement.adminVersion(),announcement.adminDigest());
        if(authority!=null)return new AnnouncementCheck(authority,null);
        announcement.verify(group,trust.latest().entries());
        var body=dependencies.revocations(announcement.revocationVersion(),announcement.revocationDigest());
        if(body==null)return new AnnouncementCheck(ManagedVerdict.NEEDS_ANNOUNCEMENT,null);
        body.verify(AdminRecords.Kind.REVOCATIONS,group,trust.latest().entries());
        if(body.format()!=2||body.version()!=announcement.revocationVersion()||tooFarAhead(body.signedAt())
                ||!Crypto.equal(Crypto.blake2s(body.signedBytes()),announcement.revocationDigest())||!revocations.covers(body))
            return new AnnouncementCheck(ManagedVerdict.INVALID,null);
        return new AnnouncementCheck(null,body);
    }
    private AdminRecords.Record recipientCertificate(ManagedDhtRecord record) {
        var cert=AdminRecords.decode(record.recipientCertificate());
        cert.verify(AdminRecords.Kind.CERTIFICATE,record.group(),trust.latest().entries());
        var wrapped=record.inner();
        if(cert.format()!=2||cert.identityProofFormat()!=2||!cert.verifyIdentityBinding()||clock.millis()>=cert.expiresAt()
                ||tooFarAhead(cert.issuedAt())||revocations.contains(record.subject())
                ||!Crypto.equal(Crypto.blake2s(cert.field(0)),record.subject())||!Crypto.equal(wrapped.field(0),record.subject())
                ||!Crypto.equal(cert.field(1),wrapped.field(1)))throw new SecurityException("受け手の証明書を受け付けられません");
        return cert;
    }
    private ManagedVerdict judgeKey(ManagedDhtRecord candidate,ManagedDhtRecord held,byte[] memberId,boolean store) {
        if(dependencies==null||revocations==null)return ManagedVerdict.INVALID;
        var latest=trust.latest();
        if(clock.millis()>=candidate.expiresAt()||tooFarAhead(candidate.signedAt()))return ManagedVerdict.INVALID;
        if(candidate.kind()==DhtKeys.KEY_ANNOUNCEMENT){
            var a=candidate.announcement();
            if(!a.hasValidSignature()||tooFarAhead(a.signedAt()))return ManagedVerdict.INVALID;
        }else if(!candidate.inner().hasValidSignature()||tooFarAhead(candidate.inner().signedAt()))return ManagedVerdict.INVALID;
        var authority=adminReference(candidate.adminVersion(),candidate.adminDigest());
        if(authority!=null)return authority;
        if(!latest.hasEntry(candidate.signer()))return ManagedVerdict.INVALID;
        if(store&&!boundTo(latest,candidate.signer(),memberId))return ManagedVerdict.INVALID;
        if(candidate.kind()==DhtKeys.KEY_ANNOUNCEMENT){
            var announcement=candidate.announcement();
            var result=checkAnnouncement(announcement,candidate.group());if(result.verdict()!=null)return result.verdict();
            int order=held==null?1:KeyAnnouncement.compare(announcement,held.announcement());
            return ranked(candidate,held,order);
        }
        var wrapped=candidate.inner();wrapped.verify(AdminRecords.Kind.WRAPPED_KEY,candidate.group(),latest.entries());
        if(wrapped.format()!=2||tooFarAhead(wrapped.signedAt()))return ManagedVerdict.INVALID;
        var cert=recipientCertificate(candidate);
        var announcement=dependencies.announcement(wrapped.field(4));
        if(announcement==null)return ManagedVerdict.NEEDS_ANNOUNCEMENT;
        if(!Crypto.equal(Crypto.blake2s(announcement.signedBytes()),wrapped.field(4))||announcement.keyVersion()!=wrapped.version())return ManagedVerdict.INVALID;
        var result=checkAnnouncement(announcement,candidate.group());if(result.verdict()!=null)return result.verdict();
        var body=result.body();
        if(body.hasEntry(candidate.subject()))return ManagedVerdict.INVALID;
        if(held==null)return ManagedVerdict.ACCEPTED;
        var oldCertificate=AdminRecords.decode(held.recipientCertificate());
        if(cert.issuedAt()==oldCertificate.issuedAt()&&!Arrays.equals(cert.encode(),oldCertificate.encode()))return ManagedVerdict.INVALID;
        int versionOrder=Long.compare(wrapped.version(),held.inner().version());
        if(versionOrder!=0)return ranked(candidate,held,versionOrder);
        var oldAnnouncement=dependencies.announcement(held.inner().field(4));
        if(oldAnnouncement==null)return ManagedVerdict.NEEDS_ANNOUNCEMENT;
        int order=KeyAnnouncement.compare(announcement,oldAnnouncement);
        if(order==0)order=Long.compare(cert.issuedAt(),oldCertificate.issuedAt());
        if(order==0)order=Long.compare(wrapped.signedAt(),held.inner().signedAt());
        if(order==0)order=AdminRecords.compareBytes(wrapped.signedBytes(),held.inner().signedBytes());
        return ranked(candidate,held,order);
    }
    private record PendingRank(ManagedDhtRecord record,KeyAnnouncement announcement,long certificateTime){}
    /**
     * その通しの順位を先にそろえ、比較中は依存本体を読み直さない。
     * <p>
     * Captures ranks for one pass without rereading dependency bodies during comparisons.
     */
    Comparator<ManagedDhtRecord> pendingOrder(List<ManagedDhtRecord> records) {
        var ranks=new IdentityHashMap<ManagedDhtRecord,PendingRank>();
        for(var record:records){
            if(ranks.containsKey(record))continue;
            var announcement=record.kind()==DhtKeys.WRAPPED_KEY&&dependencies!=null
                    ?dependencies.announcement(record.inner().field(4)):null;
            ranks.put(record,new PendingRank(record,announcement,
                    record.kind()==DhtKeys.WRAPPED_KEY?pendingCertificateTime(record):Long.MIN_VALUE));
        }
        return (a,b)->comparePending(ranks.get(a),ranks.get(b));
    }
    private static int comparePending(PendingRank ar,PendingRank br) {
        var a=ar.record();var b=br.record();
        if(a.kind()==DhtKeys.WRAPPED_KEY){
            int readable=Boolean.compare(ar.announcement()!=null,br.announcement()!=null);
            if(readable!=0)return readable;
        }
        int order=Long.compare(a.version(),b.version());
        if(order!=0)return order;
        if(a.kind()==DhtKeys.KEY_ANNOUNCEMENT)order=KeyAnnouncement.compare(a.announcement(),b.announcement());
        else if(a.kind()==DhtKeys.WRAPPED_KEY){
            var aa=ar.announcement();var ba=br.announcement();
            if(aa!=null&&ba!=null)order=KeyAnnouncement.compare(aa,ba);
            if(order==0)order=Long.compare(ar.certificateTime(),br.certificateTime());
            if(order==0)order=Long.compare(a.inner().signedAt(),b.inner().signedAt());
            if(order==0)order=AdminRecords.compareBytes(a.inner().signedBytes(),b.inner().signedBytes());
        }else order=AdminRecords.compare(a.inner(),b.inner());
        if(order==0)order=Long.compare(a.signedAt(),b.signedAt());
        if(order==0)order=Long.compare(a.publicationSeq(),b.publicationSeq());
        if(order==0)order=AdminRecords.compareBytes(a.encode(),b.encode());
        return order;
    }
    private static long pendingCertificateTime(ManagedDhtRecord record) {
        try{return AdminRecords.decode(record.recipientCertificate()).issuedAt();}
        catch(RuntimeException invalid){return Long.MIN_VALUE;}
    }
    private static ManagedVerdict ranked(ManagedDhtRecord candidate,ManagedDhtRecord held,int order) {
        if(order>0)return ManagedVerdict.ACCEPTED;
        if(order<0)return ManagedVerdict.OLD;
        if(Arrays.equals(candidate.encode(),held.encode()))return ManagedVerdict.DUPLICATE;
        int outer=Long.compare(candidate.signedAt(),held.signedAt());
        if(outer==0)outer=Long.compare(candidate.publicationSeq(),held.publicationSeq());
        return outer>0?ManagedVerdict.ACCEPTED:ManagedVerdict.DUPLICATE;
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
