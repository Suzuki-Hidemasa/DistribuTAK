// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.time.Clock;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * 管理記録を検証して有限に預かり、OLDの失効と競合告知も検証後に渡す。
 * <p>
 * Verifies and bounds management copies, delivering OLD revocations and competing announcements only after validation.
 */
public final class ManagedDhtStore implements ManagedDependencies {
    private final byte[] group;private final Clock wall;private final DhtRecordBudget budget;
    private final ManagedDependencies trusted;private final Consumer<ManagedDhtRecord> accepted;
    private final Map<DhtId,ManagedDhtRecord> records=new LinkedHashMap<>();
    private KeyAnnouncement observed;
    private final ManagedVerifier verifier;private final ManagedPending pending;
    private final java.util.function.BooleanSupplier allowed;
    public ManagedDhtStore(byte[] group,Clock wall,Clock deadlines,TrustedAdmins admins,RevocationUnion union,
            Predicate<byte[]> qualifiedSender,DhtRecordBudget budget,ManagedDependencies trusted,Consumer<ManagedDhtRecord> accepted){
        this(group,wall,deadlines,admins,union,qualifiedSender,budget,trusted,accepted,()->true);
    }
    /**
     * 保存中は検証・保留・公開を始めない製品用の入口。
     * <p>
     * Product entry that starts no validation, pending admission or publication while persistence is suspended.
     */
    public ManagedDhtStore(byte[] group,Clock wall,Clock deadlines,TrustedAdmins admins,RevocationUnion union,
            Predicate<byte[]> qualifiedSender,DhtRecordBudget budget,ManagedDependencies trusted,Consumer<ManagedDhtRecord> accepted,
            java.util.function.BooleanSupplier allowed){
        this.allowed=Objects.requireNonNull(allowed);
        this.group=group.clone();this.wall=Objects.requireNonNull(wall);this.budget=Objects.requireNonNull(budget);
        this.trusted=Objects.requireNonNull(trusted);this.accepted=Objects.requireNonNull(accepted);
        verifier=new ManagedVerifier(admins,wall,union,this).observingAnnouncements();
        pending=new ManagedPending(deadlines,verifier,Objects.requireNonNull(qualifiedSender));budget.register(this::purge);
    }
    public DhtWire.StoreStatus acceptBytes(byte[] sender,byte[] wire,boolean store){
        try{return accept(sender,ManagedDhtRecord.verifyStructure(wire,group),store);}
        catch(RuntimeException invalid){return DhtWire.StoreStatus.INVALID;}
    }
    public DhtWire.StoreStatus accept(byte[] sender,ManagedDhtRecord candidate,boolean store){
        if(!allowed.getAsBoolean())return DhtWire.StoreStatus.INVALID;
        try{
            candidate=ManagedDhtRecord.verifyStructure(candidate.encode(),group);budget.purge();
            var verdict=store?verifier.judgeStore(candidate,records.get(candidate.key()),sender):verifier.judge(candidate,records.get(candidate.key()));
            if(verdict.status()==ManagedVerdict.Status.NEEDS_VERSION||verdict.status()==ManagedVerdict.Status.NEEDS_ANNOUNCEMENT){
                pending.offer(candidate,verdict,store?sender:null);return DhtWire.StoreStatus.INVALID;
            }
            return apply(candidate,verdict);
        }catch(RuntimeException invalid){return DhtWire.StoreStatus.INVALID;}
    }
    private DhtWire.StoreStatus apply(ManagedDhtRecord candidate,ManagedVerdict verdict){
        var status=verdict.status();
        if(status==ManagedVerdict.Status.INVALID)return DhtWire.StoreStatus.INVALID;
        if(status==ManagedVerdict.Status.OLD||status==ManagedVerdict.Status.DUPLICATE){
            if(candidate.kind()==DhtKeys.LATEST_REVOCATIONS||candidate.kind()==DhtKeys.KEY_ANNOUNCEMENT)accepted.accept(candidate);
            return status==ManagedVerdict.Status.OLD?DhtWire.StoreStatus.OLD:DhtWire.StoreStatus.DUPLICATE;
        }
        if(status!=ManagedVerdict.Status.ACCEPTED)return DhtWire.StoreStatus.INVALID;
        var previous=records.get(candidate.key());int oldBytes=previous==null?0:previous.encode().length,nextBytes=candidate.encode().length;
        if(!budget.replace(oldBytes,nextBytes))return DhtWire.StoreStatus.FULL;
        try{accepted.accept(candidate);records.put(candidate.key(),candidate);}
        catch(RuntimeException failure){budget.replace(nextBytes,oldBytes);throw failure;}
        return DhtWire.StoreStatus.ACCEPTED;
    }
    /**
     * 保存未確定の一時失敗だけを保留の再試行へ戻す。
     * <p>
     * Returns only a transient uncommitted persistence failure to pending retry.
     */
    public static final class PersistenceDeferred extends RuntimeException {}
    private static final class Full extends RuntimeException {}
    public void retry(){
        if(!allowed.getAsBoolean())return;
        budget.purge();
        try{pending.retry(verifier,records::get,checked->{
            if(checked.verdict().status()!=ManagedVerdict.Status.ACCEPTED&&checked.record().kind()!=DhtKeys.KEY_ANNOUNCEMENT
                    &&checked.record().kind()!=DhtKeys.LATEST_REVOCATIONS)return;
            if(apply(checked.record(),checked.verdict())==DhtWire.StoreStatus.FULL)throw new Full();
        },true);}catch(Full|PersistenceDeferred deferred){
            // 元の保留枠と期限を保ち、次の既存pollで空き容量を調べる。
            // Retain the original pending slot and deadline, checking capacity at the next existing poll.
        }
    }
    public int pendingCount(){return pending.size();}
    /**
     * 有限保留が必要とする記録鍵を返す。未検証入力から探索を増やさない。
     * <p>
     * Returns record keys needed by bounded pending entries without expanding discovery from unvalidated input.
     */
    public Set<DhtId> dependencyKeys(){
        if(!allowed.getAsBoolean())return Set.of();var result=new LinkedHashSet<DhtId>();
        for(var candidate:pending.candidates()){
            var verdict=verifier.judge(candidate,records.get(candidate.key()));
            if(verdict.status()==ManagedVerdict.Status.NEEDS_VERSION)
                result.add(DhtKeys.derive(group,DhtKeys.ADMIN_HISTORY,DhtKeys.adminHistorySubject(verdict.neededVersion())));
            else if(verdict.status()==ManagedVerdict.Status.NEEDS_ANNOUNCEMENT)
                result.add(DhtKeys.derive(group,candidate.kind()==DhtKeys.KEY_ANNOUNCEMENT?DhtKeys.LATEST_REVOCATIONS:DhtKeys.KEY_ANNOUNCEMENT,new byte[32]));
        }
        return Collections.unmodifiableSet(result);
    }
    /**
     * 一般メンバーの告知を一件だけ共有予算へ預ける。再受信でも署名時刻を変えない。
     * <p>
     * Retains one ordinary-member announcement in the shared budget without changing its signing time on redelivery.
     */
    public boolean rememberAnnouncement(KeyAnnouncement value){
        if(!allowed.getAsBoolean())return false;budget.purge();
        if(wall.millis()-value.signedAt()>=86400000||!verifier.validObservation(value,group))return false;
        if(observed!=null&&KeyAnnouncement.compare(value,observed)<0)return true;
        if(!budget.replace(observed==null?0:observed.encode().length,value.encode().length))return false;
        observed=value;return true;
    }
    private void purge(){
        long now=wall.millis();
        if(observed!=null&&(now-observed.signedAt()>=86400000||!verifier.validObservation(observed,group))){budget.replace(observed.encode().length,0);observed=null;}
        var it=records.values().iterator();
        while(it.hasNext()){
            var value=it.next();
            if(now<0||now>=value.expiresAt()||verifier.judge(value,null).status()==ManagedVerdict.Status.INVALID){budget.replace(value.encode().length,0);it.remove();}
        }
    }
    public ManagedDhtRecord get(DhtId key){if(!allowed.getAsBoolean())return null;budget.purge();var record=records.get(key);
        if(record==null)return null;var status=verifier.judge(record,null).status();
        return status==ManagedVerdict.Status.ACCEPTED||status==ManagedVerdict.Status.DUPLICATE||status==ManagedVerdict.Status.OLD?record:null;}
    public int size(){budget.purge();return records.size();}
    public void clear(){for(var value:records.values())budget.replace(value.encode().length,0);records.clear();pending.clear();if(observed!=null){budget.replace(observed.encode().length,0);observed=null;}}
    @Override public KeyAnnouncement announcement(byte[] digest){
        if(observed!=null&&wall.millis()-observed.signedAt()<86400000&&verifier.validObservation(observed,group)
                &&Crypto.equal(Crypto.blake2s(observed.signedBytes()),digest))return observed;
        for(var value:records.values())if(value.kind()==DhtKeys.KEY_ANNOUNCEMENT&&Crypto.equal(Crypto.blake2s(value.announcement().signedBytes()),digest))return value.announcement();
        return trusted.announcement(digest);
    }
    @Override public AdminRecords.Record revocations(long version,byte[] digest){
        for(var value:records.values())if(value.kind()==DhtKeys.LATEST_REVOCATIONS&&value.version()==version&&Crypto.equal(Crypto.blake2s(value.inner().signedBytes()),digest))return value.inner();
        return trusted.revocations(version,digest);
    }
}
