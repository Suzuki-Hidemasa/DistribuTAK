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
    private static final class Full extends RuntimeException {}
    public void retry(){
        if(!allowed.getAsBoolean())return;
        budget.purge();
        try{pending.retry(verifier,records::get,checked->{
            if(checked.verdict().status()!=ManagedVerdict.Status.ACCEPTED&&checked.record().kind()!=DhtKeys.KEY_ANNOUNCEMENT
                    &&checked.record().kind()!=DhtKeys.LATEST_REVOCATIONS)return;
            if(apply(checked.record(),checked.verdict())==DhtWire.StoreStatus.FULL)throw new Full();
        },true);}catch(Full full){
            // 元の保留枠と期限を保ち、次の既存pollで空き容量を調べる。
            // Retain the original pending slot and deadline, checking capacity at the next existing poll.
        }
    }
    public int pendingCount(){return pending.size();}
    private void purge(){
        long now=wall.millis();var it=records.values().iterator();
        while(it.hasNext()){
            var value=it.next();
            if(now<0||now>=value.expiresAt()||verifier.judge(value,null).status()==ManagedVerdict.Status.INVALID){budget.replace(value.encode().length,0);it.remove();}
        }
    }
    public ManagedDhtRecord get(DhtId key){if(!allowed.getAsBoolean())return null;budget.purge();var record=records.get(key);
        if(record==null)return null;var status=verifier.judge(record,null).status();
        return status==ManagedVerdict.Status.ACCEPTED||status==ManagedVerdict.Status.DUPLICATE||status==ManagedVerdict.Status.OLD?record:null;}
    public int size(){budget.purge();return records.size();}
    public void clear(){for(var value:records.values())budget.replace(value.encode().length,0);records.clear();pending.clear();}
    @Override public KeyAnnouncement announcement(byte[] digest){
        for(var value:records.values())if(value.kind()==DhtKeys.KEY_ANNOUNCEMENT&&Crypto.equal(Crypto.blake2s(value.announcement().signedBytes()),digest))return value.announcement();
        return trusted.announcement(digest);
    }
    @Override public AdminRecords.Record revocations(long version,byte[] digest){
        for(var value:records.values())if(value.kind()==DhtKeys.LATEST_REVOCATIONS&&value.version()==version&&Crypto.equal(Crypto.blake2s(value.inner().signedBytes()),digest))return value.inner();
        return trusted.revocations(version,digest);
    }
}
