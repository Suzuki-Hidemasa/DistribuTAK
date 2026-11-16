// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.time.Clock;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Consumer;

/**
 * 依存本体を待つ管理記録の有限な保留枠（04 §4.5）。満杯なら新着を断り、再送で期限を延ばさない。
 * 最新値や名簿への登録は行わない。
 * <p>
 * Bounded pending area for managed records awaiting dependency bodies (04 §4.5). Refuses new arrivals when full and
 * never extends deadlines on retries. Registers neither latest values nor roster entries.
 */
public final class ManagedPending {
    public static final int MAX_COUNT=8,MAX_BYTES=4*1024*1024;
    public static final long MAX_AGE_MILLIS=120_000;
    private record Entry(ManagedDhtRecord record,byte[] encoded,byte[] memberId,long started){}
    /**
     * 再検査した結果。保留のままの記録は含めない。
     * <p>
     * A rechecked result, excluding records that remain pending.
     */
    public record Checked(ManagedDhtRecord record,ManagedVerdict verdict){}
    private final Clock clock;
    private final List<Entry> entries=new ArrayList<>();
    private int bytes;
    public ManagedPending(Clock clock){this.clock=Objects.requireNonNull(clock);}
    private static boolean pending(ManagedVerdict verdict){
        return verdict.status()==ManagedVerdict.Status.NEEDS_VERSION||verdict.status()==ManagedVerdict.Status.NEEDS_ANNOUNCEMENT;
    }
    private void expire(){
        long now=clock.millis();
        var iterator=entries.iterator();
        while(iterator.hasNext()){
            var entry=iterator.next();
            if(now<entry.started||now-entry.started>=MAX_AGE_MILLIS){bytes-=entry.encoded.length;iterator.remove();}
        }
    }
    /**
     * 検証器が保留とした FIND の値を預かる。
     * <p>
     * Holds a FIND value marked pending by the verifier.
     */
    public synchronized boolean offer(ManagedDhtRecord record,ManagedVerdict verdict){return offer(record,verdict,null);}
    /**
     * STORE の保留は、再検査用に認証済みの身元も渡す。
     * <p>
     * For pending STORE, also passes the authenticated identity for rechecking.
     */
    public synchronized boolean offer(ManagedDhtRecord record,ManagedVerdict verdict,byte[] authenticatedMember) {
        expire();if(record==null||verdict==null||!pending(verdict))return false;
        if(authenticatedMember!=null&&authenticatedMember.length!=32)return false;
        byte[] encoded=record.encode();
        for(var entry:entries)if(Arrays.equals(entry.encoded,encoded)&&Arrays.equals(entry.memberId,authenticatedMember))return true;
        if(entries.size()>=MAX_COUNT||encoded.length>MAX_BYTES-bytes)return false;
        entries.add(new Entry(record,encoded,authenticatedMember==null?null:authenticatedMember.clone(),clock.millis()));
        bytes+=encoded.length;return true;
    }
    /**
     * 現在の権限・失効・期限・手元の値で再検査する。同じ DHT 番号では順位の高い方から調べ、ACCEPTED を関数で適用してから次を調べる。保留以外は枠から外して返す。
     * <p>
     * Rechecks current authority, revocations, expiry and held values. Checks higher-ranked candidates first under each DHT key, applies ACCEPTED through the callback before checking the next, and removes and returns resolved results.
     */
    public synchronized List<Checked> retry(ManagedVerifier verifier,Function<DhtId,ManagedDhtRecord> held,Consumer<Checked> apply) {
        Objects.requireNonNull(apply);
        expire();
        var ordered=new ArrayList<>(entries);
        ordered.sort((a,b)->{
            int key=AdminRecords.compareBytes(a.record.key().bytes(),b.record.key().bytes());
            return key!=0?key:-verifier.comparePending(a.record,b.record);
        });
        var resolved=new ArrayList<Checked>();
        for(var entry:ordered){
            var current=held.apply(entry.record.key());
            var verdict=entry.memberId==null?verifier.judge(entry.record,current):verifier.judgeStore(entry.record,current,entry.memberId);
            if(!pending(verdict)){
                var checked=new Checked(entry.record,verdict);
                if(verdict.status()==ManagedVerdict.Status.ACCEPTED)apply.accept(checked);
                resolved.add(checked);bytes-=entry.encoded.length;entries.remove(entry);
            }
        }
        return List.copyOf(resolved);
    }
    public synchronized int size(){expire();return entries.size();}
    public synchronized int bytes(){expire();return bytes;}
}
