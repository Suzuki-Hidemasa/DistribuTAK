// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

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
    /** 再検査した結果。保留のままの記録は含めない。 / A rechecked result, excluding records that remain pending. */
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
            if(now>=entry.started&&now-entry.started>=MAX_AGE_MILLIS){bytes-=entry.encoded.length;iterator.remove();}
        }
    }
    /** 検証器が保留とした FIND の値を預かる。 / Holds a FIND value marked pending by the verifier. */
    public synchronized boolean offer(ManagedDhtRecord record,ManagedVerdict verdict){return offer(record,verdict,null);}
    /** STORE の保留は、再検査用に認証済みの身元も渡す。 / For pending STORE, also passes the authenticated identity for rechecking. */
    public synchronized boolean offer(ManagedDhtRecord record,ManagedVerdict verdict,byte[] authenticatedMember) {
        expire();if(record==null||verdict==null||!pending(verdict))return false;
        if(authenticatedMember!=null&&authenticatedMember.length!=32)return false;
        byte[] encoded=record.encode();
        for(var entry:entries)if(Arrays.equals(entry.encoded,encoded))return true;
        if(entries.size()>=MAX_COUNT||encoded.length>MAX_BYTES-bytes)return false;
        entries.add(new Entry(record,encoded,authenticatedMember==null?null:authenticatedMember.clone(),clock.millis()));
        bytes+=encoded.length;return true;
    }
    /**
     * 現在の権限・失効・期限・手元の値で再検査する。保留以外の結果は枠から外して返し、適用は呼び出し元に任せる。
     * <p>
     * Rechecks current authority, revocations, expiry and held values. Removes and returns resolved results; callers apply them.
     */
    public synchronized List<Checked> retry(ManagedVerifier verifier,Function<DhtId,ManagedDhtRecord> held) {
        expire();var resolved=new ArrayList<Checked>();var iterator=entries.iterator();
        while(iterator.hasNext()){
            var entry=iterator.next();var current=held.apply(entry.record.key());
            var verdict=entry.memberId==null?verifier.judge(entry.record,current):verifier.judgeStore(entry.record,current,entry.memberId);
            if(!pending(verdict)){resolved.add(new Checked(entry.record,verdict));bytes-=entry.encoded.length;iterator.remove();}
        }
        return List.copyOf(resolved);
    }
    public synchronized int size(){expire();return entries.size();}
    public synchronized int bytes(){expire();return bytes;}
}
