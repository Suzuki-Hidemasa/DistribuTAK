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
import java.util.function.Predicate;

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
    private record Entry(ManagedDhtRecord record,byte[] encoded,byte[] memberId,byte[] owner,int qualifiedSigners,long started){}
    /**
     * 再検査した結果。保留のままの記録は含めない。
     * <p>
     * A rechecked result, excluding records that remain pending.
     */
    public record Checked(ManagedDhtRecord record,ManagedVerdict verdict){}
    private final Clock clock;
    private final ManagedVerifier authority;
    private final Predicate<byte[]> qualifiedSender;
    private final List<Entry> entries=new ArrayList<>();
    private int bytes;
    private boolean retrying;
    /**
     * 期限内の保留候補の写しを、依存取得の計画にだけ返す。適用には再検証が必要。
     * <p>
     * Returns a copy of unexpired pending candidates solely for dependency planning; application requires revalidation.
     */
    public synchronized List<ManagedDhtRecord> candidates(){checkReentry();expire();return entries.stream().map(Entry::record).toList();}
    public ManagedPending(Clock clock){this(clock,null,null);}
    /**
     * 現在の送り手と署名者の資格に基づいて保留枠を分ける。
     * <p>
     * Partitions pending slots using current transport-sender and signer qualifications.
     */
    public ManagedPending(Clock clock,ManagedVerifier authority,Predicate<byte[]> qualifiedSender){
        this.clock=Objects.requireNonNull(clock);
        if((authority==null)!=(qualifiedSender==null))throw new IllegalArgumentException("incomplete pending authority");
        this.authority=authority;this.qualifiedSender=qualifiedSender;
    }
    private static boolean pending(ManagedVerdict verdict){
        return verdict.status()==ManagedVerdict.Status.NEEDS_VERSION||verdict.status()==ManagedVerdict.Status.NEEDS_ANNOUNCEMENT;
    }
    private void checkReentry(){
        if(retrying)throw new IllegalStateException("pending retry is in progress");
    }
    private boolean remove(Entry entry){
        if(!entries.remove(entry))return false;
        bytes-=entry.encoded.length;return true;
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
        checkReentry();
        expire();if(record==null||verdict==null||!pending(verdict))return false;
        if(authenticatedMember!=null&&authenticatedMember.length!=32)return false;
        byte[] encoded=record.encode();
        for(var entry:entries)if(Arrays.equals(entry.encoded,encoded)&&Arrays.equals(entry.memberId,authenticatedMember))return true;
        int signers=authority==null?3:authority.pendingSignerQualifications(record);
        byte[] owner=authenticatedMember!=null&&signers==3&&(qualifiedSender==null||qualifiedSender.test(authenticatedMember.clone()))
                ?authenticatedMember.clone():null;
        long owned=entries.stream().filter(entry->Arrays.equals(entry.owner,owner)).count();
        if(owned>=2||entries.size()>=MAX_COUNT||encoded.length>MAX_BYTES-bytes)return false;
        entries.add(new Entry(record,encoded,authenticatedMember==null?null:authenticatedMember.clone(),owner,signers,clock.millis()));
        bytes+=encoded.length;return true;
    }
    /**
     * 現在の権限・失効・期限・手元の値で再検査する。同じ DHT 番号では順位の高い方から調べ、保留以外は枠から外して返す。
     * ACCEPTED は枠から外してから関数で適用する。関数は保存と状態更新を済ませてから戻り、途中で投げたら未適用として扱う。
     * 例外時はその項目を元の初回時刻と容量で戻し、例外をそのまま投げる。適用済みは外れたまま、未処理は残る。
     * retry 中に同じ枠の公開メソッドを呼ぶと IllegalStateException。ACCEPTED が出た通しのあとには残りを再検査し、出なくなれば終える。
     * <p>
     * Rechecks current authority, revocations, expiry and held values. Checks higher-ranked candidates first under each DHT key and removes and returns resolved results.
     * Removes ACCEPTED before applying it through the callback. The callback must finish storage and state updates before returning; a throw means unapplied.
     * On failure, restores that entry with its original arrival time and capacity and rethrows the same exception. Applied entries stay removed and unprocessed entries remain.
     * Calling a public method of the same area during retry throws IllegalStateException. Rechecks the remainder after any pass with ACCEPTED and stops when none is accepted.
     */
    public synchronized List<Checked> retry(ManagedVerifier verifier,Function<DhtId,ManagedDhtRecord> held,Consumer<Checked> apply) {
        return retry(verifier,held,apply,false);
    }
    /**
     * 観察用の呼出だけ、検証済みのOLDとDUPLICATEも渡す。失敗した項目は元の期限で戻す。
     * <p>
     * Also delivers verified OLD and DUPLICATE results for observation callers, restoring failed entries with their original deadlines.
     */
    public synchronized List<Checked> retry(ManagedVerifier verifier,Function<DhtId,ManagedDhtRecord> held,Consumer<Checked> apply,
            boolean deliverNonWinners){
        checkReentry();Objects.requireNonNull(verifier);Objects.requireNonNull(held);Objects.requireNonNull(apply);
        retrying=true;
        try{
            var resolved=new ArrayList<Checked>();
            boolean progressed;
            do{
                expire();
                var ordered=new ArrayList<>(entries);
                var records=new ArrayList<ManagedDhtRecord>();
                for(var entry:ordered)records.add(entry.record);
                var rank=verifier.pendingOrder(records);
                ordered.sort((a,b)->{
                    int key=AdminRecords.compareBytes(a.record.key().bytes(),b.record.key().bytes());
                    return key!=0?key:-rank.compare(a.record,b.record);
                });
                progressed=false;
                for(var entry:ordered){
                    expire();
                    if(!entries.contains(entry))continue;
                    if(authority!=null){
                        int currentSigners=authority.pendingSignerQualifications(entry.record);
                        if((entry.memberId!=null&&!qualifiedSender.test(entry.memberId.clone()))||(entry.qualifiedSigners&~currentSigners)!=0){
                            if(remove(entry))resolved.add(new Checked(entry.record,ManagedVerdict.INVALID));
                            continue;
                        }
                        if((entry.qualifiedSigners|currentSigners)!=entry.qualifiedSigners){
                            var learned=new Entry(entry.record,entry.encoded,entry.memberId,entry.owner,entry.qualifiedSigners|currentSigners,entry.started);
                            entries.set(entries.indexOf(entry),learned);entry=learned;
                        }
                    }
                    var current=held.apply(entry.record.key());
                    var verdict=entry.memberId==null?verifier.judge(entry.record,current):verifier.judgeStore(entry.record,current,entry.memberId);
                    if(!pending(verdict)&&remove(entry)){
                        var checked=new Checked(entry.record,verdict);
                        boolean accepted=verdict.status()==ManagedVerdict.Status.ACCEPTED;
                        if(accepted||deliverNonWinners&&(verdict.status()==ManagedVerdict.Status.OLD||verdict.status()==ManagedVerdict.Status.DUPLICATE)){
                            try{apply.accept(checked);}
                            catch(RuntimeException|Error failure){
                                entries.add(entry);bytes+=entry.encoded.length;throw failure;
                            }
                            if(accepted)progressed=true;
                        }
                        resolved.add(checked);
                    }
                }
            }while(progressed&&!entries.isEmpty());
            return List.copyOf(resolved);
        }finally{retrying=false;}
    }
    public synchronized int size(){checkReentry();expire();return entries.size();}
    /**
     * 終了時に保留の所有バッファを消す。
     * <p>
     * Wipes owned pending buffers on shutdown.
     */
    public synchronized void clear(){
        checkReentry();for(var entry:entries){
            io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto.wipe(entry.encoded);
            io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto.wipe(entry.memberId);
            io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto.wipe(entry.owner);
        }
        entries.clear();bytes=0;
    }
    public synchronized int bytes(){checkReentry();expire();return bytes;}
}
