// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.time.Clock;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryStatus.*;

/** 同じグループの発行者からだけコピーを預かる。一つのスレッドで使い、永続保存はしない。 */
public final class DiscoveryStore {
    public static final int MAX_RECORDS=4096,MAX_ENCODED_BYTES=4*1024*1024,MAX_VERSIONS=4096;
    static final long RETENTION_NANOS=DhtLimits.RECORD_LIFETIME_MILLIS*1_000_000L;
    private static final class Maximum {
        final long version;
        final byte[] digest;
        boolean active=true;
        long removedAt;
        Object removedEpoch;
        Maximum(DiscoveryRecord record){version=record.version();digest=record.payloadDigest();}
    }
    private final byte[] group;
    private final Clock clock;
    private final LongSupplier ticker;
    private final Predicate<DhtId> revoked;
    private final int byteBudget;
    private final DhtRecordBudget sharedBudget;
    private final Map<DhtId,DiscoveryRecord> records=new LinkedHashMap<>();
    private final Map<DhtId,Maximum> maxima=new LinkedHashMap<>();
    private final DiscoveryCounts counts=new DiscoveryCounts();
    private boolean busy;
    private long encodedBytes,lastTick;
    private Object clockEpoch=new Object();
    private long resetAt;
    public DiscoveryStore(byte[] group,Clock clock,LongSupplier ticker,Predicate<DhtId> revoked) {
        this(group,clock,ticker,revoked,MAX_ENCODED_BYTES);
    }
    /** 小さいバイト予算を使う試験専用。pluginから変える口は作らない。 */
    DiscoveryStore(byte[] group,Clock clock,LongSupplier ticker,Predicate<DhtId> revoked,int byteBudget) {
        this(group,clock,ticker,revoked,byteBudget,new DhtRecordBudget());
    }
    /**
     * 管理記録と同じ預かり容量を使う。
     * <p>
     * Shares copy capacity with management records.
     */
    public static DiscoveryStore shared(byte[] group,Clock clock,LongSupplier ticker,Predicate<DhtId> revoked,DhtRecordBudget budget){
        return new DiscoveryStore(group,clock,ticker,revoked,MAX_ENCODED_BYTES,budget);
    }
    private DiscoveryStore(byte[] group,Clock clock,LongSupplier ticker,Predicate<DhtId> revoked,int byteBudget,DhtRecordBudget budget) {
        if(group==null||group.length!=32||byteBudget<1||byteBudget>MAX_ENCODED_BYTES)throw DiscoveryRecord.rejected(INVALID);
        this.group=group.clone();this.clock=Objects.requireNonNull(clock);this.ticker=Objects.requireNonNull(ticker);
        this.revoked=Objects.requireNonNull(revoked);this.byteBudget=byteBudget;lastTick=ticker.getAsLong();
        sharedBudget=Objects.requireNonNull(budget);sharedBudget.register(this::purgeLocked);
    }
    /** 失効の判定や時計の中から表を呼ぶと、途中の状態を壊すので断る。 */
    private void enter() {
        if(busy)throw new IllegalStateException("DHTの預かりの表は呼び出しの途中で使えません");
        busy=true;
    }
    public DiscoveryStatus put(AuthenticatedPeer sender,byte[] wire) {
        enter();
        try {
            DiscoveryStatus status=putLocked(sender==null?null:sender.id(),wire);
            counts.rejected(status);
            return status;
        }finally{busy=false;}
    }
    /**
     * 自分の記録を自分の表へ入れる。送り手の認証つきの型は使わず、ほかの相手から受けるときと同じ検査の道を通す
     * （署名・期限・失効・版・容量。記録の持ち主が self でなければ SENDER_MISMATCH）。
     * 件数は他の相手から受けた拒否とは別に、自分の記録の受け入れ・拒否として数える。
     */
    public DiscoveryStatus putOwn(DhtId self,byte[] wire) {
        enter();
        try {
            DiscoveryStatus status=putLocked(self,wire);
            counts.own(status);
            return status;
        }finally{busy=false;}
    }
    /** 数えない本体。件数は呼び出し側が数える。 */
    private DiscoveryStatus putLocked(DhtId senderId,byte[] wire) {
        sharedBudget.purge();
        try {
            DiscoveryRecord record=verify(wire,clock);
            if(senderId==null||!senderId.equals(record.nodeId()))return SENDER_MISMATCH;
            DiscoveryStatus order=checkMaximum(record);
            if(order==DUPLICATE)return DUPLICATE;
            if(order!=ACCEPTED)return order;
            DhtId key=record.key();DiscoveryRecord previous=records.get(key);
            if(previous==null&&records.size()>=MAX_RECORDS||!maxima.containsKey(key)&&maxima.size()>=MAX_VERSIONS
                    ||!hasByteCapacity(encodedBytes,previous==null?0:previous.encodedSize(),record.encodedSize(),byteBudget))return CAPACITY;
            if(!sharedBudget.replace(previous==null?0:previous.encodedSize(),record.encodedSize()))return CAPACITY;
            encodedBytes=encodedBytes-(previous==null?0:previous.encodedSize())+record.encodedSize();
            records.put(key,record);maxima.put(key,new Maximum(record));return ACCEPTED;
        }catch(DiscoveryRejected rejected){return rejected.status();}
    }
    DiscoveryRecord verify(byte[] wire,Clock clock){return DiscoveryRecord.verify(wire,group,clock,revoked);}
    /** 表に入れずに、この表の時計・グループ・失効の判定で記録を検証する（直接の FIND_VALUE の結果用）。 */
    DiscoveryRecord verifyOwnClock(byte[] wire){return DiscoveryRecord.verify(wire,group,clock,revoked);}
    /** VALUEは最大版を読むだけ。時計の保守も表の項目へは書き込まない。 */
    DiscoveryStatus checkMaximum(DiscoveryRecord record) {
        long now=touchTime();Maximum previous=maxima.get(record.key());
        if(previous==null||!previous.active&&retentionExpired(now,previous))return ACCEPTED;
        if(record.version()<previous.version)return OLD_VERSION;
        if(record.version()==previous.version)return Arrays.equals(record.payloadDigest(),previous.digest)?DUPLICATE:CONFLICT;
        return ACCEPTED;
    }
    public Optional<DiscoveryRecord> get(DhtId key) {
        Objects.requireNonNull(key);enter();
        try {
            purgeLocked();
            try{if(clock.millis()<0)return Optional.empty();}catch(RuntimeException unreadable){return Optional.empty();}
            return Optional.ofNullable(records.get(key));
        }finally{busy=false;}
    }
    public int size(){return records.size();}
    public int maximumSize(){return maxima.size();}
    public long encodedBytes(){return encodedBytes;}
    public DiscoveryCounts counts(){return counts;}
    public DiscoveryLookup newLookupVerifier(){return new DiscoveryLookup(this);}
    public void removeRevoked(){purge();}
    /** コピーの期限は壁時計、除いたあとの最大版の24時間は単調時計で測る。 */
    public void purge(){enter();try{purgeLocked();}finally{busy=false;}}
    /**
     * 預かっているコピーを、期限内のものも含めて全部消す（止めるとき・失敗したときにメモリを捨てるため）。
     * 消したコピーの最大版は、期限や失効で消したときと同じ決まりで 24 時間残す（版の巻き戻しを防ぐ検査は変えない）。
     * 上限・期限・検査は変えない。消したあとも新しい記録は今までどおり受ける。
     */
    public void clear() {
        enter();
        try {
            long tick=touchTime();
            for(var entry:records.entrySet()) {
                Maximum maximum=maxima.get(entry.getKey());
                if(maximum!=null&&maximum.active){maximum.active=false;maximum.removedAt=tick;maximum.removedEpoch=clockEpoch;}
            }
            for(var record:records.values())sharedBudget.replace(record.encodedSize(),0);
            records.clear();encodedBytes=0;
        }finally{busy=false;}
    }
    private void purgeLocked() {
        long tick=touchTime(),wall=0;boolean clockUnreadable=false;
        try{wall=clock.millis();}catch(RuntimeException unreadable){clockUnreadable=true;}
        Iterator<Map.Entry<DhtId,DiscoveryRecord>> copies=records.entrySet().iterator();
        while(copies.hasNext()) {
            var entry=copies.next();DiscoveryRecord record=entry.getValue();
            // 時計・失効の判定が例外を出したら判定できない記録として除く（verify の例外を INVALID にするのと同じ側。外へは出さない）。
            if(clockUnreadable||wall>=0&&wall>=record.expiresAt()||isRevoked(record.nodeId())) {
                sharedBudget.replace(record.encodedSize(),0);
                encodedBytes-=record.encodedSize();copies.remove();Maximum maximum=maxima.get(entry.getKey());
                if(maximum.active){maximum.active=false;maximum.removedAt=tick;maximum.removedEpoch=clockEpoch;}
            }
        }
        var iterator=maxima.values().iterator();
        while(iterator.hasNext()){Maximum maximum=iterator.next();if(!maximum.active&&retentionExpired(tick,maximum))iterator.remove();}
    }
    private boolean isRevoked(DhtId node) {
        try{return revoked.test(node);}catch(RuntimeException unjudgeable){return true;}
    }
    private long touchTime() {
        long now=ticker.getAsLong();
        if(now<lastTick){clockEpoch=new Object();resetAt=now;}
        lastTick=now;return now;
    }
    private boolean retentionExpired(long now,Maximum maximum) {
        // 古い時計の世代の項目は共通の巻き戻り時点から数える。項目自体を更新する必要はない。
        long removedAt=maximum.removedEpoch==clockEpoch?maximum.removedAt:resetAt;
        if(now<removedAt)return false;long elapsed=now-removedAt;return elapsed<0||elapsed>=RETENTION_NANOS;
    }
    /** 実際の記録だけでは届かない4MiBの境界も、桁あふれせずに判定する。 */
    static boolean hasByteCapacity(long current,long removed,long incoming,long limit) {
        return current>=0&&removed>=0&&removed<=current&&incoming>=0&&limit>=0&&incoming<=limit&&current-removed<=limit-incoming;
    }
    @Override public String toString(){return "DHT discovery store";}
}
