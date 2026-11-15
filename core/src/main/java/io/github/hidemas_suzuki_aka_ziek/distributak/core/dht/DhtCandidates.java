// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.LongSupplier;

/**
 * DHT の返事で知った、まだ確かめていない相手の候補の表（核 C1。答え 181 の 3・(e)）。
 * 候補は署名のない宛先であって、グループの一員である証拠ではない。握手の全検査を通るまで信用しない。
 * 一つのスレッドで使う。時計は差し込み。番地・端末の番号・鍵は文字列・例外に出さない（答え 166 (5)）。
 */
public final class DhtCandidates {
    public static final int MAX_CANDIDATES=128,MAX_PER_SOURCE=8,MAX_ACTIVE=8,MAX_STARTS=64,MAX_FIRSTS=3,MAX_FAILURES=128;
    public static final long LIFETIME_NANOS=180_000_000_000L,ATTEMPT_NANOS=90_000_000_000L,GIVE_UP_NANOS=30_000_000_000L,
            FIRST_INTERVAL_NANOS=10_000_000_000L,WINDOW_NANOS=300_000_000_000L,
            BACKOFF_FIRST_NANOS=120_000_000_000L,BACKOFF_MAX_NANOS=1_800_000_000_000L;

    /** 番地・ポート・握手の鍵。身元の署名を持たない。 */
    public static final class Candidate {
        private final DhtId node;
        private final byte[] ipv4,handshakeKey;
        private final int port;
        public Candidate(DhtId node,byte[] ipv4,int port,byte[] handshakeKey) {
            if(node==null||ipv4==null||ipv4.length!=4||handshakeKey==null||handshakeKey.length!=32)throw new IllegalArgumentException("Invalid candidate");
            this.node=node;this.ipv4=ipv4.clone();this.port=port;this.handshakeKey=handshakeKey.clone();
        }
        public DhtId node(){return node;}
        public byte[] ipv4(){return ipv4.clone();}
        public int port(){return port;}
        public byte[] handshakeKey(){return handshakeKey.clone();}
        @Override public String toString(){return "DHT candidate";}
    }

    /** 開始した 1 台ぶんの試み。同時に最大 3 台、90 秒で捨てる。 */
    public static final class Attempt {
        private final Candidate candidate;
        private final long startedAt;
        private long firstSentAt,lastFirst;
        private int firsts;
        private boolean answered,probed;
        private Attempt(Candidate candidate,long startedAt){this.candidate=candidate;this.startedAt=startedAt;}
        public Candidate candidate(){return candidate;}
        public int firstsSent(){return firsts;}
        @Override public String toString(){return "DHT candidate attempt";}
    }

    private static final class Entry {
        final Candidate candidate;
        final DhtId source;
        final long offeredAt;
        Entry(Candidate candidate,DhtId source,long offeredAt){this.candidate=candidate;this.source=source;this.offeredAt=offeredAt;}
    }
    private static final class Failure {
        int count;
        long until;
    }
    /** 番地は表の鍵にだけ使う。toString は固定の文にして、番地・ポートをログや例外に出さない。 */
    private record Address(int ip,int port){@Override public String toString(){return "DHT candidate address";}}

    private final DhtId self;
    private final LongSupplier ticker;
    private final List<Entry> entries=new ArrayList<>();
    private final List<Attempt> attempts=new ArrayList<>();
    private final Deque<Long> starts=new ArrayDeque<>();
    private final Map<Address,Failure> failures=new LinkedHashMap<>();
    private LocalNetwork network;
    private long lastTick;
    public DhtCandidates(DhtId self,LongSupplier ticker) {
        this.self=Objects.requireNonNull(self);this.ticker=Objects.requireNonNull(ticker);lastTick=ticker.getAsLong();
    }
    /** ネットワークが変わったら候補・試み・失敗の記録を捨てる。端末全体の開始の窓は、切り替えの繰り返しで抜けられないように残す。 */
    public void setNetwork(LocalNetwork next) {
        Objects.requireNonNull(next);touch();
        if(!next.equals(network)){entries.clear();attempts.clear();failures.clear();}
        network=next;
    }
    /** ネットワークの値が分からなくなったとき。候補・試み・失敗の記録を捨て、次の {@link #setNetwork} まで何も入れない。 */
    public void clear(){touch();entries.clear();attempts.clear();failures.clear();network=null;}
    public boolean offer(DhtId source,Candidate candidate) {
        Objects.requireNonNull(source);Objects.requireNonNull(candidate);long now=touch();purge(now);
        if(network==null||!network.allows(candidate.ipv4,candidate.port)||candidate.node.equals(self))return false;
        if(entries.size()>=MAX_CANDIDATES||knownNode(candidate.node)||knownAddress(candidate))return false;
        int fromSource=0;for(Entry e:entries)if(e.source.equals(source))fromSource++;
        if(fromSource>=MAX_PER_SOURCE)return false;
        Failure failure=failures.get(address(candidate));
        if(failure!=null&&now<failure.until)return false;
        entries.add(new Entry(candidate,source,now));return true;
    }
    private boolean knownNode(DhtId node) {
        for(Entry e:entries)if(e.candidate.node.equals(node))return true;
        for(Attempt a:attempts)if(a.candidate.node.equals(node))return true;
        return false;
    }
    private boolean knownAddress(Candidate c) {
        for(Entry e:entries)if(sameAddress(e.candidate,c))return true;
        for(Attempt a:attempts)if(sameAddress(a.candidate,c))return true;
        return false;
    }
    private static boolean sameAddress(Candidate a,Candidate b){return a.port==b.port&&Arrays.equals(a.ipv4,b.ipv4);}
    private static Address address(Candidate c) {
        byte[] b=c.ipv4;return new Address((b[0]&0xff)<<24|(b[1]&0xff)<<16|(b[2]&0xff)<<8|b[3]&0xff,c.port);
    }
    /** {@link #startFor} の結果。STARTED は今始めた、ACTIVE は同じ相手の試みがもう動いている、BUSY は上限（同時 8 台・5 分 64 件）、REFUSED は表に無い・失敗の待ちの番地。 */
    public enum Start { STARTED,ACTIVE,BUSY,REFUSED }
    /**
     * 探索が欲しい相手を名指しして握手の試みを始める（核 D。自動で古い順に始める口はやめた）。
     * 指名でも、候補の表（寿命 180 秒・紹介元ごと 8・全体 64 を通ったもの）に載っていて、失敗の待ちの番地でなく、同じ番号・番地の試みが動いていないときだけ始める。
     * 開始の数は始めたときだけ 1 つ数える（何度聞いても増えない）。BUSY のときは候補を残す。
     */
    public Start startFor(DhtId node) {
        Objects.requireNonNull(node);long now=touch();purge(now);
        for(Attempt a:attempts)if(a.candidate.node.equals(node))return Start.ACTIVE;
        int index=-1;for(int i=0;i<entries.size();i++)if(entries.get(i).candidate.node.equals(node)){index=i;break;}
        if(index<0)return Start.REFUSED;
        Entry entry=entries.get(index);Failure failure=failures.get(address(entry.candidate));
        if(failure!=null&&now<failure.until){entries.remove(index);return Start.REFUSED;}
        if(attempts.size()>=MAX_ACTIVE||starts.size()>=MAX_STARTS)return Start.BUSY;
        entries.remove(index);Attempt attempt=new Attempt(entry.candidate,now);
        attempts.add(attempt);starts.addLast(now);return Start.STARTED;
    }
    /**
     * {@link #startFor} を今呼んだら何が返るか（STARTED は「始められる」）。何も始めず、候補も捨てず、開始の数も増やさない。
     * 揮発の枠が満杯のとき、手放す前に「始められるか」を知るのに使う。
     */
    public Start check(DhtId node) {
        Objects.requireNonNull(node);long now=touch();purge(now);
        for(Attempt a:attempts)if(a.candidate.node.equals(node))return Start.ACTIVE;
        for(Entry e:entries) {
            if(!e.candidate.node.equals(node))continue;
            Failure failure=failures.get(address(e.candidate));
            if(failure!=null&&now<failure.until)return Start.REFUSED;
            return attempts.size()>=MAX_ACTIVE||starts.size()>=MAX_STARTS?Start.BUSY:Start.STARTED;
        }
        return Start.REFUSED;
    }
    /** 同時の試みが上限（3 台）に達しているか。BUSY の理由を「同時」と「5 分の件数」に分けるための読み口（件数・番号は返さない）。 */
    public boolean concurrentFull(){purge(touch());return attempts.size()>=MAX_ACTIVE;}
    /** その相手の試みが動いているか。 */
    public boolean isActive(DhtId node){return attemptFor(node).isPresent();}
    /** その相手の動いている試み。 */
    public Optional<Attempt> attemptFor(DhtId node) {
        Objects.requireNonNull(node);purge(touch());
        for(Attempt a:attempts)if(a.candidate.node.equals(node))return Optional.of(a);
        return Optional.empty();
    }
    /** 1 通目を出す番か。10 秒おき・最大 3 通。返事をもらったあとは出さない。 */
    public boolean firstDue(Attempt attempt) {
        long now=touch();
        if(!attempts.contains(attempt)||attempt.answered||attempt.firsts>=MAX_FIRSTS)return false;
        return attempt.firsts==0||now-attempt.lastFirst>=FIRST_INTERVAL_NANOS&&now-attempt.firstSentAt<GIVE_UP_NANOS;
    }
    public void firstSent(Attempt attempt) {
        long now=touch();if(!attempts.contains(attempt))return;
        if(attempt.firsts==0)attempt.firstSentAt=now;
        attempt.firsts++;attempt.lastFirst=now;
    }
    /** 相手から返事があった。1 通目はもう出さないが、枠は終わるか 90 秒まで持つ。 */
    public void answered(Attempt attempt){touch();if(attempts.contains(attempt))attempt.answered=true;}
    /** 試みを終える。通らなければその番地は 2 分から倍々（上限 30 分）で待つ。通れば失敗の記録を消す。 */
    public void finish(Attempt attempt,boolean success) {
        long now=touch();if(!attempts.remove(attempt))return;
        if(success)failures.remove(address(attempt.candidate));else fail(attempt.candidate,now);
    }
    /**
     * 3 つ目の閉じ方。失敗の待ちに入れず、開始の数（5 分 64 件）も戻さない。
     * 自分の側の都合（探りの枠が足りない等）で終える試みに使う。purge を先に走らせないので、ちょうど 90 秒でも失敗にされない。
     */
    public void release(Attempt attempt){touch();attempts.remove(attempt);}
    /** 握手のあと、探りを 1 通出した。出す前に 90 秒になった試みは、自分の枠の都合なので失敗の待ちに入れない。 */
    public void probeSent(Attempt attempt){touch();if(attempts.contains(attempt))attempt.probed=true;}
    private void fail(Candidate candidate,long now) {
        Address key=address(candidate);Failure failure=failures.remove(key);if(failure==null)failure=new Failure();
        long wait=failure.count>=5?BACKOFF_MAX_NANOS:Math.min(BACKOFF_MAX_NANOS,BACKOFF_FIRST_NANOS<<failure.count);
        failure.count++;failure.until=now+wait;failures.put(key,failure);
        while(failures.size()>MAX_FAILURES){Iterator<Address> oldest=failures.keySet().iterator();oldest.next();oldest.remove();}
    }
    /** 時間で捨てるものを捨てる。捨てた試みは通らなかったものとして数える。 */
    public void poll(){purge(touch());}
    private long touch() {
        long now=ticker.getAsLong();
        if(now<lastTick){entries.clear();attempts.clear();failures.clear();
            // 時計が戻ったら、開始の窓は最近のものとして数え直す（上限をゆるめない側）。
            int count=starts.size();starts.clear();for(int i=0;i<count;i++)starts.addLast(now);}
        lastTick=now;return now;
    }
    private void purge(long now) {
        entries.removeIf(e->now-e.offeredAt>=LIFETIME_NANOS);
        Iterator<Attempt> running=attempts.iterator();
        while(running.hasNext()) {
            Attempt a=running.next();
            boolean gaveUp=!a.answered&&a.firsts>0&&now-a.firstSentAt>=GIVE_UP_NANOS;
            boolean expired=now-a.startedAt>=ATTEMPT_NANOS;
            // 握手が済んで探りを 1 通も出せないまま 90 秒になったときは、自分の枠の都合なので失敗の待ちに入れない。
            if(expired&&a.answered&&!a.probed)running.remove();
            else if(gaveUp||expired){running.remove();fail(a.candidate,now);}
        }
        while(!starts.isEmpty()&&now-starts.peekFirst()>=WINDOW_NANOS)starts.removeFirst();
        failures.values().removeIf(f->now-f.until>=BACKOFF_MAX_NANOS);
    }
    public int size(){purge(touch());return entries.size();}
    public int active(){purge(touch());return attempts.size();}
    public int failures(){purge(touch());return failures.size();}
    public int startsInWindow(){purge(touch());return starts.size();}
    @Override public String toString(){return "DHT candidates";}
}
