// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.LongSupplier;

/**
 * 反復探索とバケットのPING。スレッドもソケットも作らない。
 * Vは検証済みの不変の値。実際の署名・期限の検査と版の比較は核Bから渡す。
 */
public final class DhtNode<V> {
    /** COMPLETE は探し終えた場合のほかに、値を得て送った返事の決着がついた場合も含む。 */
    public enum Stop { COMPLETE,QUERY_LIMIT,DEADLINE,CLOCK_RESET,NETWORK_CHANGED }
    @FunctionalInterface public interface Verifier<V> {
        /** 不正な記録はnullで断る。RuntimeExceptionも全て拒否として扱い、文は記録しない。引数はコピー。 */
        V verify(DhtId key,byte[] encoded,Clock clock);
        /** 探索が終わったとき 1 回だけ呼ぶ（件数をまとめて渡す用）。例外は外へ出さない。 */
        default void finished(){}
    }
    /** 外へ出す診断は台数と終了の理由だけ。値の中身はtoStringに出さない。 */
    public static final class Result<V> {
        private final Stop stop;
        private final int queried,responded,candidates;
        private final V value;
        private final List<Contact> closest;
        private Result(Stop stop,int queried,int responded,int candidates,V value,List<Contact> closest) {
            this.stop=stop;this.queried=queried;this.responded=responded;this.candidates=candidates;this.value=value;this.closest=closest;
        }
        public Stop stop(){return stop;}
        public int queried(){return queried;}
        public int responded(){return responded;}
        public int candidates(){return candidates;}
        public Optional<V> value(){return Optional.ofNullable(value);}
        /**
         * 返事をくれた近い相手を、距離の近い順に最大 K 台。番号だけの不変の一覧。
         * 終わり方が COMPLETE・QUERY_LIMIT・DEADLINE のときだけ出し、返事のない相手・待ちの相手は入れない。
         * 値の探索（FIND_VALUE）では、値を得て早く終えるため、返事をくれた相手だけの一覧になる。STORE の送り先には使わない
         * （答え 190 (1)。STORE の送り先は FIND_NODE の結果から決める）。
         */
        public List<Contact> closest(){return closest;}
        @Override public String toString(){return "DHT lookup result";}
    }
    /** RELEASED は案 B で最初の値の印のときに手放した握手待ち。完了の数・参照・近い順の一覧に入れず、握手そのものは閉じない。 */
    private enum State { NEW,CONNECTING,WAITING,DONE,FAILED,RELEASED }
    private static final class Candidate {
        final Contact contact;
        State state=State.NEW;
        DhtTransport.Request request;
        long started,connectingSince;
        int retries;
        /** 初めての BUSY を配送側へ知らせたか（1 つの候補につき 1 回だけ）。 */
        boolean busyCounted;
        byte[] record;
        /** 検証済みの値を受けた順（同じ版で中身が違うとき、最初に受けたほうを残すため）。 */
        long order;
        Candidate(Contact contact){this.contact=contact;}
    }
    public final class Lookup {
        private final DhtId target;
        private final boolean findValue;
        private final long started;
        private final Map<DhtId,Candidate> candidates=new LinkedHashMap<>();
        private Verifier<V> valueVerifier;
        private Comparator<V> valueVersions;
        private int queried,responded;
        /** 最初の検証済みの値を受けたら立てる（FIND_NODE では立てない）。立ったら新しい問い合わせを出さない。 */
        private boolean valueMarked;
        private long receivedOrder;
        private Result<V> result;
        private Lookup(DhtId target,boolean findValue,long now,Verifier<V> verifier,Comparator<V> versions) {
            this.target=target;this.findValue=findValue;started=now;valueVerifier=verifier;valueVersions=versions;
        }
        public boolean done(){return result!=null;}
        public Result<V> result() {
            if(result==null)throw new IllegalStateException("DHTの探索はまだ終わっていません");return result;
        }
        private void add(Contact contact) {
            if(done()||contact.id().equals(local)||candidates.containsKey(contact.id()))return;
            if(candidates.size()>=DhtLimits.MAX_CANDIDATES) {
                Candidate farthest=null;
                for(Candidate candidate:candidates.values())if(candidate.state==State.NEW
                        &&(farthest==null||target.compareDistance(candidate.contact.id(),farthest.contact.id())>0))farthest=candidate;
                // 照会済みと返事待ちは残す。候補の数の上限を探索の終了理由にはしない。
                if(farthest==null||target.compareDistance(contact.id(),farthest.contact.id())>=0)return;
                candidates.remove(farthest.contact.id());
            }
            candidates.put(contact.id(),new Candidate(contact));
        }
        private List<Candidate> closest() {
            List<Candidate> result=new ArrayList<>();
            for(Candidate candidate:candidates.values())if(candidate.state!=State.FAILED&&candidate.state!=State.RELEASED)result.add(candidate);
            result.sort((a,b)->target.compareDistance(a.contact.id(),b.contact.id()));
            return result.subList(0,Math.min(DhtLimits.K,result.size()));
        }
        /** 返事待ちと握手待ちの合計。α はこの合計で数える。 */
        private int inFlight() {
            int count=0;for(Candidate candidate:candidates.values())if(candidate.state==State.WAITING||candidate.state==State.CONNECTING)count++;return count;
        }
        private int count(State state) {
            int count=0;for(Candidate candidate:candidates.values())if(candidate.state==state)count++;return count;
        }
        private boolean references(DhtId id) {
            Candidate candidate=candidates.get(id);
            return candidate!=null&&(candidate.state==State.WAITING||candidate.state==State.CONNECTING);
        }
        /** 返事をくれた相手の近い順の一覧。探索が正常に終わったときだけ。 */
        private List<Contact> repliedNearest(Stop stop) {
            if(stop==Stop.NETWORK_CHANGED||stop==Stop.CLOCK_RESET)return List.of();
            List<Candidate> replied=new ArrayList<>();
            for(Candidate candidate:candidates.values())if(candidate.state==State.DONE)replied.add(candidate);
            replied.sort((a,b)->target.compareDistance(a.contact.id(),b.contact.id()));
            List<Contact> contacts=new ArrayList<>();
            for(Candidate candidate:replied.subList(0,Math.min(DhtLimits.K,replied.size())))contacts.add(candidate.contact);
            return List.copyOf(contacts);
        }
        private void finish(Stop stop) {
            if(done())return;V best=null;
            if(stop==Stop.QUERY_LIMIT)lookupsQueryLimit=inc(lookupsQueryLimit);
            else if(stop==Stop.DEADLINE)lookupsDeadline=inc(lookupsDeadline);
            if(findValue&&stop!=Stop.CLOCK_RESET&&stop!=Stop.NETWORK_CHANGED) {
                // 案 B: 検証済みの値を全て、受けた順に見て、版が一番新しいものを選ぶ（同じ版なら最初に受けたほうを残す）。
                List<Candidate> received=new ArrayList<>();
                for(Candidate candidate:candidates.values())if(candidate.record!=null)received.add(candidate);
                received.sort(Comparator.comparingLong(candidate->candidate.order));
                for(Candidate candidate:received) {
                    // 待っている間に期限が切れた記録も除く。受信したバイト列そのものを再検査する。
                    V value=verify(target,candidate.record,valueVerifier);
                    if(value!=null&&(best==null||newer(value,best,valueVersions)))best=value;
                }
            }
            result=new Result<>(stop,queried,responded,candidates.size(),best,repliedNearest(stop));
            if(valueVerifier!=null)try{valueVerifier.finished();}catch(RuntimeException ignored){/* 件数の受け渡しの失敗で探索の結果は変えない */}
            // 完了したhandleを呼び出し側が残しても、応答本文と候補の表は残さない。
            candidates.clear();valueVerifier=null;valueVersions=null;
        }
        private void poll(long now) {
            if(done())return;
            if(elapsed(now,started)>=DhtLimits.LOOKUP_NANOS){finish(Stop.DEADLINE);return;}
            for(Candidate candidate:candidates.values()) {
                if(candidate.state==State.WAITING) {
                    long age=elapsed(now,candidate.started);
                    if(age>=rpcLifetime())candidate.state=State.FAILED;
                    else if(age>=DhtLimits.RPC_NANOS&&candidate.retries<DhtLimits.RPC_RETRIES) {
                        candidate.retries++;
                        if(!deliver(candidate.contact,candidate.request))candidate.state=State.FAILED;
                    }
                } else if(candidate.state==State.CONNECTING)advance(candidate,now);
            }
            // 値の印のあとは新しい問い合わせを出さない（送った問い合わせの再送と 6 秒の失敗は上で済ませた）。
            if(!valueMarked)for(Candidate candidate:closest()) {
                if(inFlight()>=DhtLimits.ALPHA||queried>=DhtLimits.MAX_QUERIES)break;
                if(candidate.state!=State.NEW)continue;
                // 握手を始める・送る・諦めるときに 1 回だけ queried を足す。BUSY は NEW のまま残して数えない。
                switch(prepare(candidate.contact)) {
                    case READY -> {queried++;send(candidate,now);}
                    case CONNECTING -> {candidate.state=State.CONNECTING;candidate.connectingSince=now;queried++;}
                    case UNAVAILABLE -> {candidate.state=State.FAILED;queried++;unavailableFailed=inc(unavailableFailed);}
                    case BUSY -> {
                        // NEW のまま。ほかの NEW を先に試す。初めての BUSY だけ 1 回、配送側へ知らせる（聞き直しでは数えない）。
                        if(!candidate.busyCounted) {
                            candidate.busyCounted=true;
                            try{transport.firstBusy(candidate.contact);}catch(RuntimeException ignored){/* 件数の知らせの失敗で探索は変えない */}
                        }
                    }
                }
            }
            if(count(State.WAITING)!=0)return;
            if(valueMarked){finish(Stop.COMPLETE);return;}
            boolean remaining=false;for(Candidate candidate:closest())if(candidate.state==State.NEW){remaining=true;break;}
            if(count(State.CONNECTING)!=0) {
                // 握手が終わらなくても締切は延ばさない。128 に届いたら待たずに終える。
                if(queried>=DhtLimits.MAX_QUERIES)finish(Stop.QUERY_LIMIT);
                return;
            }
            if(!remaining)finish(Stop.COMPLETE);
            else if(queried>=DhtLimits.MAX_QUERIES)finish(Stop.QUERY_LIMIT);
        }
        /** 最初の検証済みの値で 1 回だけ印を立て、つなぎ中の候補を手放す（握手の試みは閉じず、queried は変えない）。 */
        private void markValue() {
            if(valueMarked)return;
            valueMarked=true;
            for(Candidate candidate:candidates.values())if(candidate.state==State.CONNECTING) {
                candidate.state=State.RELEASED;connectingReleased=inc(connectingReleased);
            }
        }
        /** 握手待ちの候補を 1 つ進める。入ってから 90 秒で失敗。READY になったら送る（queried は足さない）。 */
        private void advance(Candidate candidate,long now) {
            if(elapsed(now,candidate.connectingSince)>=DhtCandidates.ATTEMPT_NANOS) {
                candidate.state=State.FAILED;connectingTimedOut=inc(connectingTimedOut);return;
            }
            switch(prepare(candidate.contact)) {
                case READY -> send(candidate,now);
                case CONNECTING -> {/* まだ待つ */}
                case BUSY -> candidate.state=State.FAILED;
                case UNAVAILABLE -> {candidate.state=State.FAILED;unavailableFailed=inc(unavailableFailed);}
            }
        }
        /** 要求を作って送る。RPC の時計は送った時から数える。送れなければその候補だけ失敗。 */
        private void send(Candidate candidate,long now) {
            candidate.request=new DhtTransport.Request(nextId(),findValue?DhtTransport.Operation.FIND_VALUE:DhtTransport.Operation.FIND_NODE,target);
            candidate.state=State.WAITING;candidate.started=now;candidate.retries=0;
            if(!deliver(candidate.contact,candidate.request))candidate.state=State.FAILED;
        }
        private boolean receive(AuthenticatedPeer source,long id,List<Contact> contacts,byte[] record,long now) {
            if(done())return false;
            if(elapsed(now,started)>=DhtLimits.LOOKUP_NANOS){finish(Stop.DEADLINE);return false;}
            Candidate candidate=candidates.get(source.id());
            if(candidate==null||candidate.state!=State.WAITING||candidate.request.id()!=id)return false;
            if(elapsed(now,candidate.started)>=rpcLifetime()){candidate.state=State.FAILED;return false;}
            candidate.state=State.DONE;responded++;
            boolean carried=findValue&&record!=null&&verify(target,record,valueVerifier)!=null;
            if(carried) {
                candidate.record=record.clone();candidate.order=++receivedOrder;markValue();
            } else {
                // 検証済みの値を運んだ返事の連絡先は候補に足さない（値の探索はもう近づけない）。
                for(Contact contact:contacts){add(Objects.requireNonNull(contact));if(done())break;}
            }
            // 印が立っていて、送った問い合わせの返事が片づいたら、poll を待たずにその場で終える。
            if(valueMarked&&count(State.WAITING)==0)finish(Stop.COMPLETE);
            return true;
        }
        @Override public String toString(){return "DHT lookup";}
    }
    private static final class Ping {
        final DhtRoutingTable.Probe probe;
        final DhtTransport.Request request;
        final long started;
        int retries;
        Ping(DhtRoutingTable.Probe probe,DhtTransport.Request request,long started){this.probe=probe;this.request=request;this.started=started;}
    }
    private final DhtId local;
    private final Clock clock;
    private final LongSupplier ticker;
    private final DhtTransport transport;
    private final Verifier<V> verifier;
    private final Comparator<V> versions;
    private final DhtRoutingTable routing;
    private final DhtCandidates candidates;
    private final List<Lookup> lookups=new ArrayList<>();
    private final Map<Long,Ping> pings=new LinkedHashMap<>();
    private long lastTick,refreshBase,sequence,networkFloor,generation;
    private int pollStart;
    private boolean processing;
    /** 探索が数える合計の件数（相手ごとには持たない。番号は残さない）。 */
    private long lookupsQueryLimit,lookupsDeadline,unavailableFailed,connectingTimedOut,connectingReleased;
    private static long inc(long value){return value==Long.MAX_VALUE?value:value+1;}
    public DhtNode(DhtId local,Clock clock,LongSupplier ticker,DhtTransport transport,Verifier<V> verifier,Comparator<V> versions) {
        this.local=Objects.requireNonNull(local);this.clock=Objects.requireNonNull(clock);this.ticker=Objects.requireNonNull(ticker);
        this.transport=Objects.requireNonNull(transport);this.verifier=Objects.requireNonNull(verifier);this.versions=Objects.requireNonNull(versions);
        routing=new DhtRoutingTable(local);candidates=new DhtCandidates(local,ticker);lastTick=ticker.getAsLong();refreshBase=lastTick;
    }
    public DhtRoutingTable routing(){return routing;}
    /** 確かめていない候補の表。ネットワークが変わると {@link #networkChanged} で捨てる。 */
    public DhtCandidates candidates(){return candidates;}
    /** ネットワークが変わるたびに増える世代。配送側はセッションを受け入れたときの値を相手に持たせる。 */
    public long generation(){enter();try{return generation;}finally{processing=false;}}
    /** 任意の同期の受信ではなく、認証済みのDHT受信を渡す。 */
    public void observe(AuthenticatedPeer peer) {
        enter();try{checkTime();if(current(peer))routing.observe(peer);}finally{processing=false;}
    }
    public Lookup findNode(DhtId target){return start(target,false,verifier,versions);}
    public Lookup findValue(DhtId key){return start(key,true,verifier,versions);}
    /** 回答7550。検査と比較の状態を一探索の間だけ保持する。 */
    public Lookup findValue(DhtId key,Verifier<V> verifier,Comparator<V> versions){return start(key,true,verifier,versions);}
    private Lookup start(DhtId target,boolean findValue,Verifier<V> verifier,Comparator<V> versions) {
        enter();
        try {
            Objects.requireNonNull(target,"DHTの番号が必要です");Objects.requireNonNull(verifier,"DHTの検査器が必要です");
            Objects.requireNonNull(versions,"DHTの比較が必要です");long now=checkTime();prune();
            if(lookups.size()>=DhtLimits.MAX_LOOKUPS)throw new IllegalStateException("DHTの同時探索が上限に達しています");
            Lookup lookup=new Lookup(target,findValue,now,verifier,versions);
            for(AuthenticatedPeer peer:routing.nearest(target,DhtLimits.K))lookup.add(peer.contact());
            lookups.add(lookup);return lookup;
        } finally {processing=false;}
    }
    /** いずれかの探索が、その相手の返事か握手を待っているか。手放してよいかの判定に使う。 */
    boolean isReferenced(DhtId id) {
        for(Lookup lookup:lookups)if(lookup.references(id))return true;
        return false;
    }
    /** 読むだけの口では時計も状態も変えない。 */
    public int activeLookups(){return lookups.size();}
    /** 128 通に届いて終わった探索の数（合計）。 */
    long lookupsQueryLimit(){return lookupsQueryLimit;}
    /** 締切（120 秒）で終わった探索の数（合計）。 */
    long lookupsDeadline(){return lookupsDeadline;}
    /** 配送側が UNAVAILABLE と答えて FAILED にした候補の数（合計。BUSY の失敗・送信の失敗は入れない）。 */
    long unavailableFailed(){return unavailableFailed;}
    /** つなぎ中が 90 秒に届いて FAILED にした候補の数（合計）。 */
    long connectingTimedOut(){return connectingTimedOut;}
    /** 案 B で、最初の値の印のときに手放したつなぎ中の候補の数（合計。失敗にも時間切れにも入れない）。 */
    long connectingReleased(){return connectingReleased;}
    /**
     * いま探索を新しく始められるか（終わっていない探索が同時の上限より少ないか）。読むだけで、時計も状態も変えない。
     * start が最初に終わった探索を片付けてから数えるのと同じ数え方。
     */
    public boolean canStartLookup() {
        int running=0;
        for(Lookup lookup:lookups)if(!lookup.done())running++;
        return running<DhtLimits.MAX_LOOKUPS;
    }
    public void poll() {
        enter();
        try {
            long now=checkTime();pollPings(now);
            // 先頭を毎回ずらし、同じ探索だけが握手の枠を先に取り続けないようにする。
            int count=lookups.size();
            if(count!=0){int first=pollStart%count;for(int i=0;i<count;i++)lookups.get((first+i)%count).poll(now);}
            prune();pollStart=lookups.isEmpty()?0:(pollStart+1)%lookups.size();
        } finally {processing=false;}
    }
    /** contactsとrecordは配送側が構文と長さを検査済みの応答。未認証の受信を渡す口は作らない。 */
    public void receive(AuthenticatedPeer source,long requestId,List<Contact> contacts,byte[] record) {
        enter();
        try {
            Objects.requireNonNull(source);Objects.requireNonNull(contacts);long now=checkTime();
            // 前のネットワークの要求への応答で、消した経路表を復活させない。
            if(requestId>0&&requestId<=networkFloor)return;
            // 前のネットワークで受け入れたセッションの受信は、要求の番号が新しくても受け付けない（核 C1）。
            if(!current(source))return;
            routing.observe(source);
            Ping ping=pings.get(requestId);
            if(ping!=null&&ping.probe.incumbent().id().equals(source.id())) {
                // 時間切れ後でも、今の認証済みの受信が生存の証拠になる。
                pings.remove(requestId);return;
            }
            for(Lookup lookup:lookups)if(lookup.receive(source,requestId,contacts,record,now))break;
            prune();
        } finally {processing=false;}
    }
    /** 周期を消費する口。実際のバケット見直しの配送は呼び出し側から始める。 */
    public boolean refreshDue() {
        enter();
        try {
            long now=checkTime();if(elapsed(now,refreshBase)<DhtLimits.REFRESH_NANOS)return false;
            refreshBase=now;return true;
        } finally {processing=false;}
    }
    /** 自分で世代を数える口。試験専用（本番は世代とサブネットを一緒に渡す口だけを使う）。 */
    void networkChanged() {
        enter();
        try{long now=checkTime();cancel(Stop.NETWORK_CHANGED);routing.clear();candidates.clear();refreshBase=now;networkFloor=sequence;generation++;}
        finally{processing=false;}
    }
    /** 世代だけ SessionManager にそろえる口。試験専用。 */
    void networkChanged(long sessionGeneration) {
        enter();
        try{
            if(sessionGeneration<=generation)throw new IllegalArgumentException("DHTの世代が進んでいません");
            long now=checkTime();cancel(Stop.NETWORK_CHANGED);routing.clear();candidates.clear();refreshBase=now;networkFloor=sequence;generation=sessionGeneration;
        } finally{processing=false;}
    }
    /** 新しいサブネットだけを受ける口。試験専用。 */
    void networkChanged(LocalNetwork next) {
        Objects.requireNonNull(next);networkChanged();candidates.setNetwork(next);
    }
    /**
     * ネットワークが変わったとき、SessionManager の世代（generation()）と新しい自分の番地・接頭辞を 1 回の呼び出しでそろえる。
     * 本番はこの口だけを使う（世代とサブネットを別々に渡すと、片方だけ古いまま残る隙間ができるため）。
     * これより前の世代の VerifiedSession から作った相手の受信は、核の口で捨てる。世代は戻らない。
     * 世代が進んでいない・network が null のときは、何も変えずに断る。
     */
    public void networkChanged(long sessionGeneration,LocalNetwork network) {
        Objects.requireNonNull(network);
        enter();
        try{
            if(sessionGeneration<=generation)throw new IllegalArgumentException("DHTの世代が進んでいません");
            long now=checkTime();cancel(Stop.NETWORK_CHANGED);routing.clear();candidates.clear();refreshBase=now;networkFloor=sequence;generation=sessionGeneration;
            candidates.setNetwork(network);
        } finally{processing=false;}
    }
    private void pollPings(long now) {
        var iterator=pings.values().iterator();
        while(iterator.hasNext()) {
            Ping ping=iterator.next();
            if(!routing.isPending(ping.probe)){iterator.remove();continue;}
            long age=elapsed(now,ping.started);
            if(age>=rpcLifetime()){routing.resolve(ping.probe,false);iterator.remove();}
            else if(age>=DhtLimits.RPC_NANOS&&ping.retries<DhtLimits.RPC_RETRIES) {
                ping.retries++;
                if(!deliver(ping.probe.incumbent().contact(),ping.request)){routing.discard(ping.probe);iterator.remove();}
            }
        }
        for(DhtRoutingTable.Probe probe:routing.probes()) {
            boolean existing=false;for(Ping ping:pings.values())if(ping.probe==probe){existing=true;break;}
            if(existing)continue;
            var request=new DhtTransport.Request(nextId(),DhtTransport.Operation.PING,local);
            pings.put(request.id(),new Ping(probe,request,now));
            if(!deliver(probe.incumbent().contact(),request)){pings.remove(request.id());routing.discard(probe);}
        }
    }
    /** 手元の配送失敗は相手の死亡とは分け、例外の文も記録しない。 */
    private boolean deliver(Contact destination,DhtTransport.Request request) {
        try{return transport.send(destination,request);}
        catch(RuntimeException failed){return false;}
    }
    private V verify(DhtId key,byte[] encoded,Verifier<V> verifier) {
        try{return verifier.verify(key,encoded.clone(),clock);}
        catch(RuntimeException rejected){return null;}
    }
    /** 比較できなかった候補を断り、それまでの検査済みの値は残す。 */
    private boolean newer(V candidate,V previous,Comparator<V> versions) {
        try{return versions.compare(candidate,previous)>0;}
        catch(RuntimeException rejected){return false;}
    }
    private boolean current(AuthenticatedPeer peer){return peer.generation()==AuthenticatedPeer.UNBOUND||peer.generation()==generation;}
    private void enter() {
        if(processing)throw new IllegalStateException("DHTの処理を重ねて呼べません");processing=true;
    }
    private long checkTime() {
        long now=ticker.getAsLong();
        if(now<lastTick){cancel(Stop.CLOCK_RESET);routing.clearPending();refreshBase=now;}
        lastTick=now;return now;
    }
    private void cancel(Stop stop) {for(Lookup lookup:lookups)lookup.finish(stop);lookups.clear();pings.clear();}
    private void prune(){lookups.removeIf(Lookup::done);}
    /** 配送側に聞く。例外・null は使えない相手として扱い、文は記録しない。 */
    private DhtTransport.Readiness prepare(Contact destination) {
        try {
            DhtTransport.Readiness readiness=transport.prepare(destination);
            return readiness==null?DhtTransport.Readiness.UNAVAILABLE:readiness;
        } catch(RuntimeException unavailable){return DhtTransport.Readiness.UNAVAILABLE;}
    }
    private long nextId() {
        if(sequence==Long.MAX_VALUE)throw new IllegalStateException("DHTの要求の番号が上限に達しています");return ++sequence;
    }
    private static long rpcLifetime(){return DhtLimits.RPC_NANOS*(DhtLimits.RPC_RETRIES+1L);}
    private static long elapsed(long now,long then){long value=now-then;return value<0?Long.MAX_VALUE:value;}
    @Override public String toString(){return "DHT node";}
}
