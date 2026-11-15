// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.LongSupplier;

/**
 * 同じグループの認証済みの相手が出す DHT 要求（PING・FIND_NODE・FIND_VALUE・STORE）に答える側。
 * 線の形（符号化）は核 C2 のアダプターが扱い、ここは符号化のない核の中の型だけで答える。
 * <p>
 * 検査の順は「世代 → 大きさと構文 → 速度の上限 → 署名の計算」。速度の上限を超えた要求は返事を作らず、
 * 署名も計算しない。袋は相手ごとに 1 つ（4 種類の要求で共有）と全体に 1 つ。同じスレッドで使う。
 * 相手が付けた要求の番号は、自分が出した要求の境目（networkFloor）の比べに通さず、そのまま返事に写す。
 * 番地・端末の番号・鍵は文にもログにも出さない。
 */
public final class DhtResponder {
    public static final int PEER_PER_SECOND=10,PEER_BURST=20,TOTAL_PER_SECOND=100,TOTAL_BURST=200;
    /** 覚えておく相手ごとの袋の上限。認証済みのセッションの数より十分に多く、古い相手から捨てる。 */
    public static final int MAX_PEER_BUCKETS=256;
    private static final long TOKEN=1_000_000_000L;
    public enum Command { PING,FIND_NODE,FIND_VALUE,STORE }
    public enum Kind { PONG,NODES,VALUE,STORE_RESULT }
    /** 相手の要求。id は相手が付けた番号で、返事にそのまま写す。 */
    public static final class Request {
        private final long id;
        private final Command command;
        private final DhtId target;
        private final byte[] record;
        private Request(long id,Command command,DhtId target,byte[] record) {
            this.id=id;this.command=command;this.target=target;this.record=record==null?null:record.clone();
        }
        public static Request ping(long id){return new Request(id,Command.PING,null,null);}
        public static Request findNode(long id,DhtId target){return new Request(id,Command.FIND_NODE,Objects.requireNonNull(target),null);}
        public static Request findValue(long id,DhtId key){return new Request(id,Command.FIND_VALUE,Objects.requireNonNull(key),null);}
        /** record が null でも作れる。構文の検査で INVALID になる。 */
        public static Request store(long id,byte[] record){return new Request(id,Command.STORE,null,record);}
        public long id(){return id;}
        public Command command(){return command;}
        @Override public String toString(){return "DHT peer request";}
    }
    /** 返事。STORE の結果は列挙だけで、自由な文字列は持たない。 */
    public static final class Response {
        private final Kind kind;
        private final long id;
        private final List<Contact> contacts;
        private final byte[] record;
        private final DiscoveryStatus status;
        private Response(Kind kind,long id,List<Contact> contacts,byte[] record,DiscoveryStatus status) {
            this.kind=kind;this.id=id;this.contacts=contacts;this.record=record;this.status=status;
        }
        public Kind kind(){return kind;}
        public long id(){return id;}
        public List<Contact> contacts(){return contacts;}
        public byte[] record(){return record==null?null:record.clone();}
        public DiscoveryStatus status(){return status;}
        @Override public String toString(){return "DHT response";}
    }
    /** 袋はトークンを 10 億分の 1 の単位で持つ。時間（ナノ秒）×毎秒の数がそのまま増える量になる。 */
    private static final class Bucket {
        final long rate,capacity;
        long level,last;
        Bucket(long perSecond,long burst,long now){rate=perSecond;capacity=burst*TOKEN;level=capacity;last=now;}
        void refill(long now) {
            // 時計が戻ったときは増やさず、基準だけ置き直す。
            if(now<last){last=now;return;}
            long elapsed=now-last;last=now;
            long fill=capacity/rate+1;
            if(elapsed>fill)elapsed=fill;
            level=Math.min(capacity,level+elapsed*rate);
        }
        boolean hasToken(){return level>=TOKEN;}
        void take(){level-=TOKEN;}
    }
    private final DhtNode<?> node;
    private final DiscoveryStore store;
    private final LongSupplier ticker;
    private final Bucket total;
    private final Map<DhtId,Bucket> peers=new LinkedHashMap<>(16,0.75f,true);
    private long rateLimited,staleDropped;
    public DhtResponder(DhtNode<?> node,DiscoveryStore store,LongSupplier ticker) {
        this.node=Objects.requireNonNull(node);this.store=Objects.requireNonNull(store);this.ticker=Objects.requireNonNull(ticker);
        total=new Bucket(TOTAL_PER_SECOND,TOTAL_BURST,ticker.getAsLong());
    }
    /**
     * 空なら返事を作らない（古い世代、または速度の上限の超過）。
     * 構文が違う STORE は、速度の袋を使わずに INVALID で返す。
     * 理由: 構文の検査は大きさと形を見るだけで、署名の計算をしない（CPU を使わない）。
     * 相手は同じグループの認証済みの端末だけで、返事も固定の列挙 1 つだけなので、
     * 袋を通さなくても資源を使い尽くされない。袋は署名の計算に入る前の入口にだけ置く。
     */
    public Optional<Response> answer(AuthenticatedPeer source,Request request) {
        Objects.requireNonNull(source);Objects.requireNonNull(request);
        if(source.generation()!=AuthenticatedPeer.UNBOUND&&source.generation()!=node.generation()){staleDropped=increment(staleDropped);return Optional.empty();}
        if(request.command==Command.STORE&&!wellFormed(request.record)) {
            store.counts().rejected(DiscoveryStatus.INVALID);
            return Optional.of(new Response(Kind.STORE_RESULT,request.id,List.of(),null,DiscoveryStatus.INVALID));
        }
        if(!admit(source.id())){rateLimited=increment(rateLimited);return Optional.empty();}
        node.observe(source);
        switch(request.command) {
            case PING: return Optional.of(new Response(Kind.PONG,request.id,List.of(),null,null));
            case FIND_NODE: return Optional.of(nodes(source,request));
            case FIND_VALUE: {
                Optional<DiscoveryRecord> found=store.get(request.target);
                return found.isPresent()
                    ?Optional.of(new Response(Kind.VALUE,request.id,List.of(),found.get().encode(),null))
                    :Optional.of(nodes(source,request));
            }
            default: return Optional.of(new Response(Kind.STORE_RESULT,request.id,List.of(),null,store.put(source,request.record)));
        }
    }
    /**
     * 返事の中身を作る前に、世代と速度の袋だけを通す入口（パッケージの中だけ）。
     * 経路表には入れない。通らなければ false を返し、速度の上限なら数えるだけで返事は作らない。
     */
    boolean admitBeforeAnswering(AuthenticatedPeer source) {
        Objects.requireNonNull(source);
        if(source.generation()!=AuthenticatedPeer.UNBOUND&&source.generation()!=node.generation()){staleDropped=increment(staleDropped);return false;}
        if(!admit(source.id())){rateLimited=increment(rateLimited);return false;}
        return true;
    }
    private static boolean wellFormed(byte[] wire) {
        if(wire==null||wire.length>DiscoveryRecord.MAX_BYTES)return false;
        try{DiscoveryRecord.parse(wire);return true;}catch(RuntimeException malformed){return false;}
    }
    private Response nodes(AuthenticatedPeer asker,Request request) {
        List<Contact> contacts=new ArrayList<>();
        for(AuthenticatedPeer peer:node.routing().nearest(request.target,DhtLimits.K+1)) {
            if(!peer.id().equals(asker.id())&&contacts.size()<DhtLimits.K)contacts.add(peer.contact());
        }
        return new Response(Kind.NODES,request.id,List.copyOf(contacts),null,null);
    }
    /** 相手の袋と全体の袋の両方にトークンがあるときだけ、両方から 1 つずつ使う。捨てた要求は全体の袋を減らさない。 */
    private boolean admit(DhtId peer) {
        long now=ticker.getAsLong();
        Bucket mine=peers.get(peer);
        if(mine==null){mine=new Bucket(PEER_PER_SECOND,PEER_BURST,now);peers.put(peer,mine);trim();}
        mine.refill(now);total.refill(now);
        if(!mine.hasToken()||!total.hasToken())return false;
        mine.take();total.take();return true;
    }
    private void trim() {
        var iterator=peers.entrySet().iterator();
        while(peers.size()>MAX_PEER_BUCKETS&&iterator.hasNext()){iterator.next();iterator.remove();}
    }
    /** 相手を消すときに、その相手の袋も一緒に消す。知らない相手なら何もしない。全体の袋は変えない。 */
    public void forget(DhtId peer){peers.remove(Objects.requireNonNull(peer));}
    private static long increment(long value){return value==Long.MAX_VALUE?value:value+1;}
    /** 速度の上限で返事を作らなかった要求の数。画面の「拒否」には数えない。 */
    public long rateLimited(){return rateLimited;}
    /** 古い世代のセッションから来て捨てた要求の数。 */
    public long staleDropped(){return staleDropped;}
    int peerBuckets(){return peers.size();}
    @Override public String toString(){return "DHT responder";}
}
