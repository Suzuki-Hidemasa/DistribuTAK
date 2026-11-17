// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import java.util.function.Supplier;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SessionManager;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementEnvelopeFields;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpoint;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.AuthenticatedPeer;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.Contact;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtCandidates;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcher;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtId;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtKeys;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtLink;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtNode;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtPublisher;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtResponder;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtTransport;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtWire;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryRecord;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryStore;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.LocalNetwork;

/**
 * 1 つの端点（1 つのポート）につき 1 つ作る、DHT の保持役（答え 196）。
 * <p>
 * 使うのは {@link LanController} の作業の列（1 本のスレッド）だけ。核はスレッドを作らないので、{@link #step} を 1 秒おきに呼んで進める。
 * 送る先は今の Wi-Fi の IPv4 LAN にいる同じグループの相手だけ。HaLow など外のネットワークにはつながない（legal Q107 (1)）。
 * 同じグループの発見記録と管理記録をメモリだけに預かる（答え 181 (6)・04 §4.5）。
 * 管理記録は共有の保存調整層がある通常接続にだけ接続する。新しい暗号の方式は足さない。
 * <p>
 * Destinations are peers of the same group on the current IPv4 Wi-Fi LAN, excluding HaLow and other networks (legal Q107 (1)).
 * Discovery and management copies of the same group are held only in memory (answer 181 (6); 04 §4.5).
 * Management records connect only on normal connections with a shared persistence coordinator. No new cryptographic scheme is added.
 * <p>
 * 外へ出す文字は、固定の文・件数だけ。番地・機器の番号・記録の鍵・uid・例外の文は出さない（答え 196 (5)(7)）。
 * 例外が出たらこの保持役だけ止める（通信全体は止めない）。止めたあとは何も送らず、何も受けない。
 */
final class LanDht implements DhtLink {
    static final long SECOND=1_000_000_000L;
    static final long HOUR=3_600L*SECOND;
    static final long PRESS_FLOOR=60L*SECOND;
    static final long RESERVE_RETRY=60L*SECOND;
    /** 周期・開始のばらつきの上限（5 分）。 */
    static final int JITTER_MILLIS=5*60*1000;
    static final int MAX_SEEN=256;
    static final int MAX_KNOWN=256;
    static final int MAX_HANDSHAKES=64;
    static final long[] TRY_OFFSET={0,10L*SECOND,20L*SECOND};
    static final String FOUND="DHT: 相手から自分の記録を受け取れました";
    static final String NOT_FOUND="DHT: 見つかりませんでした";
    static final String NO_PEER="DHT: DHT の相手がいません";
    static final String WAIT="DHT: しばらく待ってから押してください";

    /** 端点・セッションとの境目。試験では偽物に置き換える。 */
    interface Wire {
        /** 今のセッション番号。なければ null。 */
        byte[] sessionId(byte[] peer);

        /** その相手・そのセッションが今も確立しているときだけ、認証済みの相手を返す。 */
        AuthenticatedPeer authenticated(byte[] peer,byte[] session);

        boolean send(byte[] peer,byte[] session,byte[] plain);

        boolean release(byte[] peer);

        /** 見つけた相手へ握手を始める。通らなければ IllegalStateException か SecurityException。 */
        void start(byte[] node,byte[] handshakeKey,InetSocketAddress address);

        /** 世代を 1 つ進めて、その値を返す（セッションの管理側の世代。揮発の相手は忘れる）。 */
        long nextGeneration();
    }

    /** 記録の版の予約（保存つき）。失敗や上限は例外。 */
    interface Reserve {
        long reserve() throws Exception;
    }

    /** 版と時刻から、署名つきの記録を作る。秘密鍵はここの外に出さない。 */
    interface Issuer {
        DiscoveryRecord issue(long version,long signedAtMillis);
    }

    /** 作るときに渡すもの。 */
    static final class Config {
        byte[] groupId;
        DhtId self;
        byte[] ipv4;
        int prefix;
        Wire wire;
        LongSupplier nanos;
        Clock wall;
        Random jitter=new Random();
        Reserve reserve;
        Issuer issuer;
        BooleanSupplier rejoining=()->false;
        BooleanSupplier pinWaiting=()->false;
        Predicate<DhtId> revoked=id->false;
        Supplier<byte[]> storedPeer=()->null;
        Function<DhtId,DhtWire.NodeContact> storedContact=id->null;
        Consumer<String> log=s->{};
        ManagedDhtExchange management;
    }

    private static final class Handshake {
        final DhtCandidates.Attempt attempt;
        final long[] at=new long[3];
        int next;

        Handshake(DhtCandidates.Attempt attempt,long now) {
            this.attempt=attempt;
            for(int i=0;i<at.length;i++) {
                at[i]=now+TRY_OFFSET[i];
            }
        }
    }

    private final Config cfg;
    private final Wire wire;
    private final LongSupplier nanos;
    private final Clock wall;
    private final Random rnd;
    private final DhtId self;
    private final LocalNetwork network;
    private final DhtNode<DiscoveryRecord> node;
    private final DiscoveryStore store;
    private final DhtDispatcher dispatcher;
    private final DhtPublisher publisher;
    private final Map<DhtId,Handshake> handshakes=new LinkedHashMap<>();
    private final Map<DhtId,DhtWire.NodeContact> known=new LinkedHashMap<>();
    private final Map<DhtId,byte[]> seen=new LinkedHashMap<>();
    private final Map<DhtId,Boolean> volatileMine=new LinkedHashMap<>();
    private volatile boolean closed;
    private volatile boolean disabled;
    private boolean lookupDone;
    private boolean pressValid;
    private long lastNow;
    private long publishAt;
    private long lookupAt;
    private long lastPress;
    private long reserveFailures;
    private long pressFound;
    private long pressNotFound;
    private int pressId;
    private String result;

    LanDht(Config cfg) {
        this.cfg=cfg;
        this.wire=cfg.wire;
        this.nanos=cfg.nanos;
        this.wall=cfg.wall;
        this.rnd=cfg.jitter;
        this.self=cfg.self;
        this.network=new LocalNetwork(cfg.ipv4,cfg.prefix);
        DhtTransport transport=new DhtTransport() {
            @Override public boolean send(Contact destination,Request request) {
                return dispatcher.send(destination,request);
            }
            @Override public Readiness prepare(Contact destination) {
                return prepareHook(destination);
            }
            @Override public void firstBusy(Contact destination) {
                dispatcher.firstBusy(destination);
            }
        };
        node=new DhtNode<>(self,wall,nanos,transport,(key,bytes,clock)->{
            throw new SecurityException("unused");
        },(x,y)->Long.compare(x.version(),y.version()));
        store=cfg.management==null?new DiscoveryStore(cfg.groupId,wall,nanos,cfg.revoked):
                DiscoveryStore.shared(cfg.groupId,wall,nanos,cfg.revoked,cfg.management.budget());
        DhtResponder responder=new DhtResponder(node,store,nanos);
        dispatcher=cfg.management==null?new DhtDispatcher(cfg.groupId,node,responder,store,this,this::directory,(peer,kind,data)->{},nanos):
                new DhtDispatcher(cfg.groupId,node,responder,store,this,this::directory,(peer,kind,data)->{},nanos,cfg.management.resources());
        if(cfg.management!=null)dispatcher.configureManaged(cfg.management.store());
        publisher=new DhtPublisher(node,dispatcher,store);
        dispatcher.networkChanged(wire.nextGeneration(),network);
        long now=nanos.getAsLong();
        lastNow=now;
        publishAt=now+jitter();
        lookupAt=now+jitter();
    }

    // ---- 画面・状態の読み口 ----
    boolean active() {
        return !closed&&!disabled;
    }

    int routingSize() {
        return active()?node.routing().size():0;
    }

    int storedRecords() {
        return active()?store.size():0;
    }

    int refusedRecords() {
        return active()?(int)Math.min(Integer.MAX_VALUE,store.counts().screenRejected()):0;
    }

    /** ボタンの結果の固定文。まだ押していない・待っているときは null。 */
    String result() {
        return result;
    }

    long reserveFailures() {
        return reserveFailures;
    }

    long foundCount() {
        return pressFound;
    }

    long notFoundCount() {
        return pressNotFound;
    }

    /**
     * 管理記録を現在のDHT相手へ公開する。周期探索は後続の段階で接続する。
     * <p>
     * Publishes a management record to a current DHT peer; periodic discovery connects in a later stage.
     */
    boolean publishManaged(Contact destination,byte[] encoded,Consumer<DhtWire.StoreStatus> done){
        return active()&&cfg.management!=null&&cfg.management.allowed()&&dispatcher.storeManaged(destination,encoded,done);
    }
    /**
     * 既存の全体送信枠が満杯か調べる。上限は変えない。
     * <p>
     * Checks whether the existing global send slots are full without changing their limit.
     */
    boolean managementSendFull(){return dispatcher.pendingCount()>=DhtDispatcher.MAX_PENDING;}
    /**
     * 保存済み候補の現在の資格を確かめながら管理記録を公開する。
     * <p>
     * Publishes a management record while checking the current eligibility of its saved candidate.
     */
    boolean publishManaged(Contact destination,byte[] record,Consumer<DhtWire.StoreStatus> done,BooleanSupplier current){
        return active()&&cfg.management!=null&&cfg.management.allowed()&&dispatcher.storeManaged(destination,record,done,current);
    }
    boolean findManaged(Contact destination,DhtId target,Consumer<io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecord> done,BooleanSupplier current){
        return active()&&cfg.management!=null&&cfg.management.allowed()&&dispatcher.findManagedFrom(destination,target,done,current);
    }
    boolean findManaged(Contact destination,DhtId target,Consumer<io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecord> done){
        return active()&&cfg.management!=null&&cfg.management.allowed()&&dispatcher.findManagedFrom(destination,target,done);
    }
    DhtDispatcher dispatcherForTest() {
        return dispatcher;
    }

    DhtNode<DiscoveryRecord> nodeForTest() {
        return node;
    }

    DiscoveryStore storeForTest() {
        return store;
    }

    DhtPublisher publisherForTest() {
        return publisher;
    }

    /** 受信用: 返事を受ける番地が同じサブネットの IPv4 のときだけ許す。受信スレッドから呼ばれるので止まらない・書き換えない。 */
    boolean allowsReply(InetSocketAddress address) {
        if(closed||disabled) {
            return false;
        }
        try {
            InetAddress a=address==null?null:address.getAddress();
            return a!=null&&a.getAddress().length==4&&network.allows(a.getAddress(),address.getPort());
        } catch(RuntimeException ignored) {
            return false;
        }
    }

    // ---- 止める ----
    /** 端点を閉じた直後に呼ぶ。メモリの中の相手・記録・待ちを捨てる。保存したものは消さない（消すのは呼び出し側が最後に）。 */
    void close() {
        if(closed) {
            return;
        }
        closed=true;
        clearMemory();
        result=null;
        discardCoreMemory();
        log("DHT_CLOSED");
    }

    /** 核の DHT のメモリ（待ち・預かり）を捨てる。預かりは期限前のものも全部消す。止めるとき（close・fault）に使う。 */
    private void discardCoreMemory() {
        try {
            dispatcher.networkChanged(Long.MAX_VALUE,network);
        } catch(RuntimeException|LinkageError ignored) {
            log("DHT_CLOSE_PARTIAL");
        }
        try {
            store.clear();
        } catch(RuntimeException|LinkageError ignored) {
            log("DHT_CLOSE_PARTIAL");
        }
        if(cfg.management!=null)try{cfg.management.close();}
        catch(RuntimeException|LinkageError ignored){log("DHT_CLOSE_PARTIAL");}
    }

    private void clearMemory() {
        handshakes.clear();
        known.clear();
        seen.clear();
        volatileMine.clear();
    }

    private void fault() {
        if(disabled||closed) {
            return;
        }
        disabled=true;
        result=null;
        // 端点は生きているので、数えていた揮発の相手を放す（枠を DHT のために占めたままにしない）
        for(DhtId id:new ArrayList<>(volatileMine.keySet())) {
            try {
                wire.release(id.bytes());
            } catch(RuntimeException|LinkageError ignored) {
                log("DHT_CLOSE_PARTIAL");
            }
        }
        clearMemory();
        discardCoreMemory();
        log("DHT_FAILED");
    }

    private void log(String fixed) {
        try {
            cfg.log.accept(fixed);
        } catch(RuntimeException ignored) {
            // 記録できなくても動きは変えない
        }
    }

    // ---- 時間 ----
    private long wallMillis() {
        try {
            return wall.millis();
        } catch(RuntimeException ignored) {
            return -1;
        }
    }

    private long jitter() {
        return rnd.nextInt(JITTER_MILLIS+1)*1_000_000L;
    }

    private static boolean reached(long now,long at) {
        return now-at>=0;
    }

    // ---- 1 秒おきに進める ----
    void step() {
        if(closed||disabled) {
            return;
        }
        try {
            stepLocked();
        } catch(RuntimeException|LinkageError e) {
            fault();
        }
    }

    private void stepLocked() {
        long now=nanos.getAsLong();
        if(now-lastNow<0) {
            clockWentBack(now);
        }
        lastNow=now;
        if(wallMillis()<0) {
            return;
        }
        node.poll();
        dispatcher.poll();
        if(cfg.management!=null)cfg.management.poll(this);
        publisher.poll(now);
        seedStoredPeer();
        runHandshakes(now);
        if(cfg.rejoining.getAsBoolean()) {
            return;
        }
        if(!lookupDone) {
            if(reached(now,lookupAt)&&node.canStartLookup()&&node.routing().size()>0) {
                node.findNode(self);
                lookupDone=true;
            }
        } else if(node.canStartLookup()&&node.refreshDue()) {
            node.findNode(self);
        }
        publishIfDue(now);
    }

    /** 単調時計が戻った。途中の探しものと待ちを捨て、周期の起点を取り直す。保存したものは消さない。 */
    private void clockWentBack(long now) {
        long generation=wire.nextGeneration();
        dispatcher.networkChanged(generation,network);
        publisher.networkChanged();
        clearMemory();
        publishAt=now+jitter();
        lookupAt=now+jitter();
        lookupDone=false;
        pressValid=false;
        pressId++;
    }

    /** 引き継いだ相手（保存してある相手）が確立していて、まだ表にいなければ入れる。 */
    private void seedStoredPeer() {
        byte[] stored=cfg.storedPeer.get();
        if(stored==null||stored.length!=32) {
            return;
        }
        DhtId id=new DhtId(stored);
        byte[] session=wire.sessionId(stored);
        if(session==null) {
            return;
        }
        // 確立済みの保存相手にも、核へセッションの開始を知らせる（同じセッションなら何も起きない）。
        // 知らせないと DHT を話せるかの探りが始まらず、「YES」にならない。
        sessionSeen(id,session);
        volatileMine.remove(id);
        if(node.routing().contains(id)) {
            return;
        }
        AuthenticatedPeer peer=wire.authenticated(stored,session);
        if(peer!=null) {
            node.observe(peer);
        }
    }

    private void publishIfDue(long now) {
        if(!reached(now,publishAt)||!publisher.publishDue(now)||!node.canStartLookup()) {
            return;
        }
        long version;
        try {
            version=cfg.reserve.reserve();
        } catch(Exception|LinkageError e) {
            reserveFailures++;
            publishAt=now+RESERVE_RETRY;
            log("DHT_VERSION_RESERVE_FAILED");
            return;
        }
        byte[] signed=cfg.issuer.issue(version,wallMillis()).encode();
        if(publisher.publish(signed,now)) {
            publishAt=now+HOUR+jitter();
        } else {
            publishAt=now+RESERVE_RETRY;
        }
    }

    // ---- 握手（見つけた相手へ） ----
    private DhtTransport.Readiness prepareHook(Contact destination) {
        DhtId peer=destination.id();
        Optional<DhtCandidates.Attempt> before=node.candidates().attemptFor(peer);
        DhtTransport.Readiness ready=dispatcher.prepare(destination);
        if(ready==DhtTransport.Readiness.CONNECTING) {
            Optional<DhtCandidates.Attempt> after=node.candidates().attemptFor(peer);
            boolean fresh=after.isPresent()&&(before.isEmpty()||before.get()!=after.get());
            if(fresh&&handshakes.size()<MAX_HANDSHAKES) {
                DhtCandidates.Candidate c=after.get().candidate();
                remember(peer,new DhtWire.NodeContact(c.node(),c.handshakeKey(),c.ipv4(),c.port()));
                handshakes.put(peer,new Handshake(after.get(),nanos.getAsLong()));
            }
        }
        return ready;
    }

    private void remember(DhtId id,DhtWire.NodeContact contact) {
        known.remove(id);
        known.put(id,contact);
        while(known.size()>MAX_KNOWN) {
            Iterator<DhtId> oldest=known.keySet().iterator();
            oldest.next();
            oldest.remove();
        }
    }

    private void runHandshakes(long now) {
        List<DhtId> done=new ArrayList<>();
        for(Map.Entry<DhtId,Handshake> entry:new ArrayList<>(handshakes.entrySet())) {
            DhtId peer=entry.getKey();
            Handshake h=entry.getValue();
            Optional<DhtCandidates.Attempt> cur=node.candidates().attemptFor(peer);
            if(cur.isEmpty()||cur.get()!=h.attempt) {
                if(wire.sessionId(peer.bytes())==null) {
                    // セッションができないまま握手が終わった。核は知らせないので、ここで数から外す
                    volatileMine.remove(peer);
                }
                done.add(peer);
                continue;
            }
            byte[] session=wire.sessionId(peer.bytes());
            if(session!=null) {
                sessionSeen(peer,session);
                done.add(peer);
                continue;
            }
            if(h.next>=h.at.length||!reached(now,h.at[h.next])||!node.candidates().firstDue(h.attempt)) {
                continue;
            }
            h.next++;
            node.candidates().firstSent(h.attempt);
            DhtCandidates.Candidate c=h.attempt.candidate();
            try {
                wire.start(c.node().bytes(),c.handshakeKey(),new InetSocketAddress(InetAddress.getByAddress(c.ipv4()),c.port()));
                if(volatileMine.size()<LanGroup.MAX_PEERS) {
                    volatileMine.put(peer,Boolean.TRUE);
                }
            } catch(SecurityException refused) {
                node.candidates().finish(h.attempt,false);
                done.add(peer);
            } catch(Exception ownSide) {
                node.candidates().release(h.attempt);
                done.add(peer);
            }
        }
        for(DhtId id:done) {
            handshakes.remove(id);
        }
    }

    private void sessionSeen(DhtId peer,byte[] session) {
        byte[] previous=seen.get(peer);
        if(previous!=null&&Arrays.equals(previous,session)) {
            return;
        }
        seen.remove(peer);
        seen.put(peer,session.clone());
        while(seen.size()>MAX_SEEN) {
            Iterator<DhtId> oldest=seen.keySet().iterator();
            oldest.next();
            oldest.remove();
        }
        dispatcher.sessionStarted(peer.bytes(),session);
    }

    // ---- 受信・相手が消えた ----
    /**
     * DHT の線なら処理して true。それ以外・止まっているときは false（呼び出し側が拒否と数える）。
     * 壁時計が読めない（負）間は、DHT の線でも何も書き換えずに捨てて true を返す（拒否ではないので数えない）。
     */
    boolean receive(byte[] peer,byte[] session,byte[] plain) {
        if(closed||disabled) {
            return false;
        }
        try {
            if(!DhtWire.isDht(plain)) {
                return false;
            }
            if(wallMillis()<0) {
                return true;
            }
            DhtId id=new DhtId(peer);
            byte[] stored=cfg.storedPeer.get();
            boolean paired=stored!=null&&Arrays.equals(stored,peer);
            if(paired) {
                volatileMine.remove(id);
            } else if(!volatileMine.containsKey(id)&&volatileMine.size()<LanGroup.MAX_PEERS) {
                volatileMine.put(id,Boolean.TRUE);
            }
            if(cfg.management!=null) {
                DhtWire.Message message;
                try {message=DhtWire.parse(plain);}
                catch(RuntimeException malformed) {
                    // 壊れた1通は既存の解析側に数えさせ、DHT全体は止めない。
                    // Let the existing parser count one malformed message without stopping all DHT traffic.
                    return dispatcher.receive(peer,session,plain);
                }
                if(message.managed()&&!cfg.management.allowed())return true;
            }
            sessionSeen(id,session);
            return dispatcher.receive(peer,session,plain);
        } catch(RuntimeException|LinkageError e) {
            fault();
            return false;
        }
    }

    /** 揮発の相手が消えた知らせ（作業の列で呼ぶ）。その相手の「速さの袋」も外す。 */
    void peerForgotten(byte[] peer) {
        if(closed||disabled) {
            return;
        }
        try {
            DhtId id=new DhtId(peer);
            volatileMine.remove(id);
            seen.remove(id);
            handshakes.remove(id);
            dispatcher.volatilePeerForgotten(peer);
        } catch(RuntimeException|LinkageError e) {
            fault();
        }
    }

    /** 揮発の相手として数えている台数（試験用）。 */
    int volatileCount() {
        return volatileMine.size();
    }

    // ---- DhtLink ----
    @Override public AuthenticatedPeer authenticated(byte[] peerId,byte[] sessionId) {
        return wire.authenticated(peerId,sessionId);
    }

    @Override public boolean send(byte[] peerId,byte[] sessionId,byte[] plaintext) {
        return wire.send(peerId,sessionId,plaintext);
    }

    @Override public boolean releaseVolatile(byte[] peerId) {
        boolean released=wire.release(peerId);
        if(released) {
            volatileMine.remove(new DhtId(peerId));
        }
        return released;
    }

    @Override public boolean volatileSlotFree() {
        return volatileMine.size()<LanGroup.MAX_PEERS-1;
    }

    @Override public boolean startAllowed() {
        return !cfg.pinWaiting.getAsBoolean();
    }

    /** 相手の番地・握手の鍵: 自分で始めた候補 → 検証済みの発見の記録 → 保存してある相手、の順。 */
    private DhtWire.NodeContact directory(DhtId id) {
        DhtWire.NodeContact c=known.get(id);
        if(c!=null) {
            return c;
        }
        try {
            Optional<DiscoveryRecord> record=store.get(DhtKeys.derive(cfg.groupId,DhtKeys.MEMBER_DISCOVERY,id.bytes()));
            if(record.isPresent()&&record.get().nodeId().equals(id)) {
                DiscoveryRecord r=record.get();
                return new DhtWire.NodeContact(id,r.handshakeKey(),r.ipv4(),r.port());
            }
        } catch(IllegalStateException ignored) {
            // 表の途中で呼ばれたときは次の元へ
            return cfg.storedContact.apply(id);
        }
        return cfg.storedContact.apply(id);
    }

    // ---- 「DHTを探し直す」ボタン ----
    /**
     * 押した。直接つながっている DHT の相手 1 台へ、自分の記録を STORE し、ACK のあとに同じ相手へ自分の記録の FIND_VALUE を出す。
     * 手元のコピーは使わない。数えるのは、署名・鍵・版・要求との対応を確かめた返事だけ（答え 196 (4)・197）。
     * 結果は {@link #result()} の固定文。すぐ決まるものは返り値にも返す。待つときは null。
     */
    String press() {
        if(closed||disabled) {
            result=NO_PEER;
            return result;
        }
        try {
            return pressLocked();
        } catch(RuntimeException|LinkageError e) {
            fault();
            return null;
        }
    }

    private String pressLocked() {
        long now=nanos.getAsLong();
        if(pressValid&&now-lastPress<0) {
            pressValid=false;
        }
        if(pressValid&&now-lastPress<PRESS_FLOOR) {
            return shown(WAIT);
        }
        if(cfg.rejoining.getAsBoolean()||wallMillis()<0) {
            return shown(WAIT);
        }
        Contact target=pickPeer();
        if(target==null) {
            return shown(NO_PEER);
        }
        pressValid=true;
        lastPress=now;
        pressId++;
        int id=pressId;
        result=null;
        long version;
        try {
            version=cfg.reserve.reserve();
        } catch(Exception|LinkageError e) {
            reserveFailures++;
            log("DHT_VERSION_RESERVE_FAILED");
            return notFound();
        }
        DiscoveryRecord mine=cfg.issuer.issue(version,wallMillis());
        byte[] signed=mine.encode();
        DhtId key=mine.key();
        long stored=mine.version();
        boolean sent=dispatcher.store(target,signed,ok->onStored(id,target,key,stored,ok));
        if(!sent) {
            return notFound();
        }
        return null;
    }

    private void onStored(int id,Contact target,DhtId key,long stored,Boolean ok) {
        if(id!=pressId||closed||disabled) {
            return;
        }
        try {
            if(ok==null||!ok) {
                finish(id,false);
                return;
            }
            boolean asked=dispatcher.findValueFrom(target,key,found->{
                if(id!=pressId||closed||disabled) {
                    return;
                }
                boolean verified=found!=null&&found.nodeId().equals(self)&&found.key().equals(key)&&found.version()==stored;
                finish(id,verified);
            });
            if(!asked) {
                finish(id,false);
            }
        } catch(RuntimeException|LinkageError e) {
            fault();
        }
    }

    private void finish(int id,boolean found) {
        if(id!=pressId) {
            return;
        }
        pressId++;
        if(found) {
            pressFound++;
            result=FOUND;
        } else {
            pressNotFound++;
            result=NOT_FOUND;
        }
    }

    private String notFound() {
        pressNotFound++;
        result=NOT_FOUND;
        return result;
    }

    private String shown(String sentence) {
        result=sentence;
        return sentence;
    }

    private Contact pickPeer() {
        for(AuthenticatedPeer peer:node.routing().nearest(self,256)) {
            DhtId id=peer.id();
            if(!dispatcher.peers().isYes(id)) {
                continue;
            }
            byte[] session=wire.sessionId(id.bytes());
            if(session!=null&&wire.authenticated(id.bytes(),session)!=null) {
                return peer.contact();
            }
        }
        return null;
    }
    boolean receiveAnnouncement(byte[] peer,byte[] session,byte[] wire,long receivedAt,RevocationRecovery transport){
        if(ManagementEnvelopeFields.field(wire)!=ManagementEnvelopeFields.SIGNED_ANNOUNCEMENT)return false;
        if(cfg.management!=null){var ack=cfg.management.receiveAnnouncement(peer,session,wire,receivedAt);
            if(ack!=null&&transport!=null)transport.announcementAck(peer,session,ack);}
        return true;
    }
    List<Contact> managementPeers(){
        var result=new ArrayList<Contact>();
        for(var peer:node.routing().nearest(self,256)){
            byte[] session=wire.sessionId(peer.id().bytes());
            if(dispatcher.peers().isYes(peer.id())&&session!=null&&wire.authenticated(peer.id().bytes(),session)!=null)result.add(peer.contact());
        }
        return result;
    }

    /** 端点と管理側のセッションを包む本物の口。 */
    static final class EndpointWire implements Wire {
        private final UdpEndpoint endpoint;
        private final SessionManager sessions;

        EndpointWire(UdpEndpoint endpoint,SessionManager sessions) {
            this.endpoint=endpoint;
            this.sessions=sessions;
        }

        @Override public byte[] sessionId(byte[] peer) {
            return endpoint.sessionId(peer);
        }

        @Override public AuthenticatedPeer authenticated(byte[] peer,byte[] session) {
            SessionManager.VerifiedSession verified=sessions.verifiedSession(peer);
            if(verified==null||!Arrays.equals(verified.sessionId(),session)) {
                return null;
            }
            return AuthenticatedPeer.fromVerifiedSession(verified);
        }

        @Override public boolean send(byte[] peer,byte[] session,byte[] plain) {
            return endpoint.sendIfSession(peer,session,plain);
        }

        @Override public boolean release(byte[] peer) {
            return endpoint.forgetVolatilePeer(peer);
        }

        @Override public void start(byte[] node,byte[] handshakeKey,InetSocketAddress address) {
            endpoint.startDiscovered(node,handshakeKey,address);
        }

        @Override public long nextGeneration() {
            endpoint.networkChanged();
            return sessions.generation();
        }
    }
}
