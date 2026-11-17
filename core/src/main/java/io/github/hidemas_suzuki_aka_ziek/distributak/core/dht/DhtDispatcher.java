// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.UnaryOperator;

/**
 * DHTの線の形（DATAのSyncEnvelope項目9）と核（DhtNode・DhtResponder）の間の配送側（核C2）。
 * 認証済みの相手からのDHTの要求はDhtResponderへ振り分け、自分が出した要求への応答は
 * 「同じ相手・同じセッション・同じrequest_id・対応する種類・同じ対象・同じ世代・期限内・1回だけ」のときだけ核へ渡す。
 * DHTを話せると確かめた相手（DhtPeers）にだけ要求を送る。旧版（r19）の相手へ送り続けて相手の「拒否」の数を
 * 増やさないため、探りの通数はDhtPeersが絞る。
 * 呼ぶスレッドはDhtNodeと同じ1本。番地・端末の番号・セッションの番号・鍵・記録の中身は、ログにも例外にも文字列にも出さない。
 */
public final class DhtDispatcher implements DhtTransport {
    public static final int MAX_PENDING=64;
    public static final int MAX_PENDING_PER_PEER=8;
    /** NODESの1ページに入れる連絡先の数。 */
    public static final int PAGE_CONTACTS=DhtWire.MAX_CONTACTS;
    private static final long SECOND=1_000_000_000L;
    private static final long PAGE_NANOS=SECOND;
    private static final long PROBE_NANOS=3*SECOND;

    private enum Kind { CORE,PROBE,STORE,DIRECT_VALUE,DIRECT_STORE,MANAGED_VALUE,MANAGED_STORE }

    private static final class Pending {
        final Kind kind;
        final DhtWire.Op op;
        final long coreId;
        final DhtId peer;
        final byte[] session;
        final DhtId target;
        final int page;
        final long generation;
        long deadline;
        boolean transferring;
        java.util.function.BooleanSupplier current=()->true;
        final List<DhtId> carry;
        /** 呼び出し側が結果を待つ口（直接の FIND_VALUE・STORE だけ）。1回だけ呼ぶ。 */
        Consumer<Object> done;
        Pending(Kind kind,DhtWire.Op op,long coreId,DhtId peer,byte[] session,DhtId target,int page,long generation,long deadline,List<DhtId> carry) {
            this.kind=kind;this.op=op;this.coreId=coreId;this.peer=peer;this.session=session.clone();this.target=target;
            this.page=page;this.generation=generation;this.deadline=deadline;this.carry=carry;
        }
    }

    /** 数だけの統計。番地・番号は持たない。画面の「拒否」の数には入れない。 */
    public static final class Statistics {
        private final long received,malformed,unauthenticated,wrongGroup,unsolicited,mismatched,expired,stale,probes;
        private final int yes,no;
        private long busy,nothingReleasable,droppedStarted,releasedNotYes,releasedOutside,releasedCrowded,releasedNo;
        private long busyConcurrent,busyWindow,busyNothingReleasable,busyRecent30s,lookupsQueryLimit,lookupsDeadline,unavailableFailed,connectingTimedOut,connectingReleased,rehandshakeAfterRelease,probeBudgetBlocked;
        private Statistics(long received,long malformed,long unauthenticated,long wrongGroup,long unsolicited,long mismatched,long expired,long stale,long probes,int yes,int no) {
            this.received=received;this.malformed=malformed;this.unauthenticated=unauthenticated;this.wrongGroup=wrongGroup;
            this.unsolicited=unsolicited;this.mismatched=mismatched;this.expired=expired;this.stale=stale;this.probes=probes;this.yes=yes;this.no=no;
        }
        /** 揮発の枠が詰まって握手を始められなかった回数（合計。相手ごとには持たない）。prepare を呼んだ回数で数える（同じ候補を何度尋ねても、そのたびに増える）。 */
        public long busy(){return busy;}
        /** 揮発の枠が満杯で手放せる相手がいなかった回数。busy と同じく prepare を呼んだ回数で数える。理由別の busy*（候補ごとに最初の BUSY だけ）とは数え方が違う。 */
        public long nothingReleasable(){return nothingReleasable;}
        public long droppedStarted(){return droppedStarted;}
        public long releasedNotYes(){return releasedNotYes;}
        public long releasedOutsideTable(){return releasedOutside;}
        public long releasedCrowdedBucket(){return releasedCrowded;}
        public long releasedNo(){return releasedNo;}
        /** 探索の候補が NEW から初めて BUSY になった件数（理由別。合計だけで、相手ごとには持たない）。同時 8 件が理由。 */
        public long busyConcurrent(){return busyConcurrent;}
        /** 同上。5 分に 64 件の開始の枠が理由（同時 8 件も満杯のときは busyConcurrent に数える）。 */
        public long busyWindow(){return busyWindow;}
        /** 同上。揮発の枠が満杯で、手放せる相手がいなかった。 */
        public long busyNothingReleasable(){return busyNothingReleasable;}
        /** 同上。最後に正しいやり取り（握手の完了・検査を通った返事・答えた要求）があってから 30 秒たっていない相手がいたため、手放せなかった（それ以外に手放せる相手はいない）。 */
        public long busyRecent30s(){return busyRecent30s;}
        /** 探索が QUERY_LIMIT で終わった数。 */
        public long lookupsQueryLimit(){return lookupsQueryLimit;}
        /** 探索が DEADLINE で終わった数。 */
        public long lookupsDeadline(){return lookupsDeadline;}
        /** 候補を UNAVAILABLE で FAILED にした数。 */
        public long unavailableFailed(){return unavailableFailed;}
        /** つなぎ中 90 秒で候補を FAILED にした数。 */
        public long connectingTimedOut(){return connectingTimedOut;}
        /**
         * 案 B で、探索が最初の値の印のときに手放したつなぎ中の候補の数（合計。件数だけ。答え 195）。
         * 配送の部品が揮発の相手を手放す数（releasedNotYes など）とは別で、混ぜない。握手そのものは閉じない。
         */
        public long connectingReleased(){return connectingReleased;}
        /** 手放した相手へ、また握手を始めた数。 */
        public long rehandshakeAfterRelease(){return rehandshakeAfterRelease;}
        /** 探りの枠が尽きて NO にした数（DhtPeers）。 */
        public long probeBudgetBlocked(){return probeBudgetBlocked;}
        public long received(){return received;}
        public long malformed(){return malformed;}
        public long unauthenticated(){return unauthenticated;}
        public long wrongGroup(){return wrongGroup;}
        public long unsolicited(){return unsolicited;}
        public long mismatched(){return mismatched;}
        public long expired(){return expired;}
        public long stale(){return stale;}
        public long probesSent(){return probes;}
        public int yesPeers(){return yes;}
        public int noPeers(){return no;}
        @Override public String toString(){return "DHT statistics";}
    }

    private final byte[] group;
    private final DhtNode<?> node;
    private final DhtResponder responder;
    private final DiscoveryStore store;
    private final DhtLink link;
    private final DhtContactDirectory directory;
    private final LongSupplier ticker;
    private final Random rng;
    private final DhtPeers peers;
    private final DhtTransfers transfers;
    private final TransferResources transferResources;
    private final DhtTransfers.RateBudget transferRateBudget;
    private DhtTransfers managedTransfers;
    private ManagedDhtStore managedStore;
    private final Map<ByteBuffer,Pending> pending=new LinkedHashMap<>();
    private long nextResponderId;
    /** DhtNodeの世代の写し。核の処理の途中で呼ばれるsendからnode.generation()を呼べないため、自分で持つ。 */
    private long generation;
    private long received,malformed,unauthenticated,wrongGroup,unsolicited,mismatched,expired,stale;
    /** 自分が握手を始めた揮発の相手（番号だけ・メモリだけ）。上限を超えたら古い順に捨てる。 */
    static final int MAX_STARTED=32;
    /** 握手や探りの動きから、この時間は手放さない（直近 30 秒）。 */
    static final long RELEASE_GRACE_NANOS=30*SECOND;
    private final Map<DhtId,Started> started=new LinkedHashMap<>();
    private long lastStartedTick;
    private java.util.function.Predicate<DhtId> publishInUse=p->false;
    /** STORE の結果（status）か、返事なく終わったこと（null）を公開の側へ知らせる。 */
    private java.util.function.BiConsumer<DhtId,DhtWire.StoreStatus> storeListener=(peer,status)->{};
    /** prepare と手放しの合計の件数（相手ごとには持たない）。 */
    private long busy,nothingReleasable,droppedStarted,releasedNotYes,releasedOutside,releasedCrowded,releasedNo;
    /** BUSY の理由別の件数。探索の候補が初めて BUSY になった知らせ（firstBusy）のときだけ数える。 */
    private long busyConcurrent,busyWindow,busyNothingReleasable,busyRecent30s,rehandshakeAfterRelease;
    private enum BusyReason { CONCURRENT,WINDOW,NOTHING,RECENT_30S }
    /** 直前の prepare が BUSY を返した理由と相手。次の prepare で消える。firstBusy が同じ相手のときだけ件数にする。 */
    private BusyReason busyReason;
    private DhtId busyPeer;
    /** 手放した相手の番号（上限つき。件数にもログにも出さない）。また握手を始めた数を数えるためだけに持つ。 */
    static final int MAX_RELEASED=32;
    private final LinkedHashSet<DhtId> releasedPeers=new LinkedHashSet<>();

    public DhtDispatcher(byte[] groupId,DhtNode<?> node,DhtResponder responder,DiscoveryStore store,DhtLink link,
                         DhtContactDirectory directory,DhtTransferSink sink,LongSupplier ticker) {
        this(groupId,node,responder,store,link,directory,sink,ticker,new SecureRandom(),DhtTransfers.Limits.defaults());
    }

    DhtDispatcher(byte[] groupId,DhtNode<?> node,DhtResponder responder,DiscoveryStore store,DhtLink link,
                  DhtContactDirectory directory,DhtTransferSink sink,LongSupplier ticker,Random rng,DhtTransfers.Limits limits) {
        this(groupId,node,responder,store,link,directory,sink,ticker,rng,limits,new TransferResources());
    }

    /**
     * 管理ページと同じ組立資源を渡す。
     * <p>
     * Supplies assembly resources shared with management pages.
     */
    public DhtDispatcher(byte[] groupId,DhtNode<?> node,DhtResponder responder,DiscoveryStore store,DhtLink link,
            DhtContactDirectory directory,DhtTransferSink sink,LongSupplier ticker,TransferResources resources){
        this(groupId,node,responder,store,link,directory,sink,ticker,new SecureRandom(),DhtTransfers.Limits.defaults(),resources);
    }
    private DhtDispatcher(byte[] groupId,DhtNode<?> node,DhtResponder responder,DiscoveryStore store,DhtLink link,
            DhtContactDirectory directory,DhtTransferSink sink,LongSupplier ticker,Random rng,DhtTransfers.Limits limits,TransferResources resources){
        if(groupId==null||groupId.length!=DhtWire.ID_BYTES)throw new IllegalArgumentException("Invalid group");
        this.group=groupId.clone();
        this.node=Objects.requireNonNull(node);this.responder=Objects.requireNonNull(responder);this.store=Objects.requireNonNull(store);
        this.link=Objects.requireNonNull(link);this.directory=Objects.requireNonNull(directory);
        this.ticker=Objects.requireNonNull(ticker);this.rng=Objects.requireNonNull(rng);
        this.generation=node.generation();
        this.peers=new DhtPeers(ticker,this::probe);
        this.transferResources=Objects.requireNonNull(resources);
        this.transferRateBudget=new DhtTransfers.RateBudget(limits);
        this.transfers=new DhtTransfers(group,link::send,ticker,rng,sink,this::valueExpected,resources,null,transferRateBudget);
    }

    /**
     * 検証者を持つ管理記録の受け渡しを接続する。旧DHTの経路は保つ。
     * <p>
     * Connects management storage with its verifier, preserving legacy DHT paths.
     */
    public void configureManaged(ManagedDhtStore store){
        if(managedStore!=null)throw new IllegalStateException("Management DHT already connected");
        managedStore=Objects.requireNonNull(store);
        managedTransfers=new DhtTransfers(group,(peer,session,wire)->{
            var message=DhtWire.parse(wire);
            if(message.op()==DhtWire.Op.TRANSFER&&message.transferKind()==DhtWire.TransferKind.STORE){
                var request=pending.get(keyOf(new DhtId(peer),message.transferId()));
                if(request==null||!request.current.getAsBoolean())return false;
            }
            return link.send(peer,session,DhtWire.management(wire));
        },ticker,rng,null,
                (peer,id)->managedValueExpected(peer,peers.sessionOf(peer),id),transferResources,new ManagedTransferSink(){
            @Override public void started(DhtId peer,byte[] session,long boundGeneration,DhtWire.TransferKind kind,byte[] id,long started){
                if(kind!=DhtWire.TransferKind.VALUE||boundGeneration!=generation)return;
                var request=pending.get(keyOf(peer,id));
                if(request!=null&&managedValueExpected(peer,session,id)&&!request.transferring){
                    request.transferring=true;request.deadline=started+DhtTransfers.TOTAL_NANOS;
                }
            }
            @Override public void completed(DhtId peer,byte[] session,long boundGeneration,DhtWire.TransferKind kind,byte[] id,ManagedTransferResult result){
                if(kind!=DhtWire.TransferKind.VALUE||boundGeneration!=generation)return;
                var key=keyOf(peer,id);var request=pending.get(key);
                if(request!=null&&request.kind==Kind.MANAGED_VALUE&&request.generation==boundGeneration&&Arrays.equals(request.session,session)){
                    pending.remove(key);finish(request,null);
                }
            }
            @Override public ManagedTransferResult accept(ManagedTransferContext context,ManagedDhtRecord record){
                if(context.generation()!=generation||link.authenticated(context.peer().bytes(),context.sessionId())==null)return ManagedTransferResult.REJECTED;
                if(context.kind()==DhtWire.TransferKind.STORE){
                    var status=managedStore.accept(context.peer().bytes(),record,true);
                    transmit(context.peer(),context.sessionId(),DhtWire.management(DhtWire.storeResult(group,context.requestId(),record.key(),status)));
                    return accepted(status)?ManagedTransferResult.ACCEPTED:ManagedTransferResult.REJECTED;
                }
                var key=keyOf(context.peer(),context.requestId());var request=pending.get(key);
                if(request==null||!managedValueExpected(context.peer(),context.sessionId(),context.requestId())||!request.target.equals(record.key()))return ManagedTransferResult.REJECTED;
                pending.remove(key);
                boolean valid=accepted(managedStore.accept(context.peer().bytes(),record,false));finish(request,valid?record:null);
                return valid?ManagedTransferResult.ACCEPTED:ManagedTransferResult.REJECTED;
            }
        },transferRateBudget);
    }
    private static boolean accepted(DhtWire.StoreStatus status){return status==DhtWire.StoreStatus.ACCEPTED||status==DhtWire.StoreStatus.DUPLICATE||status==DhtWire.StoreStatus.OLD;}
    /**
     * 管理記録を既存STOREまたはTransferで公開し、全体の結果を一度だけ返す。
     * <p>
     * Publishes a management record over existing STORE or Transfer and reports the whole-record result once.
     */
    public boolean storeManaged(Contact destination,byte[] encoded,Consumer<DhtWire.StoreStatus> done){
        return storeManaged(destination,encoded,done,()->true);
    }
    /**
     * 保存済み候補の取消後は、残るSTORE断片も新たに送らない。
     * <p>
     * Sends no further STORE chunks after cancellation of a persisted candidate.
     */
    public boolean storeManaged(Contact destination,byte[] encoded,Consumer<DhtWire.StoreStatus> done,java.util.function.BooleanSupplier current){
        if(managedStore==null||!current.getAsBoolean())return false;
        final ManagedDhtRecord record;try{record=ManagedDhtRecord.verifyStructure(encoded,group);}catch(RuntimeException invalid){return false;}
        var peer=destination.id();var session=usable(peer);if(session==null)return false;
        if(record.transport()==ManagedDhtRecord.Transport.STORE)return register(Kind.MANAGED_STORE,DhtWire.Op.STORE,0,peer,session,record.key(),0,
                ticker.getAsLong()+DhtLimits.RPC_NANOS,null,rid->link.send(peer.bytes(),session,DhtWire.management(DhtWire.store(group,rid,record.key(),encoded))),result->done.accept((DhtWire.StoreStatus)result),current);
        return register(Kind.MANAGED_STORE,DhtWire.Op.STORE,0,peer,session,record.key(),0,ticker.getAsLong()+240*SECOND,null,
                rid->managedTransfers.start(peer,session,DhtWire.TransferKind.STORE,rid,encoded),result->done.accept((DhtWire.StoreStatus)result),current);
    }
    /**
     * 現在の相手へ管理記録を要求し、束縛と全体を検証した結果だけを返す。
     * <p>
     * Requests a management record from a current peer and returns only a bound, fully verified result.
     */
    public boolean findManagedFrom(Contact destination,DhtId target,Consumer<ManagedDhtRecord> done){
        return findManagedFrom(destination,target,done,()->true);
    }
    /**
     * 呼出側の待ちが終わったら、VALUEやTransferを検証・保存へ進めない。
     * <p>
     * Prevents VALUE or Transfer validation and persistence after the caller's wait ends.
     */
    public boolean findManagedFrom(Contact destination,DhtId target,Consumer<ManagedDhtRecord> done,java.util.function.BooleanSupplier current){
        if(managedStore==null||!current.getAsBoolean())return false;var peer=destination.id();var session=usable(peer);if(session==null)return false;
        return register(Kind.MANAGED_VALUE,DhtWire.Op.FIND_VALUE,0,peer,session,target,0,ticker.getAsLong()+DhtLimits.RPC_NANOS,null,
                rid->link.send(peer.bytes(),session,DhtWire.management(DhtWire.findValue(group,rid,target))),result->done.accept((ManagedDhtRecord)result),current);
    }
    private boolean managedValueExpected(DhtId peer,byte[] session,byte[] id){
        var p=pending.get(keyOf(peer,id));
        return p!=null&&p.kind==Kind.MANAGED_VALUE&&p.generation==generation&&Arrays.equals(p.session,session)
                &&ticker.getAsLong()-p.deadline<0&&p.current.getAsBoolean();
    }
    private void answerManaged(AuthenticatedPeer peer,byte[] session,DhtWire.Message message){
        if(!responder.admitBeforeAnswering(peer))return;
        if(message.op()==DhtWire.Op.STORE){
            DhtWire.StoreStatus status=DhtWire.StoreStatus.INVALID;
            try{
                var record=ManagedDhtRecord.verifyStructure(message.record(),group);
                if(record.key().equals(message.target()))status=managedStore.accept(peer.id().bytes(),record,true);
            }catch(RuntimeException invalid){}
            transmit(peer.id(),session,DhtWire.management(DhtWire.storeResult(group,message.requestId(),message.target(),status)));return;
        }
        var record=managedStore.get(message.target());
        if(record==null){transmit(peer.id(),session,DhtWire.management(DhtWire.nodes(group,message.requestId(),message.target(),0,true,List.of())));return;}
        byte[] encoded=record.encode();
        if(record.transport()==ManagedDhtRecord.Transport.STORE)transmit(peer.id(),session,DhtWire.management(DhtWire.value(group,message.requestId(),message.target(),encoded)));
        else managedTransfers.start(peer.id(),session,DhtWire.TransferKind.VALUE,message.requestId(),encoded);
    }

    public DhtPeers peers(){return peers;}
    /** 試験と同じパッケージの中だけ。外からは startTransfer を使い、DHT を話せると確かめた相手にしか転送を始めない。 */
    DhtTransfers transfers(){return transfers;}

    /**
     * 大きな転送を始める。DHT を話せると確かめた相手（YES）で、今のセッションがあるときだけ始める。
     * そうでなければ何も送らず null を返す。転送番号を返す。
     */
    public byte[] startTransfer(Contact destination,DhtWire.TransferKind kind,byte[] data) {
        Objects.requireNonNull(destination);Objects.requireNonNull(kind);Objects.requireNonNull(data);
        DhtId peer=destination.id();
        byte[] session=usable(peer);
        if(session==null)return null;
        return transfers.start(peer,session,kind,data);
    }

    /** 番号を指定する版（FIND_VALUE の返事の値を送るときなど）。始めたら true。 */
    public boolean startTransfer(Contact destination,DhtWire.TransferKind kind,byte[] id,byte[] data) {
        Objects.requireNonNull(destination);Objects.requireNonNull(kind);Objects.requireNonNull(id);Objects.requireNonNull(data);
        DhtId peer=destination.id();
        byte[] session=usable(peer);
        if(session==null)return false;
        return transfers.start(peer,session,kind,id,data);
    }
    public int pendingCount(){return pending.size();}

    // ---- 送る側 ----

    /** 核からの要求。DHTを話せると確かめた相手で、今のセッションがあるときだけ送る。 */
    @Override public boolean send(Contact destination,Request request) {
        Objects.requireNonNull(destination);Objects.requireNonNull(request);
        DhtId peer=destination.id();
        byte[] session=usable(peer);
        if(session==null)return false;
        long deadline=ticker.getAsLong()+DhtLimits.RPC_NANOS;
        switch(request.operation()) {
            case PING:
                return open(Kind.CORE,DhtWire.Op.PING,request.id(),peer,session,null,0,deadline,null,rid->DhtWire.ping(group,rid));
            case FIND_NODE:
                return open(Kind.CORE,DhtWire.Op.FIND_NODE,request.id(),peer,session,request.target(),0,deadline,null,
                    rid->DhtWire.findNode(group,rid,request.target(),0));
            case FIND_VALUE:
                return open(Kind.CORE,DhtWire.Op.FIND_VALUE,request.id(),peer,session,request.target(),0,deadline,null,
                    rid->DhtWire.findValue(group,rid,request.target()));
            default:
                return false; // STORE は記録が要る。store(Contact,byte[]) を使う。
        }
    }

    /** 署名つきの記録を預ける要求。相手の返事（STORE_RESULT）は数えるだけ。 */
    public boolean store(Contact destination,byte[] signedRecord) {
        Objects.requireNonNull(destination);Objects.requireNonNull(signedRecord);
        DhtId key;
        try {
            key=DiscoveryRecord.parse(signedRecord).key();
        } catch(RuntimeException malformedRecord) {
            return false;
        }
        DhtId peer=destination.id();
        byte[] session=usable(peer);
        if(session==null)return false;
        return open(Kind.STORE,DhtWire.Op.STORE,0,peer,session,key,0,ticker.getAsLong()+DhtLimits.RPC_NANOS,null,
            rid->DhtWire.store(group,rid,key,signedRecord));
    }

    /**
     * 直接つながった1人の相手へ、署名つきの記録を預け、相手の答えを1回だけ done に渡す（true=受け取った。false=受け取らない。null=待ちを捨てた）。
     * 送れなければ false を返し、done は呼ばない。結果は DhtPublisher の数には入らない。
     */
    public boolean store(Contact destination,byte[] signedRecord,Consumer<Boolean> done) {
        Objects.requireNonNull(destination);Objects.requireNonNull(signedRecord);Objects.requireNonNull(done);
        DhtId key;
        try {
            key=DiscoveryRecord.parse(signedRecord).key();
        } catch(RuntimeException malformedRecord) {
            return false;
        }
        DhtId peer=destination.id();
        byte[] session=usable(peer);
        if(session==null)return false;
        return open(Kind.DIRECT_STORE,DhtWire.Op.STORE,0,peer,session,key,0,ticker.getAsLong()+DhtLimits.RPC_NANOS,null,
            rid->DhtWire.store(group,rid,key,signedRecord),r->done.accept((Boolean)r));
    }

    /**
     * 直接つながった1人の相手へ FIND_VALUE を1通だけ送り、検証できた記録を1回だけ done に渡す。
     * 記録は預かりの表に入れない。VALUE でなかったとき・検証に落ちたとき・期限切れ・世代の変わり・待ちを捨てたときは null。
     * 送れなければ false を返し、done は呼ばない。
     */
    public boolean findValueFrom(Contact destination,DhtId key,Consumer<DiscoveryRecord> done) {
        Objects.requireNonNull(destination);Objects.requireNonNull(key);Objects.requireNonNull(done);
        DhtId peer=destination.id();
        byte[] session=usable(peer);
        if(session==null)return false;
        return open(Kind.DIRECT_VALUE,DhtWire.Op.FIND_VALUE,0,peer,session,key,0,ticker.getAsLong()+DhtLimits.RPC_NANOS,null,
            rid->DhtWire.findValue(group,rid,key),r->done.accept((DiscoveryRecord)r));
    }

    /** 直接の待ちの結果を1回だけ渡す。呼び出し側の例外で核の状態を壊さない。 */
    private static void finish(Pending p,Object result) {
        Consumer<Object> done=p.done;
        if(done==null)return;
        p.done=null;
        try {
            done.accept(result);
        } catch(RuntimeException ignored) {
            // 呼び出し側の失敗は核の状態に影響させない。
        }
    }

    private byte[] usable(DhtId peer) {
        if(!peers.isYes(peer))return null;
        return peers.sessionOf(peer);
    }

    /** DhtPeersの探り。PINGを1通送る。自分が始めた握手の試みなら、探りを出せたことを試みと表に知らせる。 */
    private boolean probe(DhtId peer,byte[] session) {
        boolean sent=open(Kind.PROBE,DhtWire.Op.PING,0,peer,session,null,0,ticker.getAsLong()+PROBE_NANOS,null,rid->DhtWire.ping(group,rid));
        if(sent) {
            Started s=started.get(peer);
            if(s!=null) {
                s.probed=true;
                node.candidates().attemptFor(peer).ifPresent(a->node.candidates().probeSent(a));
            }
        }
        return sent;
    }

    // ---- 探索が欲しい相手の握手（核D） ----

    /** 自分が握手を始めた揮発の相手の覚え。番号と時刻だけ。 */
    private static final class Started {
        final long startedAt;
        long lastActive;
        boolean sessionSeen,probed;
        Started(long now){startedAt=now;lastActive=now;}
        @Override public String toString(){return "DHT started peer";}
    }

    /** 手放しの順位。小さいほど先に手放す。 */
    private static final int RANK_NOT_YES=0,RANK_OUTSIDE_TABLE=1,RANK_TABLE=2,NOT_RELEASABLE=-1,ONLY_RECENT=-2;
    /** 直前の releaseOne で、30 秒だけが理由で外した相手がいたか。 */
    private boolean recentOnlySeen;

    /**
     * 探索が欲しい相手を使える形にする。DhtNode の探索から呼ばれるので、DhtNode の enter を通る口（observe・poll・receive など）は呼ばない。
     * 順: YES でセッションあり→READY、NO→UNAVAILABLE、握手の試みが動いている／セッションがあって探りの返事待ち→CONNECTING、
     * 候補の表にいれば握手を始める（揮発の枠が満杯なら手放せる相手を手放してから）、どれでもなければ UNAVAILABLE。
     */
    @Override public Readiness prepare(Contact destination) {
        Objects.requireNonNull(destination);
        try {
            busyReason=null;busyPeer=null;
            DhtId peer=destination.id();long now=tickStarted();
            DhtPeers.State state=peers.state(peer);byte[] session=peers.sessionOf(peer);
            if(state==DhtPeers.State.YES&&session!=null)return Readiness.READY;
            if(state==DhtPeers.State.NO)return Readiness.UNAVAILABLE;
            DhtCandidates candidates=node.candidates();
            if(candidates.isActive(peer))return Readiness.CONNECTING;
            if(session!=null) {
                Started s=started.get(peer);
                // 握手は済んだのに探りを 1 通も出せないまま試みが終わった相手は、この探索では使えない。
                if(s!=null&&s.sessionSeen&&!s.probed)return Readiness.UNAVAILABLE;
                return Readiness.CONNECTING;
            }
            switch(candidates.check(peer)) {
                case ACTIVE: return Readiness.CONNECTING;
                case BUSY: return busy(peer,candidates.concurrentFull()?BusyReason.CONCURRENT:BusyReason.WINDOW);
                case REFUSED: return Readiness.UNAVAILABLE;
                default: break;
            }
            if(!link.startAllowed())return Readiness.UNAVAILABLE;
            if(!link.volatileSlotFree()&&!releaseOne(now)) {
                nothingReleasable=inc(nothingReleasable);
                return busy(peer,recentOnlySeen?BusyReason.RECENT_30S:BusyReason.NOTHING);
            }
            switch(candidates.startFor(peer)) {
                case STARTED:
                    remember(peer,now);return Readiness.CONNECTING;
                case ACTIVE: return Readiness.CONNECTING;
                case BUSY: return busy(peer,candidates.concurrentFull()?BusyReason.CONCURRENT:BusyReason.WINDOW);
                default: return Readiness.UNAVAILABLE;
            }
        } catch(RuntimeException failed) {
            return Readiness.UNAVAILABLE;
        }
    }

    /** BUSY を返す。理由と相手を覚えるだけで、理由別の件数は探索が初めて BUSY を受けたとき（firstBusy）に数える。 */
    private Readiness busy(DhtId peer,BusyReason reason) {
        busy=inc(busy);busyReason=reason;busyPeer=peer;return Readiness.BUSY;
    }

    /** 探索の候補が初めて BUSY になった知らせ。直前の prepare が BUSY を返した相手のときだけ、その理由の件数を 1 つ足す。 */
    @Override public void firstBusy(Contact destination) {
        Objects.requireNonNull(destination);
        BusyReason reason=busyReason;
        if(reason==null||!destination.id().equals(busyPeer))return;
        busyReason=null;busyPeer=null;
        switch(reason) {
            case CONCURRENT: busyConcurrent=inc(busyConcurrent);break;
            case WINDOW: busyWindow=inc(busyWindow);break;
            case NOTHING: busyNothingReleasable=inc(busyNothingReleasable);break;
            default: busyRecent30s=inc(busyRecent30s);
        }
    }

    /** 自分が始めた相手の表に入れる。上限を超えたら古い順に捨てて数える（捨てた相手は、もう手放しの対象にならないだけ）。 */
    private void remember(DhtId peer,long now) {
        started.remove(peer);started.put(peer,new Started(now));
        if(releasedPeers.remove(peer))rehandshakeAfterRelease=inc(rehandshakeAfterRelease);
        while(started.size()>MAX_STARTED) {
            var oldest=started.keySet().iterator();oldest.next();oldest.remove();droppedStarted=inc(droppedStarted);
        }
    }

    /** 時計が戻ったら、自分が始めた相手の表を捨てる（時刻の比べ方が成り立たなくなるため）。 */
    private long tickStarted() {
        long now=ticker.getAsLong();
        if(now-lastStartedTick<0)started.clear();
        lastStartedTick=now;return now;
    }

    /** 自分が始めた相手と、正しい返事を受けた・要求に答えた。手放しまでの 30 秒を、そのときから数え直す。 */
    private void touchStarted(DhtId peer) {
        long now=tickStarted();
        Started s=started.get(peer);
        if(s!=null)s.lastActive=now;
    }

    /** 使用中か。探索・保留の要求・大きな転送・公開の送り先のどれかが、その相手を使っている。 */
    private boolean inUse(DhtId peer) {
        if(node.isReferenced(peer)||transfers.usesPeer(peer)||managedTransfers!=null&&managedTransfers.usesPeer(peer)||publishInUse.test(peer))return true;
        for(Pending p:pending.values())if(p.peer.equals(peer))return true;
        return false;
    }

    private int rankOf(DhtId peer,Started s,long now) {
        if(!s.sessionSeen||inUse(peer))return NOT_RELEASABLE;
        if(peers.sessionOf(peer)==null)return NOT_RELEASABLE;
        if(now-s.lastActive<RELEASE_GRACE_NANOS)return ONLY_RECENT;
        if(peers.state(peer)!=DhtPeers.State.YES)return RANK_NOT_YES;
        return node.routing().contains(peer)?RANK_TABLE:RANK_OUTSIDE_TABLE;
    }

    /** 自分が始めた相手から 1 台を手放す。手放せたら true。受け側は追い出さない。 */
    private boolean releaseOne(long now) {
        recentOnlySeen=false;
        while(true) {
            DhtId best=null;int bestRank=NOT_RELEASABLE,bestLoad=-1,bestAge=Integer.MAX_VALUE;
            for(Map.Entry<DhtId,Started> e:started.entrySet()) {
                int rank=rankOf(e.getKey(),e.getValue(),now);
                if(rank==ONLY_RECENT){recentOnlySeen=true;continue;}
                if(rank==NOT_RELEASABLE)continue;
                int load=rank==RANK_TABLE?node.routing().bucketLoadOf(e.getKey()):0;
                int age=rank==RANK_TABLE?node.routing().ageRankOf(e.getKey()):0;
                boolean better=best==null||rank<bestRank||rank==bestRank&&rank==RANK_TABLE&&(load>bestLoad||load==bestLoad&&age<bestAge);
                if(better){best=e.getKey();bestRank=rank;bestLoad=load;bestAge=age;}
            }
            if(best==null)return false;
            if(releaseNow(best)){
                switch(bestRank) {
                    case RANK_NOT_YES: releasedNotYes=inc(releasedNotYes);break;
                    case RANK_OUTSIDE_TABLE: releasedOutside=inc(releasedOutside);break;
                    default: releasedCrowded=inc(releasedCrowded);
                }
                return true;
            }
        }
    }

    /** 手放す。保存した相手・知らない相手のときは手放さず、表から外すだけ（false）。手放せたら後片付けも済ませる（true）。 */
    private boolean releaseNow(DhtId peer) {
        boolean released;
        try {
            released=link.releaseVolatile(peer.bytes());
        } catch(RuntimeException failed) {
            released=false;
        }
        started.remove(peer);
        if(released) {
            volatilePeerForgotten(peer.bytes());
            node.routing().remove(peer);
            rememberReleased(peer);
        }
        return released;
    }

    /** 手放した相手の番号を覚える（上限 32。超えたら古い順に捨てる）。 */
    private void rememberReleased(DhtId peer) {
        releasedPeers.remove(peer);releasedPeers.add(peer);
        while(releasedPeers.size()>MAX_RELEASED) {
            var oldest=releasedPeers.iterator();oldest.next();oldest.remove();
        }
    }

    /** 握手の試みの結果を、探りの結果に合わせて閉じる。NO と分かった自分が始めた相手は、満杯を待たずに手放す。 */
    private void settleStarted() {
        for(DhtId peer:new ArrayList<>(started.keySet())) {
            Started s=started.get(peer);if(s==null)continue;
            Optional<DhtCandidates.Attempt> attempt=node.candidates().attemptFor(peer);
            if(!s.sessionSeen){
                if(attempt.isEmpty())started.remove(peer);
                continue;
            }
            DhtPeers.State state=peers.state(peer);
            if(attempt.isPresent()) {
                if(state==DhtPeers.State.YES)node.candidates().finish(attempt.get(),true);
                else if(state==DhtPeers.State.NO)node.candidates().finish(attempt.get(),false);
            }
            if(state==DhtPeers.State.NO&&!inUse(peer)&&releaseNow(peer))releasedNo=inc(releasedNo);
        }
    }

    /** 公開の送り先など、DhtDispatcher の外で「使用中」にしている相手を知らせる口（試験と DhtPublisher から）。 */
    void setPublishInUse(java.util.function.Predicate<DhtId> inUse){this.publishInUse=Objects.requireNonNull(inUse);}
    void setStoreListener(java.util.function.BiConsumer<DhtId,DhtWire.StoreStatus> listener){this.storeListener=Objects.requireNonNull(listener);}

    private boolean open(Kind kind,DhtWire.Op op,long coreId,DhtId peer,byte[] session,DhtId target,int page,long deadline,
                         List<DhtId> carry,UnaryOperator<byte[]> wire) {
        return open(kind,op,coreId,peer,session,target,page,deadline,carry,wire,null);
    }

    private boolean open(Kind kind,DhtWire.Op op,long coreId,DhtId peer,byte[] session,DhtId target,int page,long deadline,
                         List<DhtId> carry,UnaryOperator<byte[]> wire,Consumer<Object> done) {
        return register(kind,op,coreId,peer,session,target,page,deadline,carry,rid->link.send(peer.bytes(),session,wire.apply(rid)),done);
    }
    private boolean register(Kind kind,DhtWire.Op op,long coreId,DhtId peer,byte[] session,DhtId target,int page,long deadline,
            List<DhtId> carry,java.util.function.Function<byte[],Boolean> send,Consumer<Object> done){
        return register(kind,op,coreId,peer,session,target,page,deadline,carry,send,done,()->true);
    }
    private boolean register(Kind kind,DhtWire.Op op,long coreId,DhtId peer,byte[] session,DhtId target,int page,long deadline,
            List<DhtId> carry,java.util.function.Function<byte[],Boolean> send,Consumer<Object> done,java.util.function.BooleanSupplier current){
        if(pending.size()>=MAX_PENDING)return false;
        int mine=0;
        for(Pending p:pending.values()) {
            if(p.peer.equals(peer))mine++;
        }
        if(mine>=MAX_PENDING_PER_PEER)return false;
        byte[] rid=null;
        ByteBuffer key=null;
        for(int attempt=0;attempt<4&&key==null;attempt++) {
            byte[] candidate=new byte[DhtWire.REQUEST_BYTES];rng.nextBytes(candidate);
            ByteBuffer k=keyOf(peer,candidate);
            if(!pending.containsKey(k)){rid=candidate;key=k;}
        }
        if(key==null)return false;
        Pending entry=new Pending(kind,op,coreId,peer,session,target,page,generation,deadline,carry);
        entry.done=done;entry.current=Objects.requireNonNull(current);
        pending.put(key,entry);
        boolean sent;
        try {
            sent=send.apply(rid);
        } catch(RuntimeException failed) {
            sent=false;
        }
        if(!sent)pending.remove(key);
        return sent;
    }

    private static ByteBuffer keyOf(DhtId peer,byte[] requestId) {
        byte[] id=peer.bytes();
        byte[] both=new byte[id.length+requestId.length];
        System.arraycopy(id,0,both,0,id.length);System.arraycopy(requestId,0,both,id.length,requestId.length);
        return ByteBuffer.wrap(both);
    }

    // ---- 受ける側 ----

    /**
     * 復号済みの本文を1つ受ける。DHTの形でなければ何もせずfalse（呼び出し側が他の処理へ回す）。
     * DHTの形ならtrue（捨てた場合も含む）。
     */
    public boolean receive(byte[] peerId,byte[] sessionId,byte[] plaintext) {
        Objects.requireNonNull(peerId);Objects.requireNonNull(sessionId);Objects.requireNonNull(plaintext);
        if(!DhtWire.isDht(plaintext))return false;
        received=inc(received);
        AuthenticatedPeer source;
        try {
            source=link.authenticated(peerId,sessionId);
        } catch(RuntimeException failed) {
            source=null;
        }
        if(source==null||peerId.length!=DhtWire.ID_BYTES||!source.id().equals(new DhtId(peerId))){unauthenticated=inc(unauthenticated);return true;}
        DhtWire.Message message;
        try {
            message=DhtWire.parse(plaintext);
        } catch(RuntimeException bad) {
            malformed=inc(malformed);return true;
        }
        if(!Arrays.equals(message.groupId(),group)){wrongGroup=inc(wrongGroup);return true;}
        if(message.managed()){
            if(managedStore==null)return true;
            if(source.generation()!=AuthenticatedPeer.UNBOUND&&source.generation()!=generation)return true;
            switch(message.op()){
                case STORE: case FIND_VALUE: answerManaged(source,sessionId,message);break;
                case TRANSFER: case TRANSFER_ACK:
                    if(message.op()==DhtWire.Op.TRANSFER&&message.transferKind()==DhtWire.TransferKind.VALUE){
                        if(!managedValueExpected(source.id(),sessionId,message.transferId()))return true;
                    }
                    managedTransfers.receive(source.id(),sessionId,generation,message);break;
                default: matchResponse(source,sessionId,message);
            }
            return true;
        }
        switch(message.op()) {
            case PING: case FIND_NODE: case FIND_VALUE: case STORE:
                answerRequest(source,sessionId,message);break;
            case TRANSFER: case TRANSFER_ACK:
                transfers.receive(source.id(),sessionId,message);break;
            default:
                matchResponse(source,sessionId,message);
        }
        return true;
    }

    private void answerRequest(AuthenticatedPeer source,byte[] session,DhtWire.Message m) {
        DhtId peer=source.id();
        peers.hint(peer,session);
        byte[] rid=m.requestId();
        long id=++nextResponderId;
        byte[] reply=null;
        boolean keyMismatchRefusal=false;
        switch(m.op()) {
            case PING: {
                Optional<DhtResponder.Response> r=responder.answer(source,DhtResponder.Request.ping(id));
                if(r.isPresent())reply=DhtWire.pong(group,rid);
                break;
            }
            case FIND_NODE: {
                Optional<DhtResponder.Response> r=responder.answer(source,DhtResponder.Request.findNode(id,m.target()));
                if(r.isPresent())reply=nodesReply(rid,m.target(),m.page(),r.get().contacts());
                break;
            }
            case FIND_VALUE: {
                Optional<DhtResponder.Response> r=responder.answer(source,DhtResponder.Request.findValue(id,m.target()));
                if(r.isPresent()) {
                    DhtResponder.Response response=r.get();
                    reply=response.kind()==DhtResponder.Kind.VALUE
                        ?DhtWire.value(group,rid,m.target(),response.record())
                        :nodesReply(rid,m.target(),0,response.contacts());
                }
                break;
            }
            default: { // STORE。線のkeyと記録のkeyが違うものは、署名の計算に入る前に断る。
                byte[] record=m.record();
                DhtId recordKey=null;
                try {
                    recordKey=DiscoveryRecord.parse(record).key();
                } catch(RuntimeException malformedRecord) {
                    recordKey=null; // 構文違いはDhtResponderがINVALIDで返す。
                }
                if(recordKey!=null&&!recordKey.equals(m.target())) {
                    // この断りも返事を作るので、DhtResponder と同じ速度の袋を先に通す。
                    if(!responder.admitBeforeAnswering(source))break;
                    store.counts().rejected(DiscoveryStatus.INVALID);
                    keyMismatchRefusal=true;
                    reply=DhtWire.storeResult(group,rid,m.target(),DhtWire.StoreStatus.INVALID);
                    break;
                }
                Optional<DhtResponder.Response> r=responder.answer(source,DhtResponder.Request.store(id,record));
                if(r.isPresent())reply=DhtWire.storeResult(group,rid,m.target(),wireStatus(r.get().status()));
            }
        }
        if(reply!=null) {
            // 返事を作った分岐だけが「要求に答えた」。速度の枠の断り・鍵違いの INVALID の断りは含めない。
            if(!keyMismatchRefusal)touchStarted(peer);
            transmit(peer,session,reply);
        }
    }

    private static DhtWire.StoreStatus wireStatus(DiscoveryStatus status) {
        if(status==null)return DhtWire.StoreStatus.INVALID;
        switch(status) {
            case ACCEPTED: return DhtWire.StoreStatus.ACCEPTED;
            case DUPLICATE: return DhtWire.StoreStatus.DUPLICATE;
            case OLD_VERSION: return DhtWire.StoreStatus.OLD;
            case CAPACITY: return DhtWire.StoreStatus.FULL;
            default: return DhtWire.StoreStatus.INVALID;
        }
    }

    /**
     * 連絡先を番地つきに直して1ページ10件で返す。番地のない連絡先は除く。
     * 2ページ目の要求（FIND_NODE の page 1）も、1ページ目と同じく {@link DhtResponder} の速度の枠を 1 回使う。
     * FIND_VALUE で記録がなかったときの返事は 1 ページ目だけで、続きは FIND_NODE の page 1 で取る。
     */
    private byte[] nodesReply(byte[] rid,DhtId target,int page,List<Contact> contacts) {
        List<DhtWire.NodeContact> mapped=new ArrayList<>();
        for(Contact c:contacts) {
            DhtWire.NodeContact n=null;
            try {
                n=directory.contact(c.id());
            } catch(RuntimeException failed) {
                n=null;
            }
            if(n!=null)mapped.add(n);
        }
        boolean last=page>=1||mapped.size()<=PAGE_CONTACTS;
        List<DhtWire.NodeContact> slice;
        if(page>=1) {
            slice=mapped.size()>PAGE_CONTACTS?mapped.subList(PAGE_CONTACTS,Math.min(mapped.size(),2*PAGE_CONTACTS)):List.of();
        } else {
            slice=mapped.subList(0,Math.min(mapped.size(),PAGE_CONTACTS));
        }
        return DhtWire.nodes(group,rid,target,page>=1?1:0,last,new ArrayList<>(slice));
    }

    private void transmit(DhtId peer,byte[] session,byte[] wire) {
        try {
            link.send(peer.bytes(),session,wire);
        } catch(RuntimeException failed) {
            // 送れなかった返事は捨てる。相手は再送する。
        }
    }

    // ---- 応答の結び付け ----

    private void matchResponse(AuthenticatedPeer source,byte[] session,DhtWire.Message m) {
        DhtId peer=source.id();
        ByteBuffer key=keyOf(peer,m.requestId());
        Pending p=pending.get(key);
        if(p==null){unsolicited=inc(unsolicited);return;}
        long now=ticker.getAsLong();
        if(now-p.deadline>=0||!p.current.getAsBoolean()){pending.remove(key);expired=inc(expired);expireOne(p);return;}
        if(!Arrays.equals(p.session,session)||((p.kind==Kind.MANAGED_VALUE||p.kind==Kind.MANAGED_STORE)!=m.managed())||!compatible(p,m)){mismatched=inc(mismatched);return;}
        if(p.generation!=generation||source.generation()!=AuthenticatedPeer.UNBOUND&&source.generation()!=generation) {
            pending.remove(key);stale=inc(stale);
            // 世代の違う返事で待ちを捨てるときも、STORE の使用中の印が残らないように知らせる。
            if(p.kind==Kind.STORE)storeListener.accept(p.peer,null);
            finish(p,null);
            return;
        }
        pending.remove(key);
        touchStarted(peer); // 検査をすべて通った正しい返事だけが、手放しまでの 30 秒を延ばす。
        switch(p.kind) {
            case PROBE:
                if(peers.probeAnswered(peer,session))node.observe(source);
                break;
            case STORE:
                peers.requestAnswered(peer,session);
                storeListener.accept(peer,m.status());
                break;
            case DIRECT_STORE:
                peers.requestAnswered(peer,session);
                finish(p,m.status()==DhtWire.StoreStatus.ACCEPTED||m.status()==DhtWire.StoreStatus.DUPLICATE);
                break;
            case MANAGED_STORE:
                finish(p,m.status());break;
            case MANAGED_VALUE:
                ManagedDhtRecord value=null;
                if(m.op()==DhtWire.Op.VALUE){
                    try{
                        var record=ManagedDhtRecord.verifyStructure(m.record(),group);
                        if(record.key().equals(p.target)&&accepted(managedStore.accept(peer.bytes(),record,false)))value=record;
                    }catch(RuntimeException invalid){}
                }
                finish(p,value);break;
            case DIRECT_VALUE:
                peers.requestAnswered(peer,session);
                finish(p,verifiedDirectValue(p,m));
                break;
            default:
                peers.requestAnswered(peer,session);
                deliver(source,p,m);
        }
    }

    /** 直接の FIND_VALUE への VALUE を検証する。検証に通り、探した鍵と同じときだけ記録を返す。それ以外は null。 */
    private DiscoveryRecord verifiedDirectValue(Pending p,DhtWire.Message m) {
        if(m.op()!=DhtWire.Op.VALUE||m.record()==null)return null;
        try {
            DiscoveryRecord record=store.verifyOwnClock(m.record());
            return record.key().equals(p.target)?record:null;
        } catch(RuntimeException rejected) {
            return null;
        }
    }

    private static boolean compatible(Pending p,DhtWire.Message m) {
        switch(p.op) {
            case PING: return m.op()==DhtWire.Op.PONG;
            case FIND_NODE: return m.op()==DhtWire.Op.NODES&&p.target.equals(m.target())&&m.page()==p.page;
            case FIND_VALUE:
                return (m.op()==DhtWire.Op.VALUE&&p.target.equals(m.target()))
                    ||(m.op()==DhtWire.Op.NODES&&p.target.equals(m.target())&&m.page()==0);
            case STORE: return m.op()==DhtWire.Op.STORE_RESULT&&p.target.equals(m.target());
            default: return false;
        }
    }

    private void deliver(AuthenticatedPeer source,Pending p,DhtWire.Message m) {
        DhtId peer=source.id();
        switch(m.op()) {
            case PONG:
                node.receive(source,p.coreId,List.of(),null);
                break;
            case VALUE:
                node.receive(source,p.coreId,List.of(),m.record());
                break;
            default: { // NODES
                List<DhtId> ids=new ArrayList<>();
                for(DhtWire.NodeContact n:m.contacts()) {
                    try {
                        node.candidates().offer(peer,new DhtCandidates.Candidate(n.node(),n.ipv4(),n.port(),n.handshakeKey()));
                    } catch(IllegalArgumentException invalid) {
                        // 形が悪い候補は捨てる。
                    }
                    ids.add(n.node());
                }
                if(p.page==1) {
                    node.receive(source,p.coreId,merge(p.carry,ids),null);
                } else if(!m.last()) {
                    long deadline=ticker.getAsLong()+PAGE_NANOS;
                    boolean asked=open(Kind.CORE,DhtWire.Op.FIND_NODE,p.coreId,peer,p.session,p.target,1,deadline,ids,
                        rid->DhtWire.findNode(group,rid,p.target,1));
                    if(!asked)node.receive(source,p.coreId,toContacts(ids),null);
                } else {
                    node.receive(source,p.coreId,toContacts(ids),null);
                }
            }
        }
    }

    private static List<Contact> toContacts(List<DhtId> ids) {
        List<Contact> out=new ArrayList<>();
        for(DhtId id:ids)out.add(new Contact(id));
        return out;
    }

    private static List<Contact> merge(List<DhtId> first,List<DhtId> second) {
        List<DhtId> unique=new ArrayList<>();
        for(DhtId id:first)if(!unique.contains(id)&&unique.size()<DhtLimits.K)unique.add(id);
        for(DhtId id:second)if(!unique.contains(id)&&unique.size()<DhtLimits.K)unique.add(id);
        return toContacts(unique);
    }

    /** 期限切れの1件。2ページ目を待っていたものは、1ページ目だけを核へ渡す。 */
    private void expireOne(Pending p) {
        if(p.kind==Kind.STORE)storeListener.accept(p.peer,null);
        finish(p,null);
        if(p.kind!=Kind.PROBE&&p.generation==generation)peers.requestExpired(p.peer,p.session);
        if(p.kind==Kind.CORE&&p.page==1&&p.carry!=null&&p.generation==generation) {
            AuthenticatedPeer source=authenticatedOrNull(p);
            if(source!=null)node.receive(source,p.coreId,toContacts(p.carry),null);
        }
    }

    private AuthenticatedPeer authenticatedOrNull(Pending p) {
        try {
            return link.authenticated(p.peer.bytes(),p.session);
        } catch(RuntimeException failed) {
            return null;
        }
    }

    /** 自分が出したFIND_VALUEへの答えとして届く大きな転送だけを受ける（request_id = transfer_id）。 */
    private boolean valueExpected(DhtId peer,byte[] transferId) {
        Pending p=pending.get(keyOf(peer,transferId));
        return p!=null&&p.kind==Kind.CORE&&p.op==DhtWire.Op.FIND_VALUE&&ticker.getAsLong()-p.deadline<0&&p.current.getAsBoolean();
    }

    // ---- 周期・状態の変化 ----

    /** 期限切れの掃除と、探り・転送の周期処理。 */
    public void poll() {
        long now=ticker.getAsLong();
        List<Pending> dead=new ArrayList<>();
        var it=pending.values().iterator();
        while(it.hasNext()) {
            Pending p=it.next();
            if(now-p.deadline>=0||!p.current.getAsBoolean()){it.remove();dead.add(p);expired=inc(expired);}
        }
        for(Pending p:dead)expireOne(p);
        tickStarted();
        peers.tick();
        transfers.poll();
        if(managedTransfers!=null){managedTransfers.poll();managedStore.retry();}
        settleStarted();
    }

    /** 認証済みのセッションができた（作り直しを含む）。 */
    public void sessionStarted(byte[] peerId,byte[] sessionId) {
        DhtId peer=new DhtId(peerId);
        long now=tickStarted();
        Started s=started.get(peer);
        // どちらが始めたかは、started（自分が握手を始めた相手の覚え）と candidates().attemptFor(peer)（動いている試み）の両方で見分ける。
        // 両方あれば自分が始めた握手が通った。試みがなくなっていれば、相手からつなぎ直してきたものとして覚えから外す。
        if(s!=null) {
            Optional<DhtCandidates.Attempt> attempt=node.candidates().attemptFor(peer);
            if(attempt.isPresent()&&!s.sessionSeen) {
                // 自分が始めた握手が通った。探りの結果が出るまで試みは閉じない。
                node.candidates().answered(attempt.get());
                s.sessionSeen=true;s.lastActive=now;
            } else if(!s.sessionSeen||attempt.isEmpty()) {
                // 試みが動いていないのにセッションが始まった＝相手からつなぎ直してきた。自分が始めた相手の覚えから外す。
                started.remove(peer);
            }
        }
        peers.sessionStarted(peer,sessionId);
    }

    /** ネットワークが変わった。保留・探りの状態・転送を捨てる。通数の記録は残る（DhtPeers）。 */
    public void networkChanged(long sessionGeneration,LocalNetwork network) {
        node.networkChanged(sessionGeneration,network);
        generation=sessionGeneration;
        for(Pending p:pending.values())if(p.kind==Kind.STORE)storeListener.accept(p.peer,null);
        List<Pending> dropped=new ArrayList<>(pending.values());
        pending.clear();
        for(Pending p:dropped)finish(p,null);
        started.clear();releasedPeers.clear();
        peers.networkChanged();
        transfers.clear();
        if(managedTransfers!=null)managedTransfers.clear();
    }

    /** 揮発の相手を消した。 */
    public void volatilePeerForgotten(byte[] peerId) {
        DhtId peer=new DhtId(peerId);
        started.remove(peer);
        peers.forget(peer);
        responder.forget(peer);
        for(Pending p:pending.values())if(p.peer.equals(peer)&&p.kind==Kind.STORE)storeListener.accept(peer,null);
        List<Pending> dropped=new ArrayList<>();
        for(Pending p:pending.values())if(p.peer.equals(peer))dropped.add(p);
        pending.values().removeIf(p->p.peer.equals(peer));
        for(Pending p:dropped)finish(p,null);
        transfers.forget(peer);
        if(managedTransfers!=null)managedTransfers.forget(peer);
    }

    public Statistics statistics() {
        Statistics s=new Statistics(received,malformed,unauthenticated,wrongGroup,unsolicited,mismatched,expired,stale,
            peers.probesSent(),peers.yesCount(),peers.noCount());
        s.busy=busy;s.nothingReleasable=nothingReleasable;s.droppedStarted=droppedStarted;s.releasedNotYes=releasedNotYes;
        s.releasedOutside=releasedOutside;s.releasedCrowded=releasedCrowded;s.releasedNo=releasedNo;
        s.busyConcurrent=busyConcurrent;s.busyWindow=busyWindow;s.busyNothingReleasable=busyNothingReleasable;s.busyRecent30s=busyRecent30s;
        s.lookupsQueryLimit=node.lookupsQueryLimit();s.lookupsDeadline=node.lookupsDeadline();
        s.unavailableFailed=node.unavailableFailed();s.connectingTimedOut=node.connectingTimedOut();s.connectingReleased=node.connectingReleased();
        s.rehandshakeAfterRelease=rehandshakeAfterRelease;s.probeBudgetBlocked=peers.budgetBlocked();
        return s;
    }

    private static long inc(long n){return n==Long.MAX_VALUE?n:n+1;}

    @Override public String toString(){return "DHT dispatcher";}
}
