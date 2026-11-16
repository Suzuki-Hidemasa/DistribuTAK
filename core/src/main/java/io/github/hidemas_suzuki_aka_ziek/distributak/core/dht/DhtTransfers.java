// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.function.LongSupplier;

/**
 * 大きな転送（最大3MiB。将来の管理記録用）の送り手と受け手（核C2）。1024バイトの断片に分け、窓4で送り、
 * 受け手が受けた断片の一覧（ビットマップ）をACKで返す。1秒で戻らない断片は最大3回送り直す。
 * 資源の上限: 相手ごと1件・全体2件（送りと受けでそれぞれ）・受け手の予約8MiB・最後に進んでから30秒・全体で240秒。
 * 同じグループの認証済みの端末だけが相手で、電波の区間には出ない。暗号は新しく足さない
 * （BLAKE2sは壊れの検出用で、認証には使わない）。DhtNodeと同じ1本のスレッドから呼ぶ。
 * 相手・番号・断片の中身は、ログにも文字列にも出さない。
 */
public final class DhtTransfers {
    @FunctionalInterface public interface Sender { boolean send(byte[] peerId,byte[] sessionId,byte[] plaintext); }
    /** 頼んだ FIND_VALUE の返事の転送だけを受けるための照会。 */
    @FunctionalInterface public interface ValueGate { boolean expected(DhtId peer,byte[] transferId); }
    /** 速度の袋（毎秒の補充と瞬間の上限）。断片とACKに使う。試験で差し替えられる。 */
    public static final class Limits {
        final int peerPerSecond,peerBurst,totalPerSecond,totalBurst;
        public Limits(int peerPerSecond,int peerBurst,int totalPerSecond,int totalBurst) {
            if(peerPerSecond<1||peerBurst<1||totalPerSecond<1||totalBurst<1)throw new IllegalArgumentException("Invalid limits");
            this.peerPerSecond=peerPerSecond;this.peerBurst=peerBurst;this.totalPerSecond=totalPerSecond;this.totalBurst=totalBurst;
        }
        public static Limits defaults(){return new Limits(200,400,400,800);}
        @Override public String toString(){return "DHT transfer limits";}
    }

    public static final int MAX_PER_PEER=1,MAX_ACTIVE=2,WINDOW=4,MAX_RETRIES=3,MAX_DONE=8,MAX_PEER_BUCKETS=256;
    public static final long RESERVE_BYTES=8L*1024*1024;
    private static final long SECOND=1_000_000_000L;
    static final long RETRY_NANOS=SECOND,PROGRESS_NANOS=30*SECOND,TOTAL_NANOS=240*SECOND,DONE_NANOS=30*SECOND;
    private static final byte[] LABEL="DistribuTAK/dht-transfer/v1".getBytes(StandardCharsets.UTF_8);
    private static final long TOKEN=SECOND;

    private static final class Key {
        final DhtId peer;final byte[] id;
        Key(DhtId peer,byte[] id){this.peer=peer;this.id=id.clone();}
        @Override public boolean equals(Object o){return o instanceof Key k&&k.peer.equals(peer)&&Arrays.equals(k.id,id);}
        @Override public int hashCode(){return 31*peer.hashCode()+Arrays.hashCode(id);}
    }
    private static final class Out {
        final DhtId peer;final byte[] session,id,digest,data;final DhtWire.TransferKind kind;final int count;
        final boolean[] acked,sent,inflight;final long[] sentAt;final int[] retries;
        int ackedCount,inflightCount;long started,lastProgress;
        Out(DhtId peer,byte[] session,DhtWire.TransferKind kind,byte[] id,byte[] digest,byte[] data,long now) {
            this.peer=peer;this.session=session.clone();this.kind=kind;this.id=id.clone();this.digest=digest;this.data=data;
            count=(data.length+DhtWire.PIECE_BYTES-1)/DhtWire.PIECE_BYTES;
            acked=new boolean[count];sent=new boolean[count];inflight=new boolean[count];sentAt=new long[count];retries=new int[count];
            started=now;lastProgress=now;
        }
    }
    private static final class In {
        final DhtId peer;final byte[] session,id,digest,buffer;final DhtWire.TransferKind kind;final int total,count;
        final long generation;final boolean managed;
        final boolean[] have;final TransferResources.Lease lease;int haveCount;long started,lastProgress;
        In(DhtId peer,byte[] session,DhtWire.Message m,long now,TransferResources.Lease lease,long generation,boolean managed) {
            this.generation=generation;this.managed=managed;this.lease=lease;
            this.peer=peer;this.session=session.clone();id=m.transferId();digest=m.digest();kind=m.transferKind();
            total=m.totalBytes();count=m.count();buffer=new byte[total];have=new boolean[count];started=now;lastProgress=now;
        }
    }
    private static final class Done {
        final byte[] session,digest;final int count,total;final DhtWire.TransferKind kind;final long until;
        /** digest が合わなかった転送。重複の断片にも ACK を返さない。 */
        final boolean corrupt;
        final long generation;final boolean managed;
        /** 完了後に返してよい全部受けたACKの残り数。送り手の送り直しの上限（断片ごとに最大 MAX_RETRIES+1 回）まで。 */
        int acksLeft;
        Done(In in,boolean corrupt,long until) {
            this.session=in.session.clone();this.digest=in.digest.clone();this.count=in.count;this.total=in.total;this.kind=in.kind;
            this.generation=in.generation;this.managed=in.managed;
            this.corrupt=corrupt;this.until=until;this.acksLeft=in.count*(MAX_RETRIES+1);
        }
    }
    private static final class Bucket {
        long tokens,last;final long rate,burst;
        Bucket(long rate,long burst,long now){this.rate=rate;this.burst=burst*TOKEN;this.tokens=this.burst;this.last=now;}
        boolean take(long now) {
            long elapsed=Math.max(0,Math.min(now-last,10*SECOND));last=now;
            tokens=Math.min(burst,tokens+elapsed*rate);
            if(tokens<TOKEN)return false;
            tokens-=TOKEN;return true;
        }
    }

    private final byte[] group;
    private final Sender sender;
    private final LongSupplier ticker;
    private final Random random;
    private final DhtTransferSink sink;
    private final ManagedTransferSink managedSink;
    private final ValueGate gate;
    private final Limits limits;
    private final TransferResources resources;
    private final Map<Key,Out> outs=new LinkedHashMap<>();
    private final Map<Key,In> ins=new LinkedHashMap<>();
    private final Map<Key,Done> done=new LinkedHashMap<>();
    private final LinkedHashMap<DhtId,Bucket> peerBuckets=new LinkedHashMap<>();
    private Bucket total;
    private long reserved;
    private long completedIn,completedOut,failedOut,abandonedIn,rateLimited,rejected,unsupported,mismatched,corrupt;

    public DhtTransfers(byte[] group,Sender sender,LongSupplier ticker,Random random,DhtTransferSink sink,ValueGate gate,Limits limits) {
        this(group,sender,ticker,random,sink,gate,limits,new TransferResources());
    }
    /**
     * 管理ページと受信予約だけを共有する。既存の速度予算と、既定の入口の挙動は変えない。
     * <p>
     * Shares only receive reservations with management pages, preserving existing rate budgets and default-entry behavior.
     */
    public DhtTransfers(byte[] group,Sender sender,LongSupplier ticker,Random random,DhtTransferSink sink,ValueGate gate,Limits limits,
            TransferResources resources) {
        this(group,sender,ticker,random,sink,gate,limits,resources,null);
    }

    /**
     * 管理用の渡し先を追加する。旧入口は引き続き旧渡し先だけに渡す。
     * <p>
     * Adds a managed sink; the legacy entry continues to use only the legacy sink.
     */
    public DhtTransfers(byte[] group,Sender sender,LongSupplier ticker,Random random,DhtTransferSink sink,ValueGate gate,Limits limits,
            TransferResources resources,ManagedTransferSink managedSink) {
        this.managedSink=managedSink;
        this.group=Objects.requireNonNull(group).clone();this.sender=Objects.requireNonNull(sender);this.ticker=Objects.requireNonNull(ticker);
        this.random=Objects.requireNonNull(random);this.sink=sink;this.gate=Objects.requireNonNull(gate);this.limits=Objects.requireNonNull(limits);
        this.resources=Objects.requireNonNull(resources);
    }

    static byte[] digestOf(byte[] data) {
        return Crypto.blake2s(Crypto.concat(LABEL,data));
    }


    /** 送り始める。自分で転送の番号を作る。断られたら null。 */
    public byte[] start(DhtId peer,byte[] session,DhtWire.TransferKind kind,byte[] data) {
        byte[] id=new byte[DhtWire.REQUEST_BYTES];random.nextBytes(id);
        return start(peer,session,kind,id,data)?id:null;
    }
    /** 転送の番号を決めて送り始める（VALUE の転送は FIND_VALUE の request_id と同じ番号を使う）。 */
    public boolean start(DhtId peer,byte[] session,DhtWire.TransferKind kind,byte[] id,byte[] data) {
        Objects.requireNonNull(peer);Objects.requireNonNull(session);Objects.requireNonNull(kind);Objects.requireNonNull(id);Objects.requireNonNull(data);
        if(id.length!=DhtWire.REQUEST_BYTES||data.length<1||data.length>DhtWire.MAX_TRANSFER_BYTES)return false;
        if(outs.size()>=MAX_ACTIVE||outCountFor(peer)>=MAX_PER_PEER)return false;
        long now=ticker.getAsLong();
        Out out=new Out(peer,session,kind,id,digestOf(data),data.clone(),now);
        Key key=new Key(peer,id);
        outs.put(key,out);
        if(!fill(out,now)) {
            outs.remove(key);failedOut=inc(failedOut);return false;
        }
        return true;
    }

    /** 認証済みの相手から来た TRANSFER・TRANSFER_ACK を処理する。 */
    public void receive(DhtId peer,byte[] session,DhtWire.Message m) {
        receive(peer,session,0,m,false);
    }

    /**
     * 世代を組立と完成済みの覚えに結び付け、管理用の全体を専用の渡し先へ渡す。
     * <p>
     * Binds assembly and completed-transfer memory to a generation and delivers managed whole records to their sink.
     */
    public void receive(DhtId peer,byte[] session,long generation,DhtWire.Message m) {
        receive(peer,session,generation,m,managedSink!=null);
    }

    private void receive(DhtId peer,byte[] session,long generation,DhtWire.Message m,boolean managed) {
        Objects.requireNonNull(peer);Objects.requireNonNull(session);Objects.requireNonNull(m);
        long now=ticker.getAsLong();
        if(!admit(peer,now)){rateLimited=inc(rateLimited);return;}
        if(m.op()==DhtWire.Op.TRANSFER)onPiece(peer,session,m,now,generation,managed);
        else if(m.op()==DhtWire.Op.TRANSFER_ACK)onAck(peer,session,m,now);
    }

    /** 周期の処理。送り直し・締切・完了の覚えの期限。 */
    public void poll() {
        long now=ticker.getAsLong();
        Iterator<Out> oi=outs.values().iterator();
        while(oi.hasNext()) {
            Out o=oi.next();
            if(now-o.started>=TOTAL_NANOS||now-o.lastProgress>=PROGRESS_NANOS||!resend(o,now)) {
                oi.remove();failedOut=inc(failedOut);
            }
        }
        Iterator<In> ii=ins.values().iterator();
        while(ii.hasNext()) {
            In i=ii.next();
            if(now-i.started>=TOTAL_NANOS||now-i.lastProgress>=PROGRESS_NANOS) {
                release(i);ii.remove();abandonedIn=inc(abandonedIn);
            }
        }
        done.values().removeIf(d->now-d.until>=0);
    }

    /** 相手のセッションが消えた。その相手との転送をやめる。 */
    public void forget(DhtId peer) {
        outs.values().removeIf(o->o.peer.equals(peer));
        Iterator<In> ii=ins.values().iterator();
        while(ii.hasNext()) {
            In i=ii.next();
            if(i.peer.equals(peer)){release(i);ii.remove();abandonedIn=inc(abandonedIn);}
        }
        done.keySet().removeIf(k->k.peer.equals(peer));peerBuckets.remove(peer);
    }
    /** ネットワークが変わった。全部やめる。 */
    public void clear() {
        for(In in:ins.values())in.lease.close();
        outs.clear();ins.clear();done.clear();peerBuckets.clear();reserved=0;
    }

    public int activeOut(){return outs.size();}
    public int activeIn(){return ins.size();}
    /**
     * この DhtTransfers の分だけの受信予約バイト数。共有枠の総量ではない。
     * <p>
     * Receive reservation bytes owned only by this DhtTransfers, rather than the shared pool total.
     */
    public long reservedBytes(){return reserved;}
    public long completedIn(){return completedIn;}
    public long completedOut(){return completedOut;}
    public long failedOut(){return failedOut;}
    public long abandonedIn(){return abandonedIn;}
    public long rateLimited(){return rateLimited;}
    public long rejected(){return rejected;}
    public long unsupported(){return unsupported;}
    public long mismatched(){return mismatched;}
    public long corrupt(){return corrupt;}
    boolean hasIn(DhtId peer,byte[] id){return ins.containsKey(new Key(peer,id));}
    /** その相手との転送（送り・受け）が動いているか。手放してよいかの判定に使う。 */
    boolean usesPeer(DhtId peer){return outCountFor(peer)!=0||inCountFor(peer)!=0;}

    private int outCountFor(DhtId peer) {
        int n=0;
        for(Out o:outs.values())if(o.peer.equals(peer))n++;
        return n;
    }
    private int inCountFor(DhtId peer) {
        int n=0;
        for(In i:ins.values())if(i.peer.equals(peer))n++;
        return n;
    }
    private boolean admit(DhtId peer,long now) {
        if(total==null)total=new Bucket(limits.totalPerSecond,limits.totalBurst,now);
        Bucket mine=peerBuckets.remove(peer);
        if(mine==null)mine=new Bucket(limits.peerPerSecond,limits.peerBurst,now);
        peerBuckets.put(peer,mine);
        while(peerBuckets.size()>MAX_PEER_BUCKETS){Iterator<DhtId> it=peerBuckets.keySet().iterator();it.next();it.remove();}
        // 相手の袋で先に断ち、全体の袋を使い切らせない。
        if(!mine.take(now))return false;
        return total.take(now);
    }

    // ---- 送り手 ----
    private boolean piece(Out o,int index,long now) {
        int from=index*DhtWire.PIECE_BYTES,to=Math.min(o.data.length,from+DhtWire.PIECE_BYTES);
        byte[] bytes;
        try {
            bytes=DhtWire.transfer(group,o.kind,o.id,o.digest,o.data.length,index,o.count,Arrays.copyOfRange(o.data,from,to));
            if(!sender.send(o.peer.bytes(),o.session,bytes))return false;
        } catch(RuntimeException failed) {
            return false;
        }
        if(!o.sent[index]){o.sent[index]=true;}
        if(!o.inflight[index]){o.inflight[index]=true;o.inflightCount++;}
        o.sentAt[index]=now;
        return true;
    }
    /** 窓に空きがあれば、まだ送っていない断片を送る。最初の断片が送れなければ false。 */
    private boolean fill(Out o,long now) {
        boolean any=false;
        for(int i=0;i<o.count&&o.inflightCount<WINDOW;i++) {
            if(o.acked[i]||o.sent[i])continue;
            if(!piece(o,i,now))return any;
            any=true;
        }
        return any||o.inflightCount>0||o.ackedCount==o.count;
    }
    private boolean resend(Out o,long now) {
        for(int i=0;i<o.count;i++) {
            if(!o.inflight[i]||now-o.sentAt[i]<RETRY_NANOS)continue;
            if(o.retries[i]>=MAX_RETRIES)return false;
            o.retries[i]++;
            if(!piece(o,i,now))return false;
        }
        return true;
    }
    private void onAck(DhtId peer,byte[] session,DhtWire.Message m,long now) {
        Key key=new Key(peer,m.transferId());
        Out o=outs.get(key);
        if(o==null){mismatched=inc(mismatched);return;}
        if(!Arrays.equals(o.session,session)||!Arrays.equals(o.digest,m.digest())||o.count!=m.count()){mismatched=inc(mismatched);return;}
        byte[] bits=m.received();
        boolean progressed=false;
        for(int i=0;i<o.count;i++) {
            boolean set=(bits[i>>3]&(1<<(i&7)))!=0;
            if(!set||o.acked[i]||!o.sent[i])continue;
            o.acked[i]=true;o.ackedCount++;progressed=true;
            if(o.inflight[i]){o.inflight[i]=false;o.inflightCount--;}
        }
        if(progressed)o.lastProgress=now;
        if(o.ackedCount==o.count) {
            outs.remove(key);completedOut=inc(completedOut);return;
        }
        if(!fill(o,now)&&o.inflightCount==0) {
            outs.remove(key);failedOut=inc(failedOut);
        }
    }

    // ---- 受け手 ----
    private void onPiece(DhtId peer,byte[] session,DhtWire.Message m,long now,long generation,boolean managed) {
        if(managed&&(!Arrays.equals(group,m.groupId())||session.length!=16)){rejected=inc(rejected);return;}
        Key key=new Key(peer,m.transferId());
        Done finished=done.get(key);
        if(finished!=null) {
            // 完了後は、同じ転送の断片の重複に、全部受けたACKを返す（ACKが落ちたとき、送り手が失敗にしないため）。
            // 返す数には上限がある。壊れた転送には返さない。digest・総バイト数・種類が合うものにだけ返す。
            if(now-finished.until<0&&!finished.corrupt&&finished.managed==managed&&finished.generation==generation&&Arrays.equals(finished.session,session)&&finished.count==m.count()
                &&finished.total==m.totalBytes()&&finished.kind==m.transferKind()&&Arrays.equals(finished.digest,m.digest())&&finished.acksLeft>0) {
                finished.acksLeft--;
                byte[] all=new byte[(m.count()+7)/8];
                for(int i=0;i<m.count();i++)all[i>>3]|=(byte)(1<<(i&7));
                ack(peer,session,m.transferId(),m.digest(),m.count(),all);
            }
            return;
        }
        In in=ins.get(key);
        if(in==null) {
            if(managed?managedSink==null:sink==null){unsupported=inc(unsupported);return;}
            if(m.transferKind()==DhtWire.TransferKind.VALUE&&!gate.expected(peer,m.transferId())){rejected=inc(rejected);return;}
            var lease=resources.acquire(peer,m.totalBytes());
            if(lease==null){rejected=inc(rejected);return;}
            try{in=new In(peer,session,m,now,lease,generation,managed);}
            catch(RuntimeException|Error failure){lease.close();throw failure;}
            reserved+=in.total;ins.put(key,in);
        } else if(in.managed!=managed||in.generation!=generation||!Arrays.equals(in.session,session)||!Arrays.equals(in.digest,m.digest())||in.total!=m.totalBytes()||in.count!=m.count()||in.kind!=m.transferKind()) {
            mismatched=inc(mismatched);return;
        }
        int index=m.index();
        if(!in.have[index]) {
            byte[] piece=m.piece();
            System.arraycopy(piece,0,in.buffer,index*DhtWire.PIECE_BYTES,piece.length);
            in.have[index]=true;in.haveCount++;in.lastProgress=now;
        }
        if(in.haveCount==in.count) {
            // 最後の断片：先に digest を照合し、合ったときだけ全ビットの ACK を返す。
            finish(key,in,now);
            return;
        }
        ack(peer,session,in.id,in.digest,in.count,bitmap(in));
    }
    private static byte[] bitmap(In in) {
        byte[] bits=new byte[(in.count+7)/8];
        for(int i=0;i<in.count;i++)if(in.have[i])bits[i>>3]|=(byte)(1<<(i&7));
        return bits;
    }
    private void ack(DhtId peer,byte[] session,byte[] id,byte[] digest,int count,byte[] bits) {
        try{sender.send(peer.bytes(),session,DhtWire.transferAck(group,id,digest,count,bits));}catch(RuntimeException ignored){/* ACKは送り直しで補う */}
    }
    private void finish(Key key,In in,long now) {
        ins.remove(key);release(in);
        boolean ok=Crypto.equal(digestOf(in.buffer),in.digest);
        if(done.size()>=MAX_DONE){Iterator<Key> it=done.keySet().iterator();it.next();it.remove();}
        done.put(key,new Done(in,!ok,now+DONE_NANOS));
        if(!ok){corrupt=inc(corrupt);return;}
        ack(in.peer,in.session,in.id,in.digest,in.count,bitmap(in));
        completedIn=inc(completedIn);
        if(in.managed){
            ManagedTransferResult result;
            ManagedDhtRecord record;
            try{record=ManagedDhtRecord.verifyStructure(in.buffer,group);}
            catch(RuntimeException invalid){notifyManaged(in,ManagedTransferResult.REJECTED);return;}
            var context=new ManagedTransferContext(in.peer,in.session,in.generation,in.id,record.key(),in.kind);
            try{result=Objects.requireNonNull(managedSink.accept(context,record));}
            catch(RuntimeException failed){result=ManagedTransferResult.FAILED;}
            notifyManaged(in,result);return;
        }
        try{sink.accept(in.peer,in.kind,in.buffer);}catch(RuntimeException ignored){/* 渡し先の失敗は転送の結果に影響しない */}
    }
    private void notifyManaged(In in,ManagedTransferResult result) {
        try{managedSink.completed(in.peer,in.session.clone(),in.generation,in.kind,in.id.clone(),result);}
        catch(RuntimeException ignored){
            // 通知の失敗でも、解放済みの受信枠と配送 ACK は戻さない。
            // A failed notification does not restore released receive resources or undo delivery ACKs.
        }
    }
    private static long inc(long v){return v==Long.MAX_VALUE?v:v+1;}
    private void release(In in){in.lease.close();reserved-=in.total;}
    List<DhtId> activePeers() {
        List<DhtId> list=new ArrayList<>();
        for(Out o:outs.values())list.add(o.peer);
        for(In i:ins.values())list.add(i.peer);
        return list;
    }
    @Override public String toString(){return "DHT transfers";}
}
