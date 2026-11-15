// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.LongSupplier;
import org.bouncycastle.util.encoders.Hex;

/** 認証済みの相手とセッションごとの分割。呼び出し元の一つのスレッドで使う。 */
public final class SyncFragments implements AutoCloseable {
    public static final int PIECE_BYTES=1024,MAX_PIECES=72,MAX_PENDING=8;
    public static final long LIFETIME_NANOS=10_000_000_000L,REPLY_NANOS=1_000_000_000L;
    private static final int PEER_BYTES=144*1024,TOTAL_BYTES=576*1024,COMPLETED_BYTES=1024*1024;
    private final LongSupplier ticker;
    private final Map<String,Partial> pending=new LinkedHashMap<>();
    private final Map<String,Completed> completed=new LinkedHashMap<>();
    private int reserved,replyBytes;
    private boolean closed;
    private record Header(byte[] transfer,byte[] digest,int total,int count) {
        boolean same(Header other) {
            return total==other.total&&count==other.count&&Arrays.equals(transfer,other.transfer)&&Arrays.equals(digest,other.digest);
        }
        @Override public String toString() { return "Fragment header"; }
    }
    private static final class Partial {
        final String peer;final Header header;final long started;final byte[] bytes;final BitSet received=new BitSet(MAX_PIECES);
        Partial(String peer,Header header,long now) { this.peer=peer;this.header=header;started=now;bytes=new byte[header.total]; }
    }
    private static final class Completed {
        final String peer;final Header header;final long started;final List<byte[]> replies;final int size;long lastReply;
        Completed(String peer,Header header,long now,List<byte[]> replies,int size) {
            this.peer=peer;this.header=header;started=now;lastReply=now;this.replies=replies;this.size=size;
        }
        void clear() { for(byte[] bytes:replies)Crypto.wipe(bytes); }
    }
    /** 保存待ちには本文を残さず、この短い記録だけを持つ。 */
    public static final class Receipt {
        private final String key,peer;private final Header header;
        private Receipt(String key,String peer,Header header){this.key=key;this.peer=peer;this.header=header;}
        @Override public String toString(){return "Fragment receipt";}
    }
    /** messageがnullなら、完成済みの転送への返事だけ。使用後にcloseして本文の配列を消す。 */
    public static final class Result implements AutoCloseable {
        private final String key,peer;private final Header header;private final byte[] message;private final List<byte[]> replies;
        private boolean closed;
        private Result(String key,String peer,Header header,byte[] message,List<byte[]> replies) {
            this.key=key;this.peer=peer;this.header=header;this.message=message;this.replies=replies;
        }
        public byte[] message() { open();return message==null?null:message.clone(); }
        public List<byte[]> replies() { open();return copies(replies); }
        private void open() { if(closed)throw new IllegalStateException("受信した転送は閉じています"); }
        @Override public void close() { if(!closed) { closed=true;Crypto.wipe(message);for(byte[] bytes:replies)Crypto.wipe(bytes); } }
        @Override public String toString() { return "Fragment result"; }
    }
    public SyncFragments(LongSupplier monotonicNanos) { ticker=Objects.requireNonNull(monotonicNanos); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("分割した同期の値が範囲外です"); }
    private void open() { if(closed)throw new IllegalStateException("同期の組み立ては閉じています"); }
    private static List<byte[]> copies(List<byte[]> source) {
        var result=new ArrayList<byte[]>(source.size());for(byte[] bytes:source)result.add(bytes.clone());return List.copyOf(result);
    }
    private static byte[] digest(byte[] message) {
        byte[] input=Crypto.concat("DTK-SYNC-TRANSFER-v1\0".getBytes(StandardCharsets.US_ASCII),message);
        try { return Crypto.blake2s(input); } finally { Crypto.wipe(input); }
    }
    public static List<byte[]> split(byte[] message,byte[] transferId) {
        Crypto.length(transferId,16);
        if(message==null||message.length>SyncWire.MAX_MESSAGE_BYTES||SyncWire.parse(message).hasFragment())throw invalid();
        if(message.length<=SessionPacket.MAX_PLAINTEXT)return List.of(message.clone());
        int count=(message.length+PIECE_BYTES-1)/PIECE_BYTES;byte[] digest=digest(message);var result=new ArrayList<byte[]>(count);
        try {
            for(int index=0;index<count;index++) {
                byte[] piece=Arrays.copyOfRange(message,index*PIECE_BYTES,Math.min(message.length,(index+1)*PIECE_BYTES));
                try {
                    byte[] frame=SyncWire.envelope().setFragment(SyncSchema.SyncFragment.newBuilder().setTransferId(SyncWire.bytes(transferId))
                            .setDigest(SyncWire.bytes(digest)).setTotalBytes(message.length).setIndex(index).setCount(count).setPayload(SyncWire.bytes(piece))).build().toByteArray();
                    if(frame.length>SessionPacket.MAX_PLAINTEXT)throw invalid();result.add(frame);
                } finally { Crypto.wipe(piece); }
            }
            return List.copyOf(result);
        } finally { Crypto.wipe(digest); }
    }
    private static Header header(SyncSchema.SyncFragment fragment) {
        int total=fragment.getTotalBytes(),count=fragment.getCount(),index=fragment.getIndex();
        if(fragment.getTransferId().size()!=16||fragment.getDigest().size()!=32
                ||total<=SessionPacket.MAX_PLAINTEXT||total>SyncWire.MAX_MESSAGE_BYTES||count<2||count>MAX_PIECES
                ||count!=(total+PIECE_BYTES-1)/PIECE_BYTES||index<0||index>=count
                ||fragment.getPayload().size()!=Math.min(PIECE_BYTES,total-index*PIECE_BYTES))throw invalid();
        return new Header(fragment.getTransferId().toByteArray(),fragment.getDigest().toByteArray(),total,count);
    }
    public Result accept(byte[] peerId,byte[] sessionId,byte[] wire) {
        open();Crypto.length(peerId,32);Crypto.length(sessionId,16);
        if(wire==null||wire.length>SessionPacket.MAX_PLAINTEXT)throw invalid();expire();
        var envelope=SyncWire.parse(wire);
        if(!envelope.hasFragment())return new Result(null,null,null,wire.clone(),List.of());
        var fragment=envelope.getFragment();Header header=header(fragment);
        String peer=Hex.toHexString(peerId),key=peer+":"+Hex.toHexString(sessionId)+":"+Hex.toHexString(header.transfer);
        long now=ticker.getAsLong();Completed done=completed.get(key);
        if(done!=null) {
            if(!done.header.same(header))throw invalid();
            if(now-done.lastReply<REPLY_NANOS)return null;
            done.lastReply=now;return new Result(key,peer,header,null,copies(done.replies));
        }
        Partial partial=pending.get(key);
        if(partial!=null&&!partial.header.same(header)) { removePartial(key,true);throw invalid(); }
        if(partial==null) {
            int peers=0,peerBytes=0;
            for(Partial item:pending.values())if(item.peer.equals(peer)) { peers++;peerBytes+=item.header.total; }
            if(peers>=2||pending.size()>=MAX_PENDING||peerBytes+header.total>PEER_BYTES||reserved+header.total>TOTAL_BYTES)throw invalid();
            partial=new Partial(peer,header,now);pending.put(key,partial);reserved+=header.total;
        }
        int index=fragment.getIndex(),offset=index*PIECE_BYTES;byte[] piece=fragment.getPayload().toByteArray();
        try {
            if(partial.received.get(index)) {
                for(int n=0;n<piece.length;n++)if(partial.bytes[offset+n]!=piece[n]) { removePartial(key,true);throw invalid(); }
                return null;
            }
            System.arraycopy(piece,0,partial.bytes,offset,piece.length);partial.received.set(index);
        } finally { Crypto.wipe(piece); }
        if(partial.received.cardinality()!=header.count)return null;
        byte[] message=partial.bytes;removePartial(key,false);byte[] computed=digest(message);
        try {
            if(!Crypto.equal(computed,header.digest)||SyncWire.parse(message).hasFragment())throw invalid();
            return new Result(key,peer,header,message,List.of());
        } catch(RuntimeException e) { Crypto.wipe(message);throw e; }
        finally { Crypto.wipe(computed); }
    }
    /** 保存が成功したあとだけ呼ぶ。Inventoryへの固定したRequestもここで覚える。 */
    public void remember(Result result,List<byte[]> replies) {
        remember(receipt(result),replies);
    }
    public Receipt receipt(Result result){
        open();result.open();return result.key==null||result.message==null?null:new Receipt(result.key,result.peer,result.header);
    }
    public void remember(Receipt result,List<byte[]> replies) {
        open();if(result==null)return;expire();
        int size=1024;
        for(byte[] reply:replies) {
            if(reply==null||reply.length>SyncWire.MAX_MESSAGE_BYTES)throw invalid();
            if(size>COMPLETED_BYTES-reply.length-32)return;size+=reply.length+32;
        }
        Completed old=completed.remove(result.key);if(old!=null) { replyBytes-=old.size;old.clear(); }
        while(completed.size()>=256||peerCompleted(result.peer)>=32||replyBytes+size>COMPLETED_BYTES) {
            Iterator<Completed> iterator=completed.values().iterator();if(!iterator.hasNext())return;
            Completed removed=iterator.next();iterator.remove();replyBytes-=removed.size;removed.clear();
        }
        completed.put(result.key,new Completed(result.peer,result.header,ticker.getAsLong(),copies(replies),size));replyBytes+=size;
    }
    private int peerCompleted(String peer) { int count=0;for(Completed item:completed.values())if(item.peer.equals(peer))count++;return count; }
    private void removePartial(String key,boolean wipe) {
        Partial removed=pending.remove(key);if(removed!=null) { reserved-=removed.header.total;if(wipe)Crypto.wipe(removed.bytes); }
    }
    public void expire() {
        if(closed)return;long now=ticker.getAsLong();
        var partials=pending.values().iterator();
        while(partials.hasNext()) { Partial item=partials.next();if(now-item.started>=LIFETIME_NANOS) { partials.remove();reserved-=item.header.total;Crypto.wipe(item.bytes); } }
        var receipts=completed.values().iterator();
        while(receipts.hasNext()) { Completed item=receipts.next();if(now-item.started>=LIFETIME_NANOS) { receipts.remove();replyBytes-=item.size;item.clear(); } }
    }
    public void forget(byte[] peerId,byte[] sessionId) {
        Crypto.length(peerId,32);Crypto.length(sessionId,16);String prefix=Hex.toHexString(peerId)+":"+Hex.toHexString(sessionId)+":";
        var keys=new ArrayList<>(pending.keySet());for(String key:keys)if(key.startsWith(prefix))removePartial(key,true);
        var receipts=completed.entrySet().iterator();
        while(receipts.hasNext()) { var entry=receipts.next();if(entry.getKey().startsWith(prefix)) { replyBytes-=entry.getValue().size;entry.getValue().clear();receipts.remove(); } }
    }
    public int pendingCount() { expire();return pending.size(); }
    public int reservedBytes() { expire();return reserved; }
    public int completedCount() { expire();return completed.size(); }
    public int completedBytes() { expire();return replyBytes; }
    @Override public void close() {
        if(closed)return;closed=true;for(Partial item:pending.values())Crypto.wipe(item.bytes);
        for(Completed item:completed.values())item.clear();pending.clear();completed.clear();reserved=0;replyBytes=0;
    }
}
