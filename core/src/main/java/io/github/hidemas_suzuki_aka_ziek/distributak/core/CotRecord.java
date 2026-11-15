// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/** 同期する一つの記録。XMLの写しとhashは最初の生成時のまま保持する。 */
public final class CotRecord {
    public static final int MAX_UID_BYTES=256,MAX_HOP=16;
    private final String uid;
    private final long time,stale;
    private final byte[] author,xml,hash;
    private final ColdBody body;private final int xmlLength;
    private final boolean deleted;
    private final int hop;
    private CotRecord(String uid,long time,byte[] author,long stale,byte[] xml,boolean deleted,int hop) {
        byte[] name=CotXml.utf8(uid);Crypto.length(author,32);
        if(name.length==0||name.length>MAX_UID_BYTES||time<0||stale<0||hop<0||hop>MAX_HOP)
            throw new IllegalArgumentException("同期の記録の値が範囲外です");
        if(!deleted) {
            var fields=CotXml.inspect(xml);
            if(!uid.equals(fields.uid())||stale!=fields.stale())throw new IllegalArgumentException("同期の記録と CoT が一致しません");
        }
        this.uid=uid;this.time=time;this.author=author.clone();this.stale=stale;
        this.xml=xml.clone();body=null;xmlLength=xml.length;this.deleted=deleted;this.hop=hop;
        byte[] prefix="DTK-SYNC-RECORD-v1\0".getBytes(StandardCharsets.US_ASCII);
        var encoded=ByteBuffer.allocate(prefix.length+1+4+name.length+8+32+8+4+xml.length);
        encoded.put(prefix).put((byte)(deleted?2:1)).putInt(name.length).put(name).putLong(time).put(author);
        encoded.putLong(stale).putInt(xml.length).put(xml);
        hash=Crypto.blake2s(encoded.array());Crypto.wipe(encoded.array());
    }
    private CotRecord(CotRecord source,int hop) {
        uid=source.uid;time=source.time;stale=source.stale;author=source.author;xml=source.xml;body=source.body;xmlLength=source.xmlLength;hash=source.hash;deleted=source.deleted;this.hop=hop;
    }
    private CotRecord(CotRecord source,ColdBody body){
        uid=source.uid;time=source.time;stale=source.stale;author=source.author;xml=null;xmlLength=source.xmlLength;hash=source.hash;deleted=source.deleted;hop=source.hop;this.body=body;
    }
    private static final class ColdBody {
        final SyncCache cache;final java.util.function.Supplier<byte[]> restore;final byte[] digest;final int length;SyncCache.Ref ref;
        ColdBody(SyncCache cache,SyncCache.Ref ref,byte[] digest,int length,java.util.function.Supplier<byte[]> restore){this.cache=cache;this.ref=ref;this.digest=digest;this.length=length;this.restore=restore;}
        byte[] read(){
            byte[] value=cache.get(ref);if(value!=null)return value;
            value=restore.get();if(value==null||value.length!=length||!Crypto.equal(Crypto.blake2s(value),digest)){Crypto.wipe(value);throw new IllegalStateException("同期の正本を復元できません");}
            ref=cache.put("xml",value,SyncState.MAX_UIDS);return value;
        }
    }
    boolean cold(){return body!=null;}
    SyncCache.Ref cacheRef(){return body==null?null:body.ref;}
    CotRecord offload(SyncCache cache,java.util.function.Supplier<byte[]> restore){
        if(body!=null||deleted)return this;var ref=cache.put("xml",xml,SyncState.MAX_UIDS);if(ref==null)return this;
        return new CotRecord(this,new ColdBody(cache,ref,Crypto.blake2s(xml),xmlLength,restore));
    }
    void prefetch(){if(body!=null){byte[] value=body.read();Crypto.wipe(value);}}
    /** mainへ渡す前にworkerで中身を確定する。 */
    public CotRecord materialize(){if(body==null)return this;byte[] value=xml();try{return record(uid,time,author,stale,value,hop);}finally{Crypto.wipe(value);}}
    public static CotRecord record(String uid,long time,byte[] author,long stale,byte[] xml,int hop) {
        Objects.requireNonNull(xml);return new CotRecord(uid,time,author,stale,xml,false,hop);
    }
    public static CotRecord tombstone(String uid,long time,byte[] author,int hop) {
        return new CotRecord(uid,time,author,0,new byte[0],true,hop);
    }
    public String uid() { return uid; }
    public long time() { return time; }
    public long stale() { return stale; }
    public byte[] author() { return author.clone(); }
    public byte[] xml() { return body==null?xml.clone():body.read(); }
    int xmlSize(){return xmlLength;}
    void wipeXml(){if(body==null)Crypto.wipe(xml);}
    public byte[] hash() { return hash.clone(); }
    public boolean deleted() { return deleted; }
    public int hop() { return hop; }
    public void validateAt(long now) {
        if(now<0||time>now&&time-now>CotXml.MAX_FUTURE_MILLIS
                ||!deleted&&(stale<=now||stale-now>CotXml.MAX_STALE_MILLIS))
            throw new IllegalArgumentException("同期の記録の時刻が範囲外です");
    }
    public CotRecord relay() {
        if(hop>=MAX_HOP)throw new IllegalArgumentException("配り直しの上限です");return new CotRecord(this,hop+1);
    }
    /** 正ならこの記録を残す。同じ版ではhashが小さい方。削除も同じ順で比べる。 */
    public int compareForWinner(CotRecord other) {
        if(!uid.equals(other.uid))throw new IllegalArgumentException("違う記録は比較できません");
        int result=Long.compare(time,other.time);
        if(result==0)result=AdminRecords.compareBytes(author,other.author);
        return result!=0?result:-AdminRecords.compareBytes(hash,other.hash);
    }
    public boolean sameRecord(CotRecord other) {
        return other!=null&&uid.equals(other.uid)&&time==other.time&&Arrays.equals(author,other.author)&&Arrays.equals(hash,other.hash);
    }
    @Override public String toString() { return "CoT record"; }
}
