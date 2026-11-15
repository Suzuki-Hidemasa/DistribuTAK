// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** 包む前の同期状態。ディスクへの確定は呼び出し元が行い、成功前にはACKしない。 */
public final class SyncState {
    public static final int MAX_UIDS=4096,MAX_PLAINTEXT_BYTES=4194266;
    private static final String PURPOSE="distributak-sync-state-v1";
    public enum Origin { UNKNOWN,LOCAL_POSITION,LOCAL_CREATED,DISTRIBUTAK,EXTERNAL }
    private record Stored(CotRecord item,long until,int bytes,byte[] digest) {
        @Override public String toString() { return "Stored CoT"; }
    }
    private final byte[] group,local;
    private final Map<String,Stored> records=new LinkedHashMap<>();
    private final Map<String,Origin> origins=new LinkedHashMap<>();
    private long maximum=-1;
    private int recordBytes,originBytes,uids;
    public SyncState(byte[] groupId,byte[] localId) {
        Objects.requireNonNull(groupId);Crypto.length(localId,32);
        if(groupId.length==0)throw invalid();group=groupId.clone();local=localId.clone();
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("同期の保存状態が範囲外か壊れています"); }
    private static void uid(String uid) {
        int bytes=CotXml.utf8(uid).length;if(bytes==0||bytes>CotRecord.MAX_UID_BYTES)throw invalid();
    }
    public SyncState copy() {
        var result=new SyncState(group,local);result.records.putAll(records);result.origins.putAll(origins);result.maximum=maximum;result.recordBytes=recordBytes;result.originBytes=originBytes;result.uids=uids;return result;
    }
    public boolean belongsTo(byte[] groupId,byte[] localId) { return Crypto.equal(group,groupId)&&Crypto.equal(local,localId); }
    boolean localIdentity(byte[] id) { return Crypto.equal(local,id); }
    byte[] groupId(){return group.clone();}
    public long maximum() { return maximum; }
    public void maximum(long value) { if(value<maximum||value< -1)throw invalid();maximum=value; }
    public CotRecord get(String uid) { Stored stored=records.get(uid);return stored==null?null:stored.item; }
    void replaceBody(CotRecord item){
        Stored old=records.get(item.uid());if(old==null||!old.item.sameRecord(item)||old.item.hop()!=item.hop()||old.item.xmlSize()!=item.xmlSize())throw invalid();
        records.put(item.uid(),new Stored(item,old.until,old.bytes,old.digest));
    }
    public Origin origin(String uid) { return origins.getOrDefault(uid,Origin.UNKNOWN); }
    java.util.Set<String> localUids(){var result=new HashSet<String>();for(var entry:origins.entrySet())if(entry.getValue()==Origin.LOCAL_POSITION||entry.getValue()==Origin.LOCAL_CREATED)result.add(entry.getKey());return java.util.Set.copyOf(result);}
    public java.util.Set<String> receivedUids() {
        var result=new HashSet<String>();for(var entry:origins.entrySet())if(entry.getValue()==Origin.DISTRIBUTAK)result.add(entry.getKey());
        return java.util.Set.copyOf(result);
    }
    public void origin(String uid,Origin value) {
        if(value==Origin.EXTERNAL)throw invalid();
        uid(uid);Objects.requireNonNull(value);Origin old=origins.get(uid);
        int oldUids=uids;boolean known=records.containsKey(uid)||old!=null;
        int oldBytes=originBytes;originBytes+=SyncWire.originSize(uid,value)-SyncWire.originSize(uid,old==null?Origin.UNKNOWN:old);
        if(value==Origin.UNKNOWN)origins.remove(uid);else origins.put(uid,value);
        uids+=(records.containsKey(uid)||origins.containsKey(uid)?1:0)-(known?1:0);
        try { budget(); }
        catch(RuntimeException e) { uids=oldUids;originBytes=oldBytes;if(old==null)origins.remove(uid);else origins.put(uid,old);throw e; }
    }
    /** 新しい勝者だけを置く。同じ記録では削除の印の保管期限を延長しない。 */
    public boolean put(CotRecord item,long acceptedAt) {
        Objects.requireNonNull(item);if(acceptedAt<0||acceptedAt>Long.MAX_VALUE-CotXml.MAX_STALE_MILLIS)throw invalid();
        Stored old=records.get(item.uid());if(old!=null&&item.compareForWinner(old.item)<=0)return false;
        long until=item.deleted()?acceptedAt+CotXml.MAX_STALE_MILLIS:0;var next=new Stored(item,until,SyncWire.storedSize(item,until),storedDigest(item,until));
        int oldUids=uids;if(old==null&&!origins.containsKey(item.uid()))uids++;
        int oldBytes=recordBytes;recordBytes+=next.bytes-(old==null?0:old.bytes);records.put(item.uid(),next);
        try { budget();return true; }
        catch(RuntimeException e) { uids=oldUids;recordBytes=oldBytes;if(old==null)records.remove(item.uid());else records.put(item.uid(),old);throw e; }
    }
    /** 1件分だけ退避して、出所・記録・最大値をまとめて変更する。 */
    void apply(CotRecord item,long acceptedAt,Origin origin,long nextMaximum){
        String uid=item.uid();Stored old=records.get(uid);Origin oldOrigin=origins.get(uid);long oldMaximum=maximum;
        int oldRecords=recordBytes,oldOrigins=originBytes,oldUids=uids;
        try{origin(uid,origin);put(item,acceptedAt);maximum(nextMaximum);}
        catch(RuntimeException e){if(old==null)records.remove(uid);else records.put(uid,old);if(oldOrigin==null)origins.remove(uid);else origins.put(uid,oldOrigin);maximum=oldMaximum;recordBytes=oldRecords;originBytes=oldOrigins;uids=oldUids;throw e;}
    }
    private static byte[] storedEncoding(CotRecord item,long until){
        byte[] wire=SyncWire.encode(item);try{return SyncSchema.SyncStoredRecord.newBuilder().setEnvelope(SyncWire.parse(wire)).setTombstoneUntil(until).build().toByteArray();}finally{Crypto.wipe(wire);}
    }
    private static byte[] storedDigest(CotRecord item,long until){byte[] wire=storedEncoding(item,until);try{return Crypto.blake2s(wire);}finally{Crypto.wipe(wire);}}
    void wipeBodies(){for(Stored stored:records.values())stored.item.wipeXml();}
    private record Range(int offset,int length){}
    private byte[] header(){
        var value=SyncSchema.SyncSnapshot.newBuilder().setPurpose(PURPOSE).setGroupId(SyncWire.bytes(group)).setLocalId(SyncWire.bytes(local));
        if(maximum>=0)value.setHasMaximum(true).setMaximum(maximum);return value.build().toByteArray();
    }
    private static boolean sameRange(byte[] source,int offset,byte[] expected){
        if(offset<0||offset>source.length-expected.length)return false;for(int n=0;n<expected.length;n++)if(source[offset+n]!=expected[n])return false;return true;
    }
    private static byte[] rangeDigest(byte[] source,int offset,int length){
        var digest=new org.bouncycastle.crypto.digests.Blake2sDigest(256);digest.update(source,offset,length);byte[] result=new byte[32];digest.doFinal(result,0);return result;
    }
    private byte[] originField(String uid)throws IOException{
        byte[] body=SyncSchema.SyncOrigin.newBuilder().setUid(uid).setKind(origins.get(uid).ordinal()).build().toByteArray();
        byte[] field=new byte[CodedOutputStream.computeByteArraySize(7,body)];var out=CodedOutputStream.newInstance(field);out.writeByteArray(7,body);out.checkNoSpaceLeft();Crypto.wipe(body);return field;
    }
    /** 保存中だけ復号した正本を使う。本文を含む配列を複製・保持せず、範囲だけを数える。 */
    public byte[] encodeUsing(SyncState committed,byte[] primary){
        if(committed==null||!belongsTo(committed.group,committed.local)||primary==null||primary.length==0||primary.length>MAX_PLAINTEXT_BYTES)throw invalid();
        var previous=new LinkedHashMap<String,Range>();byte[] result=null,oldHeader=committed.header();
        try{
            if(!sameRange(primary,0,oldHeader))throw invalid();
            var input=CodedInputStream.newInstance(primary,oldHeader.length,primary.length-oldHeader.length);input.setSizeLimit(MAX_PLAINTEXT_BYTES);
            var names=new ArrayList<>(committed.records.keySet());names.sort(SyncState::compareUid);
            for(String uid:names){
                Stored old=committed.records.get(uid);int start=input.getTotalBytesRead();if(input.readTag()!=50)throw invalid();
                int length=input.readRawVarint32(),offset=oldHeader.length+input.getTotalBytesRead();
                if(length<0||offset>primary.length-length)throw invalid();input.skipRawBytes(length);
                if(input.getTotalBytesRead()-start!=old.bytes||!Crypto.equal(old.digest,rangeDigest(primary,offset,length)))throw invalid();previous.put(uid,new Range(offset,length));
            }
            names=new ArrayList<>(committed.origins.keySet());names.sort(SyncState::compareUid);
            for(String uid:names){byte[] field=committed.originField(uid);try{if(!sameRange(primary,oldHeader.length+input.getTotalBytesRead(),field))throw invalid();input.skipRawBytes(field.length);}finally{Crypto.wipe(field);}}
            if(!input.isAtEnd())throw invalid();
            result=new byte[encodedSize()];var out=CodedOutputStream.newInstance(result);byte[] currentHeader=header();try{out.writeRawBytes(currentHeader);}finally{Crypto.wipe(currentHeader);}
            names=new ArrayList<>(records.keySet());names.sort(SyncState::compareUid);
            for(String uid:names){Stored item=records.get(uid),old=committed.records.get(uid);Range range=previous.get(uid);
                if(old!=null&&Crypto.equal(item.digest,old.digest)&&range!=null){out.writeTag(6,2);out.writeUInt32NoTag(range.length);out.writeRawBytes(primary,range.offset,range.length);}
                else{byte[] wire=storedEncoding(item.item,item.until);try{out.writeByteArray(6,wire);}finally{Crypto.wipe(wire);}}
            }
            names=new ArrayList<>(origins.keySet());names.sort(SyncState::compareUid);
            for(String uid:names){byte[] field=originField(uid);try{out.writeRawBytes(field);}finally{Crypto.wipe(field);}}
            out.checkNoSpaceLeft();byte[] encoded=result;result=null;return encoded;
        }catch(IOException e){throw invalid();}finally{Crypto.wipe(result);Crypto.wipe(oldHeader);}
    }
    public boolean prune(long now) {
        if(now<0)throw invalid();boolean changed=false;var iterator=records.values().iterator();
        while(iterator.hasNext()) {
            Stored stored=iterator.next();
            if(now>=(stored.item.deleted()?stored.until:stored.item.stale())) { recordBytes-=stored.bytes;if(!origins.containsKey(stored.item.uid()))uids--;iterator.remove();changed=true; }
        }
        return changed;
    }
    public int uidCount() { return uids; }
    public List<CotRecord> records() { var result=new ArrayList<CotRecord>();for(Stored item:records.values())result.add(item.item);return List.copyOf(result); }
    private void budget() {
        if(uidCount()>MAX_UIDS||encodedSize()>MAX_PLAINTEXT_BYTES)throw invalid();
    }
    int encodedSize(){
        int base=CodedOutputStream.computeStringSize(1,PURPOSE)+CodedOutputStream.computeByteArraySize(2,group)+CodedOutputStream.computeByteArraySize(3,local);
        if(maximum>=0)base+=2+(maximum==0?0:CodedOutputStream.computeUInt64Size(4,maximum));
        return base+recordBytes+originBytes;
    }
    public byte[] encode() {
        var snapshot=SyncSchema.SyncSnapshot.newBuilder().setPurpose(PURPOSE).setGroupId(SyncWire.bytes(group)).setLocalId(SyncWire.bytes(local));
        if(maximum>=0)snapshot.setHasMaximum(true).setMaximum(maximum);
        var names=new ArrayList<>(records.keySet());names.sort(SyncState::compareUid);
        for(String name:names) {
            Stored item=records.get(name);snapshot.addRecords(SyncSchema.SyncStoredRecord.newBuilder()
                    .setEnvelope(SyncWire.parse(SyncWire.encode(item.item))).setTombstoneUntil(item.until));
        }
        names=new ArrayList<>(origins.keySet());names.sort(SyncState::compareUid);
        for(String name:names)snapshot.addOrigins(SyncSchema.SyncOrigin.newBuilder().setUid(name).setKind(origins.get(name).ordinal()));
        // getSerializedSizeで先に判定し、上限を超える最終配列は作らない。
        var value=snapshot.build();if(value.getSerializedSize()>MAX_PLAINTEXT_BYTES||value.getSerializedSize()!=encodedSize())throw invalid();return value.toByteArray();
    }
    static int compareUid(String a,String b) { return AdminRecords.compareBytes(CotXml.utf8(a),CotXml.utf8(b)); }
    public static SyncState decode(byte[] bytes,byte[] expectedGroup,byte[] expectedLocal) {
        if(bytes==null||bytes.length==0||bytes.length>MAX_PLAINTEXT_BYTES)throw invalid();
        try {
            SyncWire.preflightSnapshot(bytes);var input=CodedInputStream.newInstance(bytes);input.setSizeLimit(MAX_PLAINTEXT_BYTES);input.setRecursionLimit(16);
            var snapshot=SyncSchema.SyncSnapshot.parseFrom(input);input.checkLastTagWas(0);
            if(!input.isAtEnd()||!PURPOSE.equals(snapshot.getPurpose())||!Arrays.equals(expectedGroup,snapshot.getGroupId().toByteArray())
                    ||!Arrays.equals(expectedLocal,snapshot.getLocalId().toByteArray())||snapshot.getMaximum()<0
                    ||!snapshot.getHasMaximum()&&snapshot.getMaximum()!=0)throw invalid();
            var state=new SyncState(expectedGroup,expectedLocal);state.maximum=snapshot.getHasMaximum()?snapshot.getMaximum():-1;
            for(var stored:snapshot.getRecordsList()) {
                if(!stored.hasEnvelope())throw invalid();var item=SyncWire.decodeRecord(stored.getEnvelope().toByteArray());
                if(stored.getTombstoneUntil()<0||item.deleted()!=(stored.getTombstoneUntil()>0)
                        ||state.records.put(item.uid(),new Stored(item,stored.getTombstoneUntil(),SyncWire.storedSize(item,stored.getTombstoneUntil()),Crypto.blake2s(stored.toByteArray())))!=null)throw invalid();
                state.recordBytes+=SyncWire.storedSize(item,stored.getTombstoneUntil());
            }
            for(var origin:snapshot.getOriginsList()) {
                uid(origin.getUid());int kind=origin.getKind();
                if(kind<1||kind>=Origin.values().length||kind==Origin.EXTERNAL.ordinal()||state.origins.put(origin.getUid(),Origin.values()[kind])!=null)throw invalid();
                state.originBytes+=SyncWire.originSize(origin.getUid(),Origin.values()[kind]);
            }
            state.uids=state.records.size();for(String name:state.origins.keySet())if(!state.records.containsKey(name))state.uids++;
            if(state.uidCount()>MAX_UIDS||!Arrays.equals(bytes,state.encode()))throw invalid();return state;
        } catch(IOException e) { throw invalid(); }
    }
    @Override public String toString() { return "Sync state"; }
}
