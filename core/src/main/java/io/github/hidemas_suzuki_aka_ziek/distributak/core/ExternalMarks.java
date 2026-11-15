// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.TreeMap;
import org.bouncycastle.crypto.digests.Blake2sDigest;

/** 外来UIDの要約だけを持ち、偶然の一致も送らない側へ倒す。 */
public final class ExternalMarks {
    public static final int MAX_ENTRIES=65536,HEADER_BYTES=104,MAX_PLAINTEXT_BYTES=1572968,MAX_ENVELOPE_BYTES=1573006;
    public static final long GRACE_MILLIS=600_000,NOT_STARTED=Long.MIN_VALUE;
    private static final int MAGIC=0x44544558;
    private static final byte[] PURPOSE="distributak-external-uids-v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] DOMAIN="DistribuTAK external uid v1".getBytes(StandardCharsets.US_ASCII);
    private final byte[] group,local;
    public record Fingerprint(long high,long low) implements Comparable<Fingerprint> {
        public int compareTo(Fingerprint other){int order=Long.compareUnsigned(high,other.high);return order!=0?order:Long.compareUnsigned(low,other.low);}
        @Override public String toString(){return "External UID fingerprint";}
    }
    private final TreeMap<Fingerprint,Long> hashes=new TreeMap<>();
    private boolean legacy;
    private long earliest=Long.MAX_VALUE;
    public ExternalMarks(byte[] group,byte[] local){Crypto.length(group,32);Crypto.length(local,32);this.group=group.clone();this.local=local.clone();}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("外来の印が範囲外か壊れています");}
    public static Fingerprint fingerprint(String uid){
        byte[] name=CotXml.utf8(uid);if(name.length==0||name.length>CotRecord.MAX_UID_BYTES){Crypto.wipe(name);throw invalid();}
        var digest=new Blake2sDigest(128);digest.update(DOMAIN,0,DOMAIN.length);digest.update((byte)0);digest.update(name,0,name.length);
        byte[] result=new byte[16];digest.doFinal(result,0);Crypto.wipe(name);try{var in=ByteBuffer.wrap(result);return new Fingerprint(in.getLong(),in.getLong());}finally{Crypto.wipe(result);}
    }
    public boolean belongsTo(byte[] group,byte[] local){return Crypto.equal(this.group,group)&&Crypto.equal(this.local,local);}
    public int size(){return hashes.size();}
    public boolean full(){return size()>=MAX_ENTRIES;}
    public boolean contains(String uid){return containsFingerprint(fingerprint(uid));}
    public boolean containsFingerprint(Fingerprint value){return hashes.containsKey(java.util.Objects.requireNonNull(value));}
    /** 重複も成功とする。いっぱいなら既存の印を変えない。 */
    public boolean add(String uid){return addFingerprint(fingerprint(uid));}
    public boolean addFingerprint(Fingerprint value){return addFingerprint(value,NOT_STARTED);}
    public boolean add(String uid,long started){return addFingerprint(fingerprint(uid),started);}
    public boolean addFingerprint(Fingerprint value,long started){java.util.Objects.requireNonNull(value);if(!hashes.containsKey(value)&&full())return false;hashes.put(value,started);earliest=Math.min(earliest,expiresAt(started));return true;}
    public Long startedAt(Fingerprint value){return hashes.get(value);}
    private static long expiresAt(long started){return started==NOT_STARTED||started>Long.MAX_VALUE-GRACE_MILLIS?Long.MAX_VALUE:started+GRACE_MILLIS;}
    public boolean start(Fingerprint value,long now){
        Long previous=hashes.get(value);if(previous==null||previous!=NOT_STARTED)return false;
        hashes.put(value,now);earliest=Math.min(earliest,expiresAt(now));return true;
    }
    /** 版1は時刻を持たない。未開始へ移して取り込み前に保存する。 */
    public boolean migrateLegacy(){if(!legacy)return false;hashes.replaceAll((key,value)->NOT_STARTED);earliest=Long.MAX_VALUE;legacy=false;return true;}
    public boolean hasExpired(long now){
        if(now<earliest)return false;earliest=Long.MAX_VALUE;
        for(long started:hashes.values()){
            earliest=Math.min(earliest,expiresAt(started));
            if(started!=NOT_STARTED&&started<=Long.MAX_VALUE-GRACE_MILLIS&&now>=started+GRACE_MILLIS)return true;
        }
        return false;
    }
    public java.util.Set<Fingerprint> expireEntries(long now){
        var removed=new java.util.LinkedHashSet<Fingerprint>();if(now<earliest||hashes.isEmpty())return removed;
        earliest=Long.MAX_VALUE;
        var entries=hashes.entrySet().iterator();while(entries.hasNext()){
            var entry=entries.next();long started=entry.getValue();
            if(started!=NOT_STARTED&&started<=Long.MAX_VALUE-GRACE_MILLIS&&now>=started+GRACE_MILLIS){removed.add(entry.getKey());entries.remove();}
            else earliest=Math.min(earliest,expiresAt(started));
        }
        return removed;
    }
    public int expire(long now){return expireEntries(now).size();}
    public ExternalMarks copy(){var result=new ExternalMarks(group,local);result.hashes.putAll(hashes);result.legacy=legacy;result.earliest=earliest;return result;}
    public byte[] encode(){
        if(legacy)throw new IllegalStateException("外来の印の移行が必要です");
        var out=ByteBuffer.allocate(HEADER_BYTES+24*size());out.putInt(MAGIC).putInt(2).put(PURPOSE).put(group).put(local).putInt(size());
        for(var entry:hashes.entrySet()){Fingerprint value=entry.getKey();out.putLong(value.high()).putLong(value.low()).putLong(entry.getValue());}return out.array();
    }
    public static ExternalMarks decode(byte[] bytes,byte[] group,byte[] local){
        if(bytes==null||bytes.length<HEADER_BYTES||bytes.length>MAX_PLAINTEXT_BYTES)throw invalid();
        var input=ByteBuffer.wrap(bytes);byte[] purpose=new byte[PURPOSE.length],storedGroup=new byte[32],storedLocal=new byte[32];
        if(input.getInt()!=MAGIC)throw invalid();int version=input.getInt();if(version!=1&&version!=2)throw invalid();input.get(purpose).get(storedGroup).get(storedLocal);int count=input.getInt();
        if(!Arrays.equals(PURPOSE,purpose)||!Crypto.equal(group,storedGroup)||!Crypto.equal(local,storedLocal)||count<0||count>MAX_ENTRIES||bytes.length!=HEADER_BYTES+(version==1?16:24)*count)throw invalid();
        var result=new ExternalMarks(group,local);result.legacy=version==1;Fingerprint previous=null;
        for(int n=0;n<count;n++){var value=new Fingerprint(input.getLong(),input.getLong());long started=version==1?NOT_STARTED:input.getLong();if(previous!=null&&previous.compareTo(value)>=0)throw invalid();result.addFingerprint(value,started);previous=value;}
        return result;
    }
    @Override public String toString(){return "External marks";}
}
