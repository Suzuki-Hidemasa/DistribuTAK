// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.LongSupplier;
import org.bouncycastle.util.encoders.Hex;

/** 有限の平文キャッシュ。退避先は暗号化する実装を注入する。worker専用。 */
public final class SyncCache implements AutoCloseable {
    public static final long IDLE_NANOS=5_000_000_000L;
    /** 参照・スコープ・両側の管理表を含む保守的な算入。平文のHotは別枠。 */
    public static final int REFERENCE_BYTES=1024;
    public static final int MAX_OBJECT_BYTES=240*1024;
    public static final class Ref {
        private final String scope,id;private final byte[] key,digest;private final int length,keep;
        private Ref(String scope,byte[] key,byte[] digest,int length,int keep){this.scope=scope;this.key=key;this.digest=digest;this.length=length;this.keep=keep;id=Hex.toHexString(key);}
        public byte[] key(){return key.clone();}
        public int length(){return length;}
        @Override public String toString(){return "Sync cache reference";}
    }
    private static final class Hot {
        final Ref ref;final byte[] value;long touched;
        Hot(Ref ref,byte[] value,long now){this.ref=ref;this.value=value;touched=now;}
        int bytes(){return value.length+128;}
    }
    private final SyncSpill spill;
    private final byte[] salt=new byte[32];
    private final int memoryLimit,referenceLimit;
    private final LongSupplier clock;
    private final Thread owner=Thread.currentThread();
    private final Map<String,Ref> refs=new LinkedHashMap<>();
    private final LinkedHashMap<String,Hot> hot=new LinkedHashMap<>(16,0.75f,true);
    private int hotBytes;
    private boolean closed;
    public SyncCache(SyncSpill spill,int memoryLimit,int referenceLimit,LongSupplier clock){this(spill,memoryLimit,referenceLimit,clock,new java.security.SecureRandom());}
    public SyncCache(SyncSpill spill,int memoryLimit,int referenceLimit,LongSupplier clock,java.security.SecureRandom random){
        if(memoryLimit<=0||referenceLimit<=0)throw new IllegalArgumentException("キャッシュの上限が範囲外です");
        Objects.requireNonNull(random).nextBytes(salt);
        this.spill=Objects.requireNonNull(spill);this.memoryLimit=memoryLimit;this.referenceLimit=referenceLimit;this.clock=Objects.requireNonNull(clock);
    }
    private void worker(){if(closed||Thread.currentThread()!=owner)throw new IllegalStateException("キャッシュは作業スレッドで使ってください");}
    public Ref put(String scope,byte[] plaintext,int keep){
        worker();if(scope==null||scope.length()>256||plaintext==null||plaintext.length>MAX_OBJECT_BYTES||keep<=0)throw new IllegalArgumentException("キャッシュの項目が範囲外です");
        byte[] digest=Crypto.blake2s(plaintext),key=Crypto.blake2s(Crypto.concat("DTK-SYNC-CACHE-v1\0".getBytes(StandardCharsets.US_ASCII),salt,CotXml.utf8(scope),new byte[]{0},digest));
        String id=Hex.toHexString(key);Ref old=refs.get(id);
        if(old!=null){promote(old,plaintext.clone());return old;}
        if(refs.size()>=referenceLimit||!spill.put(key,plaintext))return null;
        var ref=new Ref(scope,key,digest,plaintext.length,keep);refs.put(id,ref);promote(ref,plaintext.clone());return ref;
    }
    public byte[] get(Ref ref){
        worker();if(ref==null||refs.get(ref.id)!=ref)return null;
        Hot value=hot.get(ref.id);if(value!=null){value.touched=clock.getAsLong();return value.value.clone();}
        byte[] plain=spill.get(ref.key);
        if(plain==null||plain.length!=ref.length||!Crypto.equal(Crypto.blake2s(plain),ref.digest)){Crypto.wipe(plain);forget(ref);return null;}
        byte[] result=plain.clone();promote(ref,plain);return result;
    }
    public Ref repair(Ref ref,byte[] plaintext){
        worker();if(ref==null||plaintext==null||plaintext.length!=ref.length||!Crypto.equal(Crypto.blake2s(plaintext),ref.digest))return null;
        return put(ref.scope,plaintext,ref.keep);
    }
    private void promote(Ref ref,byte[] value){
        evict(ref);int size=value.length+128;
        if(size>memoryLimit){Crypto.wipe(value);return;}
        while(hotBytes+size>memoryLimit||hotCount(ref.scope)>=ref.keep){
            Iterator<Hot> iterator=hot.values().iterator();Hot selected=null;
            while(iterator.hasNext()){Hot next=iterator.next();if(hotBytes+size>memoryLimit||next.ref.scope.equals(ref.scope)){selected=next;iterator.remove();break;}}
            if(selected==null)break;hotBytes-=selected.bytes();Crypto.wipe(selected.value);
        }
        Hot next=new Hot(ref,value,clock.getAsLong());hot.put(ref.id,next);hotBytes+=next.bytes();
    }
    public void prefetch(Ref ref){byte[] value=get(ref);Crypto.wipe(value);}
    public void evict(Ref ref){worker();Hot old=ref==null?null:hot.remove(ref.id);if(old!=null){hotBytes-=old.bytes();Crypto.wipe(old.value);}}
    public void forget(Ref ref){worker();if(ref==null)return;evict(ref);if(refs.remove(ref.id,ref))spill.remove(ref.key);}
    public void forgetScope(String scope){worker();for(Ref ref:new ArrayList<>(refs.values()))if(ref.scope.equals(scope))forget(ref);}
    public void sweep(){worker();long now=clock.getAsLong();for(Hot value:new ArrayList<>(hot.values()))if(now-value.touched>=IDLE_NANOS)evict(value.ref);}
    public int hotBytes(){worker();return hotBytes;}
    public int hotCount(String scope){worker();int count=0;for(Hot value:hot.values())if(value.ref.scope.equals(scope))count++;return count;}
    public int references(){worker();return refs.size();}
    @Override public void close(){if(closed)return;worker();for(Hot value:hot.values())Crypto.wipe(value.value);hot.clear();hotBytes=0;refs.clear();Crypto.wipe(salt);try{spill.close();}finally{closed=true;}}
}
