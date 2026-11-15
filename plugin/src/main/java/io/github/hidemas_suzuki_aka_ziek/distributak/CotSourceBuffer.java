// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.LinkedHashSet;
import java.util.Set;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;

/** mainからworkerへ位置の最新1件と、外来の要約だけを渡す。 */
final class CotSourceBuffer {
    static final class Batch implements AutoCloseable {
        final String uid;final byte[] xml;final Set<ExternalMarks.Fingerprint> external;final boolean overflow;private final CotSourceBuffer owner;private boolean committed;
        Batch(CotSourceBuffer owner,String uid,byte[] xml,Set<ExternalMarks.Fingerprint> external,boolean overflow){this.owner=owner;this.uid=uid;this.xml=xml;this.external=external;this.overflow=overflow;}
        void committed(){
            synchronized(owner){if(overflow)throw new IllegalStateException("外来の待ちの上限に達しました");committed=true;if(owner.inFlight==external){owner.inFlight=Set.of();owner.inFlightOverflow=false;}}
        }
        public void close(){Crypto.wipe(xml);synchronized(owner){if(committed)external.clear();}}

    }
    private Set<ExternalMarks.Fingerprint> external=new LinkedHashSet<>(),inFlight=Set.of();
    private String uid;private byte[] xml;
    private boolean overflow,inFlightOverflow;
    private static boolean valid(String uid){
        if(uid==null||uid.isEmpty()||uid.length()>CotRecord.MAX_UID_BYTES)return false;
        var utf8=java.nio.charset.StandardCharsets.UTF_8;
        return utf8.newEncoder().canEncode(uid)&&uid.getBytes(utf8).length<=CotRecord.MAX_UID_BYTES;
    }
    synchronized boolean knownExternal(String name){
        if(overflow||inFlightOverflow)return true;
        var fingerprint=ExternalMarks.fingerprint(name);return external.contains(fingerprint)||inFlight.contains(fingerprint);
    }
    /** 上限や未読を一致とせず、mainの待ちと保存済みの実際の印だけを見る。 */
    synchronized boolean externalMarked(String name,java.util.function.Supplier<ExternalMarks> saved){
        if(!valid(name))return false;
        var fingerprint=ExternalMarks.fingerprint(name);
        if(external.contains(fingerprint)||inFlight.contains(fingerprint))return true;
        ExternalMarks current=saved.get();return current!=null&&current.containsFingerprint(fingerprint);
    }
    /** 保存済みの印への受け渡しと、mainの判定を同じロック内でそろえる。 */
    synchronized boolean permitsImport(String name,java.util.function.Supplier<ExternalMarks> saved){
        return permitsImport(name,saved,()->{});
    }
    synchronized boolean permitsImport(String name,java.util.function.Supplier<ExternalMarks> saved,Runnable externalMatch){
        var fingerprint=ExternalMarks.fingerprint(name);
        if(overflow||inFlightOverflow)return false;
        if(external.contains(fingerprint)||inFlight.contains(fingerprint)){externalMatch.run();return false;}
        ExternalMarks current=saved.get();if(current==null)return false;
        if(current.containsFingerprint(fingerprint)){externalMatch.run();return false;}
        return true;
    }
    synchronized void position(String name,byte[] value){
        if(!valid(name)||value==null||value.length>CotXml.MAX_BYTES||knownExternal(name))return;
        Crypto.wipe(xml);uid=name;xml=value.clone();
    }
    synchronized boolean external(String name){
        if(!valid(name))return false;var fingerprint=ExternalMarks.fingerprint(name);
        if(!external.contains(fingerprint)&&external.size()>=ExternalMarks.MAX_ENTRIES){overflow=true;return false;}
        if(uid!=null&&fingerprint.equals(ExternalMarks.fingerprint(uid))){Crypto.wipe(xml);xml=null;uid=null;}external.add(fingerprint);return true;
    }
    synchronized Batch take(){
        if(!inFlight.isEmpty()||inFlightOverflow)throw new IllegalStateException("外来の待ちは作業スレッドで順に処理してください");
        var batch=new Batch(this,uid,xml,external,overflow);inFlight=external;inFlightOverflow=overflow;uid=null;xml=null;external=new LinkedHashSet<>();overflow=false;return batch;
    }
    synchronized void clear(){Crypto.wipe(xml);xml=null;uid=null;external.clear();inFlight=Set.of();overflow=false;inFlightOverflow=false;}
}
