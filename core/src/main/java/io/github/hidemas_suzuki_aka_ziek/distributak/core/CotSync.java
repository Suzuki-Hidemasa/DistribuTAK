// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import org.bouncycastle.util.encoders.Hex;

/**
 * 認証済みのセッションの上の同期。一つのworkerから呼ぶ。
 * connectedにはセッションが成立してから通知し、sendは同じセッションだけへ送る。
 * Storeが成功するまでは、ACK・配り直し・ATAKへの通知を行わない。
 */
public final class CotSync implements AutoCloseable {
    public static final long SAVE_NANOS=250_000_000L,RETRY_NANOS=1_000_000_000L,CATCHUP_NANOS=30_000_000_000L;
    private static final int PEER_PENDING=32,TOTAL_PENDING=256,OUTBOUND_BYTES=1024*1024,ACK_BYTES=1024*1024;
    public interface Store {
        void save(SyncState snapshot)throws Exception;
        default SyncState load()throws Exception{throw new IllegalStateException("同期の正本を読み直せません");}
        default boolean encoded(){return false;}
        default byte[] loadEncoded()throws Exception{throw new IllegalStateException("同期の正本を読み直せません");}
        /** encodedは借り物。実装は呼び出し後に保持・変更しない。 */
        default void saveEncoded(SyncState snapshot,byte[] encoded)throws Exception{save(snapshot);}
    }
    public interface ExternalStore { void save(ExternalMarks marks)throws Exception; }
    public static final class ExternalCapacityException extends IllegalStateException {
        public ExternalCapacityException(){super("外来の印の上限に達したため同期を止めました");}
    }
    public interface Sender { boolean send(byte[] peer,byte[] session,byte[] plaintext); }
    public record Statistics(long sent,long received,long rejected,long unknown,long tooLarge,long capacity,
                             long clockBlocked,long retries,long failed,int pending,int pendingBytes) {}
    private enum Kind { RECORD,INVENTORY,REQUEST }
    private static final class Task {
        final Kind kind;final byte[] wire,id,ack;final String uid,fingerprint;
        final long stale;final boolean deleted;final int page;final Set<String> wanted;final boolean own;
        long first,last,lastTry;int attempts;boolean sent,force,failed,normalUpdate;
        Task(Kind kind,byte[] wire,byte[] id,CotRecord item,int page,Set<String> wanted,boolean own){
            deleted=item!=null&&item.deleted();this.kind=kind;this.wire=wire;this.id=id;this.page=page;this.wanted=wanted;this.own=own;
            uid=item==null?null:item.uid();fingerprint=item==null?null:key(item.hash());ack=item==null?null:SyncWire.ack(item);stale=item==null?0:item.stale();
        }
        boolean big(){return wire.length>SessionPacket.MAX_PLAINTEXT;}
        void clear(){Crypto.wipe(wire);Crypto.wipe(id);Crypto.wipe(ack);}
    }
    private static final class Serve {
        final List<SyncSchema.SyncInventoryEntry> entries;final int entryBytes;
        final Map<String,String> waiting=new LinkedHashMap<>(),attempted=new LinkedHashMap<>();
        final Set<String> unavailable=new LinkedHashSet<>();int cursor;
        Serve(List<SyncSchema.SyncInventoryEntry> entries,boolean ownEntries){this.entries=entries;int size=8*entries.size();if(ownEntries)for(var entry:entries)size+=SyncInventory.charge(entry);entryBytes=size;}
        boolean complete(){return cursor==entries.size()&&waiting.isEmpty()&&unavailable.isEmpty();}
    }
    private static final class Peer {
        final byte[] id,session;final String key;final long connected;final boolean smaller;
        final Map<String,Task> records=new LinkedHashMap<>(),requests=new LinkedHashMap<>();
        final Map<String,String> failed=new LinkedHashMap<>(),winnerReplies=new LinkedHashMap<>();
        final Set<String> deferred=new LinkedHashSet<>();final Map<Integer,Serve> serves=new LinkedHashMap<>();
        SyncInventory.Offer offer;SyncInventory.Receiver receiver;
        final Map<Integer,SyncCache.Ref> completedServes=new LinkedHashMap<>();
        Task inventory,big;Set<String> offeredOwn=Set.of();int page;long ownStart,remoteStart;
        boolean ownStarted,ownDone,remoteStarted,remoteDone,remoteFailed,missingDone,sendBlocked;
        String missingCursor;
        Peer(byte[] id,byte[] session,String key,long now,boolean smaller){
            this.id=id.clone();this.session=session.clone();this.key=key;connected=now;this.smaller=smaller;
            if(!smaller){remoteStarted=true;remoteStart=now;}
        }
        int pending(){return records.size()+requests.size()+(inventory==null?0:1);}
    }
    private static final class Waiting {
        final Peer peer;final byte[] ack;final SyncFragments.Receipt receipt;final int bytes;
        Waiting(Peer peer,byte[] ack,SyncFragments.Receipt receipt){this.peer=peer;this.ack=ack;this.receipt=receipt;bytes=1024+3*ack.length;}
    }
    private final byte[] localId;
    private final Clock wall;
    private final LongSupplier ticker;
    private final Store store;
    private final ExternalStore externalStore;
    private final SyncLimits limits;
    private final SyncCache cache;
    private final Map<String,SyncCache.Ref> bodies=new LinkedHashMap<>();
    private final Map<ExternalMarks.Fingerprint,Set<String>> ownNames=new LinkedHashMap<>();
    private ExternalMarks external;
    private boolean externalDirty;
    private final Sender sender;
    private final Consumer<CotRecord> accepted;
    private final SecureRandom random;
    private final long minimumInterval;
    private final SyncFragments fragments;
    private final SyncVersionClock versions;
    private SyncState committed,working,restored;
    private byte[] primaryEncoded;private int readDepth;
    private final Map<String,Peer> peers=new LinkedHashMap<>();
    private final Map<String,Waiting> acks=new LinkedHashMap<>();
    private final Map<String,String> changes=new LinkedHashMap<>();
    private final Map<String,Long> lastLocal=new LinkedHashMap<>();
    private final Set<String> localDeferred=new LinkedHashSet<>();
    private final Set<String> blockedCreated=new LinkedHashSet<>(),createdThisCapture=new LinkedHashSet<>();
    private int outgoingBytes,waitingBytes;
    private boolean dirty,closed;
    private String positionUid;
    private long dirtyAt,sent,received,rejected,unknown,tooLarge,capacity,clockBlocked,retries,failed;
    private long externalImportsSkipped; // 件数だけの診断。永続化せず、#10で外す対象。
    public CotSync(byte[] localId,SyncState initial,Clock wall,LongSupplier monotonicNanos,Store store,Sender sender,
                   Consumer<CotRecord> accepted,SecureRandom random,long minimumIntervalNanos){
        this(localId,initial,wall,monotonicNanos,store,sender,accepted,random,minimumIntervalNanos,new ExternalMarks(initial.groupId(),localId),marks->{});
    }
    public CotSync(byte[] localId,SyncState initial,Clock wall,LongSupplier monotonicNanos,Store store,Sender sender,
                   Consumer<CotRecord> accepted,SecureRandom random,long minimumIntervalNanos,ExternalMarks external,ExternalStore externalStore){
        this(localId,initial,wall,monotonicNanos,store,sender,accepted,random,minimumIntervalNanos,external,externalStore,SyncLimits.DEFAULT);
    }
    public CotSync(byte[] localId,SyncState initial,Clock wall,LongSupplier monotonicNanos,Store store,Sender sender,
                   Consumer<CotRecord> accepted,SecureRandom random,long minimumIntervalNanos,ExternalMarks external,ExternalStore externalStore,SyncLimits limits){
        this(localId,initial,wall,monotonicNanos,store,sender,accepted,random,minimumIntervalNanos,external,externalStore,limits,null);
    }
    public CotSync(byte[] localId,SyncState initial,Clock wall,LongSupplier monotonicNanos,Store store,Sender sender,
                   Consumer<CotRecord> accepted,SecureRandom random,long minimumIntervalNanos,ExternalMarks external,ExternalStore externalStore,SyncLimits limits,SyncCache cache){
        this.cache=cache;
        this.limits=Objects.requireNonNull(limits);
        Crypto.length(localId,32);if(minimumIntervalNanos<0||!initial.localIdentity(localId))throw new IllegalArgumentException("同期の初期状態が違います");
        if(!external.belongsTo(initial.groupId(),localId))throw new IllegalArgumentException("外来の印の所属が違います");
        this.external=external.copy();this.externalStore=Objects.requireNonNull(externalStore);
        this.localId=localId.clone();committed=initial.copy();working=initial.copy();this.wall=Objects.requireNonNull(wall);
        ticker=Objects.requireNonNull(monotonicNanos);this.store=Objects.requireNonNull(store);this.sender=Objects.requireNonNull(sender);
        this.accepted=Objects.requireNonNull(accepted);this.random=Objects.requireNonNull(random);minimumInterval=minimumIntervalNanos;
        fragments=new SyncFragments(ticker);versions=new SyncVersionClock(initial.maximum());for(String uid:initial.localUids())rememberOwn(uid);beginCreatedCapture();offloadBodies();
    }
    private void rememberOwn(String uid){ownNames.computeIfAbsent(ExternalMarks.fingerprint(uid),key->new LinkedHashSet<>()).add(uid);}
    private String scope(Peer peer,String kind){return peer.key+":"+key(peer.session)+":"+kind;}
    private SyncInventory.Receiver receiver(Peer peer){return new SyncInventory.Receiver(cache,scope(peer,"receive"));}
    private void releaseOffer(Peer peer){
        if(peer.offer!=null){peer.offer.close();peer.offer=null;}
        for(var ref:peer.completedServes.values())if(cache!=null)cache.forget(ref);peer.completedServes.clear();peer.serves.clear();peer.offeredOwn=Set.of();
    }
    private final class ReadScope implements AutoCloseable {
        ReadScope(){readDepth++;}
        public void close(){if(--readDepth==0){discardRestored();Crypto.wipe(primaryEncoded);primaryEncoded=null;}}
    }
    private void discardRestored(){if(restored!=null&&store.encoded())restored.wipeBodies();restored=null;}
    private byte[] primary()throws Exception{if(primaryEncoded==null)primaryEncoded=store.loadEncoded();return primaryEncoded;}
    private byte[] restoreXml(String uid,byte[] hash){
        try(var ignored=new ReadScope()){
            if(restored==null)restored=store.encoded()?SyncState.decode(primary(),committed.groupId(),localId):store.load();
            if(restored==null||!restored.belongsTo(committed.groupId(),localId))throw new IllegalStateException();
            CotRecord item=restored.get(uid);if(item==null||!Crypto.equal(hash,item.hash()))throw new IllegalStateException();return item.xml();
        }catch(Exception e){close();throw new IllegalStateException("同期の正本を開けません。通信を停止しました");}
    }
    private void offloadBodies(){
        if(cache==null)return;var keep=new LinkedHashMap<String,SyncCache.Ref>();
        for(CotRecord item:committed.records()){
            String uid=item.uid();byte[] hash=item.hash();
            CotRecord cold=item.offload(cache,()->restoreXml(uid,hash));
            if(cold!=item){committed.replaceBody(cold);CotRecord pending=working.get(uid);if(cold.sameRecord(pending))working.replaceBody(cold);}
            if(cold.cacheRef()!=null)keep.put(uid,cold.cacheRef());
        }
        for(var entry:bodies.entrySet())if(entry.getValue()!=keep.get(entry.getKey()))cache.forget(entry.getValue());
        bodies.clear();bodies.putAll(keep);
    }
    private static String key(byte[] value){return Hex.toHexString(value);}
    private void open(){if(closed)throw new IllegalStateException("同期は停止しています");}
    private static boolean local(SyncState.Origin origin){return origin==SyncState.Origin.LOCAL_POSITION||origin==SyncState.Origin.LOCAL_CREATED;}
    private byte[] token(){byte[] id=new byte[16];random.nextBytes(id);return id;}
    private void dirty(){if(!dirty&&!externalDirty)dirtyAt=ticker.getAsLong();dirty=true;}
    private boolean known(String uid){return working.get(uid)!=null||working.origin(uid)!=SyncState.Origin.UNKNOWN;}
    /** 自作の記録だけを外来の印で止める。受けた記録の配り直しは変えない。 */
    private boolean sendable(String uid,boolean own){
        CotRecord item=committed.get(uid);return sendable(uid,own,item!=null&&item.deleted());
    }
    private boolean sendable(String uid,boolean own,boolean deleted){
        return !own||!external.contains(uid)&&(deleted||committed.origin(uid)!=SyncState.Origin.LOCAL_CREATED||createdThisCapture.contains(uid));
    }
    /** 捕捉世代の所有はメモリだけ。保存済みの自作本文から許可を復活させない。 */
    public void beginCreatedCapture(){
        open();createdThisCapture.clear();
        for(String uid:working.localUids())if(createdBody(uid))blockedCreated.add(uid);
        localDeferred.removeIf(this::createdBody);
        for(Peer peer:peers.values()){
            peer.deferred.removeIf(this::createdBody);
            for(Task task:new ArrayList<>(peer.records.values()))if(task.own&&!task.deleted&&working.origin(task.uid)==SyncState.Origin.LOCAL_CREATED)release(peer,task);
        }
    }
    private boolean createdBody(String uid){
        CotRecord item=working.get(uid);return working.origin(uid)==SyncState.Origin.LOCAL_CREATED&&(item==null||!item.deleted());
    }
    // 送る本文と出所は、どちらも保存済みの同じ状態から取る。
    private boolean sendable(CotRecord item){return item!=null&&sendable(item.uid(),local(committed.origin(item.uid())),item.deleted());}
    private boolean pageSendable(Peer peer,byte[] wire){
        for(var entry:SyncWire.parse(wire).getInventory().getEntriesList())if(!sendable(entry.getUid(),peer.offeredOwn.contains(entry.getUid()),entry.getDeleted()))return false;return true;
    }
    private boolean blocksNew(String uid){expireExternal();return !known(uid)&&(working.uidCount()>=SyncState.MAX_UIDS||external.full()&&!external.contains(uid));}
    /** 位置がまだ得られなくても、ATAKのself UIDを接続前に登録する。 */
    public boolean protectPosition(String uid){
        open();byte[] name=CotXml.utf8(uid);
        if(name.length==0||name.length>CotRecord.MAX_UID_BYTES)throw new IllegalArgumentException("自分の位置の識別が違います");
        positionUid=uid;var origin=working.origin(uid);
        if(external.contains(uid)||blocksNew(uid)){capacity++;return false;}
        if(origin==SyncState.Origin.LOCAL_POSITION)return true;
        if(origin!=SyncState.Origin.UNKNOWN){unknown++;return false;}
        try{working.origin(uid,SyncState.Origin.LOCAL_POSITION);rememberOwn(uid);dirty();return true;}
        catch(IllegalArgumentException e){capacity++;return false;}
    }
    public boolean publish(String uid,byte[] xml,SyncState.Origin origin){
        open();if(blockedCreated.contains(uid)||!local(origin)||working.origin(uid)==SyncState.Origin.DISTRIBUTAK||external.contains(uid)){unknown++;return false;}
        if(blocksNew(uid)){capacity++;return false;}
        byte[] normalized=null;
        try{
            normalized=CotXml.shortenStale(xml,wall.millis());var fields=CotXml.inspect(normalized);
            if(!uid.equals(fields.uid()))throw new IllegalArgumentException();
            var next=versions.next(wall.millis());if(next.isEmpty()){clockBlocked++;return false;}
            var item=CotRecord.record(uid,next.getAsLong(),localId,fields.stale(),normalized,0);item.validateAt(wall.millis());
            try{
                working.apply(item,wall.millis(),origin,next.getAsLong());if(origin==SyncState.Origin.LOCAL_CREATED)createdThisCapture.add(uid);rememberOwn(uid);changes.put(uid,null);dirty();return true;
            }catch(IllegalArgumentException e){capacity++;return false;}
        }catch(IllegalArgumentException e){if(xml!=null&&xml.length>CotXml.MAX_BYTES)tooLarge++;else rejected++;return false;}
        finally{Crypto.wipe(normalized);}
    }
    public boolean remove(String uid){
        open();if(!local(working.origin(uid))||working.origin(uid)==SyncState.Origin.LOCAL_CREATED&&!createdThisCapture.contains(uid)||external.contains(uid)){unknown++;return false;}
        var next=versions.next(wall.millis());if(next.isEmpty()){clockBlocked++;return false;}
        try{
            var item=CotRecord.tombstone(uid,next.getAsLong(),localId,0);
            working.apply(item,wall.millis(),working.origin(uid),next.getAsLong());changes.put(uid,null);dirty();return true;
        }catch(IllegalArgumentException e){capacity++;return false;}
    }
    public void external(String uid){
        externalFingerprint(ExternalMarks.fingerprint(uid));
    }
    public void externalFingerprint(ExternalMarks.Fingerprint fingerprint){
        open();Long previous=external.startedAt(fingerprint);
        // 既存の印は先に未開始へ戻す。外来の更新より前に期限切れを進めない。
        if(previous==null&&external.full())expireExternal();
        if(!external.addFingerprint(fingerprint)){capacity++;try{flush();}finally{close();}throw new ExternalCapacityException();}
        if(previous==null){
            for(String uid:ownNames.getOrDefault(fingerprint,Set.of()))if(local(working.origin(uid))){
                localDeferred.remove(uid);
                for(Peer peer:peers.values()){
                    Task task=peer.records.get(uid);if(task!=null)release(peer,task);peer.deferred.remove(uid);
                    if(peer.inventory!=null&&!pageSendable(peer,peer.inventory.wire))release(peer,peer.inventory);
                    for(Serve serve:peer.serves.values())if(serve.waiting.remove(uid)!=null)serve.unavailable.add(uid);
                }
            }
        }
        if(previous==null||previous.longValue()!=ExternalMarks.NOT_STARTED)externalDirty();
    }
    private void externalDirty(){if(!dirty&&!externalDirty)dirtyAt=ticker.getAsLong();externalDirty=true;}
    private void startExternalForSavedUid(String uid){
        if(committed.get(uid)==null)return;
        var fingerprint=ExternalMarks.fingerprint(uid);Long previous=external.startedAt(fingerprint);
        if(previous==null||previous.longValue()!=ExternalMarks.NOT_STARTED)return;
        ExternalMarks started=external.copy();started.start(fingerprint,wall.millis());
        // 同じ版・古い版のACKでは、別の受信更新を先に確定しない。
        try{externalStore.save(started.copy());}
        catch(Exception e){close();throw new IllegalStateException("同期を保存できません。通信を停止しました");}
        external=started;externalDirty=false;
    }
    /** 印を消した保存に成功してから、残っている最新の記録を通常の取り込み口へ渡す。 */
    public int expireExternal(){
        try(var ignored=new ReadScope()){
            open();if(!external.hasExpired(wall.millis()))return 0;
            flush();var expired=external.expireEntries(wall.millis());int count=expired.size();
            if(count==0)return 0;
            externalDirty();flush();externalExpired=Math.min(Long.MAX_VALUE-count,externalExpired)+count;
            for(CotRecord item:committed.records())if(expired.contains(ExternalMarks.fingerprint(item.uid()))&&!item.uid().equals(positionUid))accepted.accept(item.materialize());
            return count;
        }
    }
    /** 内部取り込みの前に受信UIDを記録する。呼び出し元はflushの成功も確かめる。 */
    public boolean registerReceivedUid(String uid){
        open();if(local(working.origin(uid))||uid.equals(positionUid))return false;
        if(blocksNew(uid)){capacity++;return false;}
        try{working.origin(uid,SyncState.Origin.DISTRIBUTAK);dirty();return true;}
        catch(IllegalArgumentException e){capacity++;return false;}
    }
    public void connected(byte[] peerId,byte[] sessionId){
        try(var ignored=new ReadScope()){
        open();Crypto.length(peerId,32);Crypto.length(sessionId,16);if(Crypto.equal(peerId,localId))throw new IllegalArgumentException("自分とは同期しません");
        String key=key(peerId);Peer old=peers.get(key);if(old!=null&&Crypto.equal(old.session,sessionId))return;
        disconnected(peerId);if(peers.size()>=65535)throw new IllegalArgumentException("相手の数が上限です");
        var peer=new Peer(peerId,sessionId,key,ticker.getAsLong(),AdminRecords.compareBytes(localId,peerId)<0);peer.receiver=receiver(peer);peers.put(key,peer);
        pumpPeer(peer);
            }
    }
    public void disconnected(byte[] peerId){
        Crypto.length(peerId,32);Peer peer=peers.remove(key(peerId));if(peer==null)return;
        releaseOffer(peer);peer.receiver.close();for(Task task:tasks(peer))release(peer,task);fragments.forget(peer.id,peer.session);
        var waiting=acks.values().iterator();while(waiting.hasNext()){Waiting item=waiting.next();if(item.peer==peer){waitingBytes-=item.bytes;Crypto.wipe(item.ack);waiting.remove();}}
    }
    private List<Task> tasks(Peer peer){var result=new ArrayList<>(peer.records.values());result.addAll(peer.requests.values());if(peer.inventory!=null)result.add(peer.inventory);return result;}
    private UdpEndpoint renewalEndpoint;
    private Consumer<AdminRecords.Record> renewed;
    /** 検査済みの更新を保存する上位の受け口。差し替えは保存後に上位が行う。 */
    public void certificateRenewals(UdpEndpoint endpoint,Consumer<AdminRecords.Record> accepted) {
        open();renewalEndpoint=Objects.requireNonNull(endpoint);renewed=Objects.requireNonNull(accepted);
    }
    private void renewal(byte[] certificate) {
        if(renewalEndpoint==null || renewed==null)throw new SecurityException("更新の受け口がありません");
        var record=AdminRecords.decode(certificate);
        if(renewalEndpoint.validateLocalCertificateRenewal(record))renewed.accept(record);
    }
    public void receive(byte[] peerId,byte[] sessionId,byte[] wire){
        try(var ignored=new ReadScope()){
        open();Peer peer=peers.get(key(peerId));if(peer==null||!Crypto.equal(peer.session,sessionId)){rejected++;return;}
        try(var result=fragments.accept(peerId,sessionId,wire)){
            if(result==null)return;byte[] message=result.message();
            if(message==null){
                for(byte[] reply:result.replies())try{
                    var envelope=SyncWire.parse(reply);
                    if(envelope.hasAck()){startExternalForSavedUid(envelope.getAck().getUid());sendAck(peer,reply);}
                    else if(envelope.hasRequest())queueRequest(peer,reply,true);
                    else throw new IllegalArgumentException("同期の再応答の種類が違います");
                }finally{Crypto.wipe(reply);}
                pumpPeer(peer);
                return;
            }
            try{
                var envelope=SyncWire.parse(message);var receipt=fragments.receipt(result);
                switch(envelope.getBodyCase()){
                    case RECORD,TOMBSTONE -> record(peer,SyncWire.decodeRecord(envelope),receipt);
                    case ACK -> ack(peer,envelope.getAck());
                    case INVENTORY -> inventory(peer,message,receipt);
                    case REQUEST -> request(peer,message,receipt);
                    case RENEWAL -> renewal(envelope.getRenewal().getCertificate().toByteArray());
                    default -> throw new IllegalArgumentException("同期の種類が違います");
                }
                pumpPeer(peer);
            }finally{Crypto.wipe(message);}
        }catch(IllegalArgumentException|SecurityException e){rejected++;}
            }
    }
    private void record(Peer peer,CotRecord item,SyncFragments.Receipt receipt){
        item.validateAt(wall.millis());if(item.hop()<1||item.hop()==1&&!Crypto.equal(item.author(),peer.id))throw new IllegalArgumentException("同期の送り元が違います");
        CotRecord current=working.get(item.uid());
        if(blocksNew(item.uid())){capacity++;return;}
        if((local(working.origin(item.uid()))&&!external.contains(item.uid())||item.uid().equals(positionUid))
                &&(!Crypto.equal(item.author(),localId)||current==null||item.compareForWinner(current)>0)){rejected++;return;}
        for(Task task:new ArrayList<>(peer.requests.values()))if(task.sent&&task.wanted.contains(item.uid()))release(peer,task);
        boolean changed=current==null||item.compareForWinner(current)>0;
        byte[] ack=SyncWire.ack(item);String identity=peer.key+":"+key(peer.session)+":"+key(item.hash());
        Waiting previous=acks.get(identity);var waiting=new Waiting(peer,ack,receipt);
        CotRecord durable=committed.get(item.uid());
        if(!changed&&durable!=null&&durable.compareForWinner(item)>=0){
            try{startExternalForSavedUid(item.uid());sendAck(peer,ack);fragments.remember(receipt,List.of(ack));}finally{Crypto.wipe(ack);}
            if(!durable.sameRecord(item))winner(peer,durable);return;
        }
        if(previous==null&&(acks.size()>=SyncState.MAX_UIDS||waitingBytes+waiting.bytes>ACK_BYTES)){Crypto.wipe(ack);capacity++;return;}
        if(changed){
            try{
                var origin=working.origin(item.uid());if(!local(origin)||external.contains(item.uid()))origin=SyncState.Origin.DISTRIBUTAK;
                working.apply(item,wall.millis(),origin,working.maximum());changes.put(item.uid(),peer.key);dirty();
            }catch(IllegalArgumentException e){Crypto.wipe(ack);capacity++;return;}
        }
        if(previous==null){acks.put(identity,waiting);waitingBytes+=waiting.bytes;}
        else{Crypto.wipe(ack);}
        // 全相手を合わせてACK待ち32件、または分割した記録がそろった時点で早く保存する。
        if(acks.size()>=PEER_PENDING||receipt!=null)flush();
    }
    private void sendAck(Peer peer,byte[] wire){sender.send(peer.id.clone(),peer.session.clone(),wire);}
    private void winner(Peer peer,CotRecord item){
        String fingerprint=key(item.hash());if(fingerprint.equals(peer.winnerReplies.get(item.uid())))return;
        String old=peer.winnerReplies.put(item.uid(),fingerprint);
        if(!withinMetadata(peer)){if(old==null)peer.winnerReplies.remove(item.uid());else peer.winnerReplies.put(item.uid(),old);capacity++;return;}
        defer(peer,item.uid());
    }
    private void ack(Peer peer,SyncSchema.SyncAck ack){
        SyncWire.validateIdentity(ack.getUid(),ack.hasVersion()?ack.getVersion():null,ack.getHash());
        Task task=peer.records.get(ack.getUid());if(task==null||!task.sent||!SyncWire.parse(task.ack).getAck().equals(ack))return;
        String fingerprint=task.fingerprint;release(peer,task);
        for(Serve serve:peer.serves.values())if(fingerprint.equals(serve.waiting.get(ack.getUid())))serve.waiting.remove(ack.getUid());
    }
    public void poll(){
        try(var ignored=new ReadScope()){
        open();expireExternal();if(cache!=null)cache.sweep();fragments.expire();boolean pruned=working.prune(wall.millis());if(pruned)dirty();
        if((dirty||externalDirty)&&ticker.getAsLong()-dirtyAt>=SAVE_NANOS)flush();
        for(String uid:new ArrayList<>(localDeferred)){
            CotRecord current=committed.get(uid);
            if(current==null||!current.deleted()&&current.stale()<=wall.millis()){localDeferred.remove(uid);continue;}
            Long last=lastLocal.get(uid);if(last==null||ticker.getAsLong()-last>=minimumInterval){localDeferred.remove(uid);broadcast(uid,null);lastLocal.put(uid,ticker.getAsLong());}
        }
        for(Peer peer:peers.values())pumpPeer(peer);
            }
    }
    public void flush(){
        try(var ignored=new ReadScope()){
        open();if(!dirty&&!externalDirty)return;
        try{
            if(externalDirty)externalStore.save(external.copy());
            if(dirty){
                if(store.encoded()){
                    byte[] next=working.encodeUsing(committed,primary());
                    boolean saved=false;try{store.saveEncoded(working.copy(),next);saved=true;}finally{if(!saved)Crypto.wipe(next);}
                    Crypto.wipe(primaryEncoded);primaryEncoded=next;discardRestored();
                }else store.save(working.copy());
            }
            // 同期の保存が成功した時刻を起点にする。続けて受けても開始を変えない。
            ExternalMarks started=null;long now=wall.millis();
            for(var change:changes.entrySet())if(change.getValue()!=null){
                var fingerprint=ExternalMarks.fingerprint(change.getKey());Long previous=external.startedAt(fingerprint);
                if(previous!=null&&previous.longValue()==ExternalMarks.NOT_STARTED){if(started==null)started=external.copy();started.start(fingerprint,now);}
            }
            if(started!=null){externalStore.save(started.copy());external=started;}
        }
        catch(Exception e){close();throw new IllegalStateException("同期を保存できません。通信を停止しました");}
        committed=working.copy();dirty=false;externalDirty=false;
        for(Waiting waiting:new ArrayList<>(acks.values())){
            if(peers.get(waiting.peer.key)==waiting.peer){
                sendAck(waiting.peer,waiting.ack);fragments.remember(waiting.receipt,List.of(waiting.ack));
                var ack=SyncWire.parse(waiting.ack).getAck();CotRecord current=committed.get(ack.getUid());
                if(current!=null&&!Crypto.equal(current.hash(),ack.getHash().toByteArray()))winner(waiting.peer,current);
            }
            Crypto.wipe(waiting.ack);
        }
        acks.clear();waitingBytes=0;
        for(var change:new ArrayList<>(changes.entrySet())){
            CotRecord item=committed.get(change.getKey());if(item==null)continue;
            if(change.getValue()!=null){
                received++;
                if(!external.contains(item.uid()))accepted.accept(item.materialize());
                else if(externalImportsSkipped<Long.MAX_VALUE)externalImportsSkipped++;
                broadcast(item.uid(),change.getValue());
            }
            else{
                Long last=lastLocal.get(item.uid());
                if(item.deleted()||last==null||ticker.getAsLong()-last>=minimumInterval){localDeferred.remove(item.uid());broadcast(item.uid(),null);lastLocal.put(item.uid(),ticker.getAsLong());}
                else localDeferred.add(item.uid());
            }
        }
        changes.clear();offloadBodies();
            }
    }
    private void broadcast(String uid,String except){for(Peer peer:peers.values())if(!peer.key.equals(except))defer(peer,uid);}
    private void defer(Peer peer,String uid){
        if(!sendable(committed.get(uid)))return;
        boolean added=peer.deferred.add(uid);if(added&&!withinMetadata(peer)){peer.deferred.remove(uid);capacity++;}
    }
    private int pending(){int result=0;for(Peer peer:peers.values())result+=peer.pending();return result;}
    private boolean room(Peer peer,int bytes){return peer.pending()<PEER_PENDING&&pending()<TOTAL_PENDING&&outgoingBytes+bytes<=OUTBOUND_BYTES;}
    private Task queueRecord(Peer peer,CotRecord item,boolean requested){return queueRecord(peer,item,requested,false);}
    private Task queueRecord(Peer peer,CotRecord item,boolean requested,boolean normalUpdate){
        if(!sendable(item)||peer.sendBlocked||item.hop()>=CotRecord.MAX_HOP||!item.deleted()&&item.stale()<=wall.millis())return null;
        String fingerprint=key(item.hash());Task old=peer.records.get(item.uid());
        if(old!=null){if(fingerprint.equals(old.fingerprint)){if(!normalUpdate)old.normalUpdate=false;return old;}if(old.big()&&old.sent)return null;}
        if(!requested&&fingerprint.equals(peer.failed.get(item.uid())))return null;
        byte[] wire=SyncWire.encode(item.relay());
        int oldBytes=old==null?0:old.wire.length;
        if(outgoingBytes-oldBytes+wire.length>OUTBOUND_BYTES||old==null&&!room(peer,wire.length)){Crypto.wipe(wire);return null;}
        if(old!=null)release(peer,old);
        var task=new Task(Kind.RECORD,wire,token(),item,-1,Set.of(),local(committed.origin(item.uid())));task.normalUpdate=normalUpdate&&!item.deleted();peer.records.put(item.uid(),task);outgoingBytes+=wire.length;return task;
    }
    private boolean queueRequest(Peer peer,byte[] wire,boolean again){
        var envelope=SyncWire.parse(wire);if(!envelope.hasRequest())throw new IllegalArgumentException("同期の返事が違います");
        var request=envelope.getRequest();String key=key(request.getSnapshotId().toByteArray())+":"+request.getPage();Task old=peer.requests.get(key);
        if(old!=null){if(!Arrays.equals(old.wire,wire))throw new IllegalArgumentException("同期の求めが変わっています");old.force|=again;return true;}
        if(!room(peer,wire.length)){capacity++;return false;}
        var wanted=new LinkedHashSet<String>();for(var entry:request.getWantedList())wanted.add(entry.getUid());
        var task=new Task(Kind.REQUEST,wire.clone(),token(),null,request.getPage(),wanted,false);task.force=true;
        peer.requests.put(key,task);outgoingBytes+=wire.length;
        if(!withinMetadata(peer)){release(peer,task);capacity++;return false;}return true;
    }
    private void release(Peer peer,Task task){
        boolean removed=false;
        if(task.kind==Kind.RECORD)removed=peer.records.remove(task.uid,task);
        else if(task.kind==Kind.INVENTORY){if(peer.inventory==task){peer.inventory=null;removed=true;}}
        else{Iterator<Task> iterator=peer.requests.values().iterator();while(iterator.hasNext())if(iterator.next()==task){iterator.remove();removed=true;break;}}
        if(removed){outgoingBytes-=task.wire.length;if(peer.big==task)peer.big=null;task.clear();}
    }
    private void send(Peer peer,Task task){
        // 送り待ちの出所を後の版から引き直さず、その待ち自身の出所で再判定する。
        if(task.kind==Kind.RECORD&&(committed.get(task.uid)==null||!sendable(task.uid,task.own,task.deleted))||task.kind==Kind.INVENTORY&&!pageSendable(peer,task.wire)){release(peer,task);return;}
        // 未送信の本文は追いつき・受信の配り直しも最新版と照らす。再送と削除は保つ。
        if(task.kind==Kind.RECORD&&!task.deleted&&!task.sent){
            CotRecord latest=committed.get(task.uid);
            if(!task.fingerprint.equals(key(latest.hash()))||!latest.deleted()&&latest.stale()<=wall.millis()){release(peer,task);return;}
            if(task.own&&task.normalUpdate&&localDeferred.contains(task.uid))return;
        }
        long now=ticker.getAsLong();if(task.big()&&peer.big!=null&&peer.big!=task)return;
        if(task.kind==Kind.RECORD&&task.stale>0&&task.stale<=wall.millis()){release(peer,task);return;}
        if(task.sent&&task.kind==Kind.REQUEST&&!task.force)return;
        if(task.attempts>=4){
            if(!task.failed){
                task.failed=true;failed++;
                if(task.kind==Kind.RECORD){
                    String old=peer.failed.put(task.uid,task.fingerprint);
                    if(!withinMetadata(peer)){
                        if(old==null)peer.failed.remove(task.uid);else peer.failed.put(task.uid,old);peer.sendBlocked=true;capacity++;
                    }
                }
            }
            if(task.kind==Kind.RECORD&&(!task.big()||now-task.first>=SyncFragments.LIFETIME_NANOS))release(peer,task);return;
        }
        if(task.sent&&now-task.last<RETRY_NANOS||!task.sent&&task.lastTry!=0&&now-task.lastTry<RETRY_NANOS)return;
        task.lastTry=now;boolean emitted=false;
        List<byte[]> frames=SyncFragments.split(task.wire,task.id);
        try{for(byte[] frame:frames)emitted|=sender.send(peer.id.clone(),peer.session.clone(),frame);}
        finally{for(byte[] frame:frames)Crypto.wipe(frame);}
        if(!emitted)return;
        if(!task.sent){task.first=now;task.sent=true;if(task.kind==Kind.RECORD)sent++;}else if(task.kind==Kind.RECORD)retries++;
        task.attempts++;task.last=now;task.force=false;if(task.big())peer.big=task;
        if(task.kind==Kind.REQUEST&&(!task.big()||requestAlreadySaved(task)))release(peer,task);
    }
    private boolean requestAlreadySaved(Task task){
        for(var entry:SyncWire.parse(task.wire).getRequest().getWantedList()){
            CotRecord item=committed.get(entry.getUid());
            if(item!=null&&(SyncInventory.compare(item,entry)>0||SyncInventory.matches(item,entry)))return true;
        }
        return false;
    }
    private int metadata(Peer peer){
        int size=(peer.offer==null?0:peer.offer.retainedBytes())+peer.receiver.retainedBytes()+64*peer.offeredOwn.size();
        if(peer.inventory!=null)size+=3*peer.inventory.wire.length+128;
        for(Task task:peer.requests.values())size+=3*task.wire.length+128+8*task.wanted.size();
        size+=SyncCache.REFERENCE_BYTES*peer.completedServes.size();
        for(Serve serve:peer.serves.values())size+=128+serve.entryBytes+160*(serve.waiting.size()+serve.attempted.size()+serve.unavailable.size());
        for(String uid:peer.deferred)size+=128+2*uid.length();
        for(String uid:peer.failed.keySet())size+=256+2*uid.length();
        for(String uid:peer.winnerReplies.keySet())size+=256+2*uid.length();return size;
    }
    private int metadata(){int result=0;for(Peer peer:peers.values())result+=metadata(peer);return result;}
    private boolean withinMetadata(Peer peer){return metadata(peer)<=limits.peerBytes()&&metadata()<=limits.totalBytes();}
    private int inventoryBudget(Peer peer){int existing=peer.receiver.retainedBytes();return Math.min(limits.peerBytes()-(metadata(peer)-existing),limits.totalBytes()-(metadata()-existing));}
    private int activeInventories(){int count=0;for(Peer peer:peers.values())if(peer.ownStarted&&!peer.ownDone||peer.receiver.started()&&!peer.remoteDone)count++;return count;}
    private void startOwn(Peer peer){
        if(peer.ownStarted||peer.ownDone||activeInventories()>=8&&!(peer.receiver.started()&&!peer.remoteDone))return;
        int available=Math.min(limits.peerBytes()-metadata(peer),limits.totalBytes()-metadata());
        try{peer.offer=SyncInventory.offer(committed,token(),wall.millis(),available,cache,scope(peer,"offer"),()->committed.copy(),this::sendable);}
        catch(IllegalArgumentException e){capacity++;return;}
        peer.offeredOwn=committed.localUids();
        if(!withinMetadata(peer)){releaseOffer(peer);capacity++;return;}
        peer.ownStarted=true;peer.ownStart=peer.smaller?peer.connected:ticker.getAsLong();peer.page=0;
    }
    private void inventory(Peer peer,byte[] wire,SyncFragments.Receipt receipt){
        if(peer.remoteFailed||peer.smaller&&!peer.ownDone||peer.remoteDone&&ticker.getAsLong()-peer.remoteStart>=CATCHUP_NANOS)throw new IllegalArgumentException("一覧の順が違います");
        if(!peer.receiver.started()&&activeInventories()>=8&&!(peer.ownStarted&&!peer.ownDone))throw new IllegalArgumentException("一覧の数が上限です");
        byte[] request=peer.receiver.accept(wire,entry->{
            if(blocksNew(entry.getUid()))return false;
            long time=entry.getVersion().getWallMillis(),now=wall.millis();
            if(time>now&&time-now>CotXml.MAX_FUTURE_MILLIS)return false;
            if(local(committed.origin(entry.getUid()))&&!external.contains(entry.getUid())&&!Crypto.equal(entry.getVersion().getEudId().toByteArray(),localId))return false;
            CotRecord current=committed.get(entry.getUid());return current==null||SyncInventory.compare(current,entry)<0;
        },inventoryBudget(peer));
        if(!peer.remoteStarted){peer.remoteStarted=true;peer.remoteStart=ticker.getAsLong();}
        try{queueRequest(peer,request,false);fragments.remember(receipt,List.of(request));}finally{Crypto.wipe(request);}
    }
    private void request(Peer peer,byte[] wire,SyncFragments.Receipt receipt){
        if(peer.offer==null)throw new IllegalArgumentException("出していない一覧への求めです");
        var envelope=SyncWire.parse(wire);int page=envelope.getRequest().getPage();
        if(page>peer.page)throw new IllegalArgumentException("出していないページへの求めです");
        List<SyncSchema.SyncInventoryEntry> wanted=peer.offer.request(wire);
        var completed=peer.completedServes.get(page);
        if(completed!=null){byte[] prior=cache.get(completed);if(prior!=null){Crypto.wipe(prior);return;}peer.completedServes.remove(page);}
        if(!peer.serves.containsKey(page)){
            var serve=new Serve(wanted,cache!=null);peer.serves.put(page,serve);
            if(!withinMetadata(peer)){peer.serves.remove(page);capacity++;return;}
        }
        if(peer.inventory!=null&&peer.inventory.page==page)release(peer,peer.inventory);
        fragments.remember(receipt,List.of());
    }
    private void archiveServe(Peer peer,int page,Serve serve){
        if(cache==null)return;
        byte[] wire=SyncWire.envelope().setRequest(SyncSchema.SyncRequest.newBuilder().setSnapshotId(SyncWire.bytes(peer.offer.id())).setPage(page).addAllWanted(serve.entries)).build().toByteArray();
        try{var ref=cache.put(scope(peer,"serves"),wire,2);if(ref!=null){peer.completedServes.put(page,ref);peer.serves.remove(page);}}finally{Crypto.wipe(wire);}
    }
    private void serve(Peer peer){
        for(Serve serve:peer.serves.values()){
            if(cache!=null)for(int n=serve.cursor;n<Math.min(serve.entries.size(),serve.cursor+32);n++){
                CotRecord next=committed.get(serve.entries.get(n).getUid());if(next!=null)next.prefetch();
            }
            while(serve.cursor<serve.entries.size()){
                var requested=serve.entries.get(serve.cursor);CotRecord item=committed.get(requested.getUid());
                int extra=(serve.waiting.containsKey(requested.getUid())?0:160)+(serve.attempted.containsKey(requested.getUid())?0:160);
                if(metadata(peer)+extra>limits.peerBytes()||metadata()+extra>limits.totalBytes()){capacity++;break;}
                if(!sendable(item)||item.hop()>=CotRecord.MAX_HOP){serve.unavailable.add(requested.getUid());serve.cursor++;continue;}
                Task task=queueRecord(peer,item,true);if(task==null)break;
                serve.waiting.put(item.uid(),task.fingerprint);serve.attempted.put(item.uid(),task.fingerprint);serve.cursor++;
            }
            for(var entry:new ArrayList<>(serve.waiting.entrySet())){
                if(peer.records.containsKey(entry.getKey()))continue;CotRecord current=committed.get(entry.getKey());
                if(current!=null&&!key(current.hash()).equals(serve.attempted.get(entry.getKey()))){
                    Task task=queueRecord(peer,current,true);if(task!=null){serve.waiting.put(entry.getKey(),task.fingerprint);serve.attempted.put(entry.getKey(),task.fingerprint);}
                }
            }
        }
        for(var entry:new ArrayList<>(peer.serves.entrySet()))if(entry.getKey()!=peer.page&&entry.getValue().complete())archiveServe(peer,entry.getKey(),entry.getValue());
        Serve current=peer.serves.get(peer.page);
        if(current!=null&&current.complete()){
            archiveServe(peer,peer.page,current);
            peer.page++;peer.offer.prefetch(peer.page);
            if(peer.page==peer.offer.pageCount()){peer.ownDone=true;releaseOffer(peer);}
        }
    }
    private boolean requestedSaved(Peer peer){
        return peer.receiver.requestedSaved(wanted->{
            CotRecord item=committed.get(wanted.getUid());if(item==null)return false;
            int order=SyncInventory.compare(item,wanted);return order>0||order==0&&SyncInventory.matches(item,wanted);
        });
    }

    private void missing(Peer peer){
        if(peer.missingDone||!peer.receiver.complete()||!requestedSaved(peer))return;
        while(true){
            CotRecord next=null;
            for(CotRecord item:committed.records())if(sendable(item)&&item.hop()<CotRecord.MAX_HOP
                    &&(peer.missingCursor==null||SyncState.compareUid(item.uid(),peer.missingCursor)>0)
                    &&!peer.receiver.knows(item.uid())&&(next==null||SyncState.compareUid(item.uid(),next.uid())<0))next=item;
            if(next==null){peer.missingDone=true;peer.remoteDone=true;return;}
            if(queueRecord(peer,next,false)==null)return;peer.missingCursor=next.uid();
        }
    }
    private void failOwn(Peer peer){
        if(peer.ownDone)return;failed++;peer.ownDone=true;releaseOffer(peer);if(peer.inventory!=null)release(peer,peer.inventory);
    }
    private void failRemote(Peer peer){
        if(peer.remoteDone||peer.remoteFailed)return;failed++;peer.remoteFailed=true;peer.receiver.close();peer.receiver=receiver(peer);
        for(Task task:new ArrayList<>(peer.requests.values()))release(peer,task);
    }
    private void pumpPeer(Peer peer){
        long now=ticker.getAsLong();
        if(peer.remoteDone&&now-peer.remoteStart>=CATCHUP_NANOS){peer.receiver.close();peer.receiver=receiver(peer);}
        if(peer.smaller&&!peer.ownStarted&&now-peer.connected>=CATCHUP_NANOS)failOwn(peer);
        if(peer.remoteStarted&&!peer.remoteDone&&!peer.remoteFailed&&now-peer.remoteStart>=CATCHUP_NANOS)failRemote(peer);
        if(!peer.ownStarted&&!peer.ownDone&&(peer.smaller||peer.remoteDone||peer.remoteFailed))startOwn(peer);
        if(peer.ownStarted&&!peer.ownDone&&now-peer.ownStart>=CATCHUP_NANOS)failOwn(peer);
        if(peer.offer!=null)serve(peer);
        missing(peer);
        if(!peer.smaller&&!peer.ownStarted&&(peer.remoteDone||peer.remoteFailed))startOwn(peer);
        if(peer.offer!=null&&peer.inventory==null&&!peer.serves.containsKey(peer.page)){
            byte[] wire;
            try{wire=peer.offer.page(peer.page);}catch(SyncInventory.CacheMiss e){return;}

            int charge=3*wire.length+128;
            // 確定済みのページは書き換えず、外来になった自作の項目を含む間は出さない。
            if(pageSendable(peer,wire)&&room(peer,wire.length)&&metadata(peer)+charge<=limits.peerBytes()&&metadata()+charge<=limits.totalBytes()){peer.inventory=new Task(Kind.INVENTORY,wire,token(),null,peer.page,Set.of(),false);outgoingBytes+=wire.length;}
            else Crypto.wipe(wire);
        }
        for(String uid:new ArrayList<>(peer.deferred)){
            CotRecord item=committed.get(uid);
            if(item==null||!item.deleted()&&item.stale()<=wall.millis()||item.hop()>=CotRecord.MAX_HOP||key(item.hash()).equals(peer.failed.get(uid))){peer.deferred.remove(uid);continue;}
            if(local(committed.origin(uid))&&localDeferred.contains(uid))continue;
            if(queueRecord(peer,item,false,true)!=null)peer.deferred.remove(uid);
        }
        // 要求された記録を次の一覧より先に送り、相手の大きいRequestの枠を空ける。
        for(Task task:new ArrayList<>(peer.records.values()))send(peer,task);
        for(Task task:new ArrayList<>(peer.requests.values()))send(peer,task);
        if(peer.inventory!=null)send(peer,peer.inventory);
    }
    public SyncState snapshot(){open();return committed.copy();}
    public ExternalMarks externalSnapshot(){open();return external.copy();}
    public boolean externalFull(){open();return external.full();}
    public boolean isClosed(){return closed;}
    public Statistics statistics(){return new Statistics(sent,received,rejected,unknown,tooLarge,capacity,clockBlocked,retries,failed,pending(),outgoingBytes);}
    /** 保存した受信更新のうち、外来の印と一致して取り込み通知をしなかった件数。 */
    public long externalImportsSkipped(){return externalImportsSkipped;}
    private long externalExpired;
    public long externalExpired(){return externalExpired;}
    @Override public void close(){
        if(closed)return;closed=true;renewalEndpoint=null;renewed=null;for(Peer peer:new ArrayList<>(peers.values()))disconnected(peer.id);
        for(Waiting waiting:acks.values())Crypto.wipe(waiting.ack);acks.clear();waitingBytes=0;fragments.close();changes.clear();
        lastLocal.clear();localDeferred.clear();blockedCreated.clear();createdThisCapture.clear();discardRestored();Crypto.wipe(primaryEncoded);primaryEncoded=null;if(cache!=null)cache.close();bodies.clear();ownNames.clear();positionUid=null;committed=null;working=null;Crypto.wipe(localId);
    }
}
