// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.time.Clock;
import java.util.*;

/**
 * 保存中の通信と限定回復を調整する核の入口。共有状態は sessions のロックで扱い、保存 I/O はその外で行う。
 * 製品の CoT・DHT・管理操作は第8回で execute に接続する（04 §4.5）。
 * <p>
 * Core entry point coordinating communication during persistence and limited recovery. Shared state uses the sessions lock;
 * persistence I/O runs outside it. Product CoT, DHT and management operations connect to execute in round eight (04 §4.5).
 */
public final class CorePersistenceCoordinator {
    public enum State {RUNNING,PERSISTING,STORAGE_FAILED,RECOVERING_REVOCATIONS}
    public enum Operation {HANDSHAKE,RECOVERY_REQUEST,REVOCATION_PAGE,PAGE_ACK,COT_SEND,COT_RECEIVE,CATCH_UP,
        KEY_ANNOUNCEMENT,KEY_WRAP,KEY_APPLY,DHT_READ,DHT_WRITE,TRANSFER,ADMINISTRATION,ROSTER,INVITATION,RENEWAL,RECONNECT}
    public enum KeyResult {APPLIED,DEFERRED,REJECTED,CANCELLED,STALE}
    /**
     * active → 保存 → 照合と clear の順で呼ぶ。各段階は同期完了まで戻らない。印の実 I/O は第7回で実装する。
     * <p>
     * Invoked in active, save, then verify-and-clear order. Each stage returns only after synchronization. Actual marker I/O is round seven.
     */
    public interface PersistenceHooks {
        default void active(AdminRecordStore.Snapshot candidate){}
        void save(AdminRecordStore.Snapshot candidate);
        default void clear(AdminRecordStore.Snapshot candidate){}
        default void saveKey(byte[] key,long version){throw new UnsupportedOperationException("Key persistence required");}
        default void stopped(){}
        default void selfRevoked(){}
    }
    /**
     * 起動側で検証した停止時の要件。集合が再構成できないときは null を渡し、候補との digest の完全一致を要求する。
     * <p>
     * Stop requirements verified by startup. Pass null for an unreconstructable set to require exact candidate digest equality.
     */
    public static final class RecoveryRequirement {
        private final long version;private final byte[] digest;private final List<byte[]> subjects;
        public RecoveryRequirement(long version,byte[] digest,List<byte[]> subjects){
            Crypto.length(digest,32);this.version=version;this.digest=digest.clone();
            this.subjects=subjects==null?null:canonical(subjects);
            if(this.subjects!=null&&!Crypto.equal(digest,revocationDigest(this.subjects)))throw invalid();
        }
        boolean covers(AdminRecords.Record candidate){
            if(Long.compareUnsigned(candidate.version(),version)<0)return false;
            if(subjects==null)return Crypto.equal(digest,revocationDigest(candidate.entries()));
            for(byte[] subject:subjects)if(!candidate.hasEntry(subject))return false;return true;
        }
    }
    private record Notice(byte[] session,long generation,long began,byte[] record){}
    private final AdminState admin;
    private final SessionManager sessions;
    private final RevocationUnion revocations;
    private final Clock wall,deadlines;
    private final byte[] group;
    private State state;
    private long operation,recoveryStarted;
    private RecoveryRequirement requirement;
    private byte[] recoveryPeer,recoverySession,recoveryOperation;
    private long recoveryGeneration;
    private final ManagementPageAssembler recoveryPages;
    private final Map<DhtId,Notice> notices=new HashMap<>();
    public CorePersistenceCoordinator(AdminState admin,SessionManager sessions,RevocationUnion revocations,Clock wall,Clock deadlines){
        this(admin,sessions,revocations,wall,deadlines,null);
    }
    /**
     * 回復では再起動後の新しい SessionManager を渡す。旧セッションや停止済みインスタンスを復元しない。
     * <p>
     * Recovery requires a fresh SessionManager after restart; never restores old sessions or stopped instances.
     */
    public CorePersistenceCoordinator(AdminState admin,SessionManager sessions,RevocationUnion revocations,Clock wall,Clock deadlines,
            RecoveryRequirement requirement){
        this.admin=Objects.requireNonNull(admin);this.sessions=Objects.requireNonNull(sessions);
        this.revocations=Objects.requireNonNull(revocations);this.wall=Objects.requireNonNull(wall);this.deadlines=Objects.requireNonNull(deadlines);
        group=admin.administrators().group();this.requirement=requirement;
        recoveryPages=new ManagementPageAssembler(group,deadlines,new TransferResources());
        synchronized(sessions){
            state=requirement==null?State.RUNNING:State.RECOVERING_REVOCATIONS;recoveryStarted=deadlines.millis();
            sessions.coordinate(this,requirement!=null);
        }
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("Invalid persistence or recovery state");}
    public State state(){synchronized(sessions){return state;}}
    public String statusText(){synchronized(sessions){return state==State.STORAGE_FAILED||state==State.RECOVERING_REVOCATIONS?"保存がいっぱい":"";}}
    public boolean isRevoked(byte[] subject){synchronized(sessions){return revocations.contains(subject);}}
    public boolean permits(Operation op){synchronized(sessions){
        Objects.requireNonNull(op);
        if(sessions.isClosed())return false;
        if(state==State.RUNNING)return true;
        return state==State.RECOVERING_REVOCATIONS&&!recoveryExpired()&&switch(op){
            case HANDSHAKE,RECOVERY_REQUEST,REVOCATION_PAGE,PAGE_ACK->true;default->false;};
    }}
    void require(Operation op){if(!permits(op))throw new IllegalStateException("Group communication is suspended");}
    /**
     * 操作の判定と開始を保存開始と同じロックで行う。保存 I/O を action に渡さない。
     * <p>
     * Checks and starts an operation under the persistence-entry lock. Do not supply persistence I/O as action.
     */
    public void execute(Operation op,Runnable action){synchronized(sessions){require(op);action.run();}}
    boolean acceptsPackets(){return permits(Operation.HANDSHAKE);}
    void requireData(byte[] wire){
        if(state==State.RUNNING)return;
        if(state!=State.RECOVERING_REVOCATIONS||recoveryExpired())throw new IllegalStateException("Group communication is suspended");
        try{
            var body=ManagementWire.unwrap(wire);
            switch(body.field()){
                case ManagementEnvelopeFields.REVOCATIONS_RECOVERY_REQUEST->RevocationsRecoveryRequest.decodeEnvelope(wire);
                case ManagementEnvelopeFields.REVOCATION_PAGE->{
                    if(ManagementPage.decodeEnvelope(wire).kind()!=ManagementPage.Kind.REVOCATION)throw invalid();
                }
                case ManagementEnvelopeFields.PAGE_ACK->ManagementPageAck.decodeEnvelope(wire);
                default->throw invalid();
            }
        }catch(java.io.IOException|IllegalArgumentException bad){throw new SecurityException("Recovery traffic only");}
    }
    private boolean recoveryExpired(){return deadlines.millis()-recoveryStarted>=ManagementPageAssembler.TOTAL_MILLIS;}
    public void poll(){synchronized(sessions){
        sessions.refresh();recoveryPages.poll();
        notices.entrySet().removeIf(e->deadlines.millis()-e.getValue().began>=1000);
        if(state==State.RECOVERING_REVOCATIONS&&(recoveryExpired()||sessions.isClosed())){
            recoveryPages.clear();recoveryPeer=null;recoverySession=null;recoveryOperation=null;
        }
    }}
    private void verifyRevocations(AdminRecords.Record candidate){
        if(candidate.format()!=2)throw new SecurityException("Format two required");
        candidate.verify(AdminRecords.Kind.REVOCATIONS,group,admin.administrators());
        if(candidate.signedAt()>wall.millis()&&candidate.signedAt()-wall.millis()>300_000)throw new SecurityException("Future signing time");
    }
    public boolean receiveRevocations(AdminRecords.Record candidate,PersistenceHooks hooks){return persist(candidate,hooks,true,false);}
    public boolean persistLocalRevocations(AdminRecords.Record candidate,PersistenceHooks hooks){return persist(candidate,hooks,false,false);}
    private boolean persist(AdminRecords.Record candidate,PersistenceHooks hooks,boolean received,boolean recovery){
        Objects.requireNonNull(hooks);final AdminState prepared;final AdminRecordStore.Snapshot base,next;final long token,generation;
        synchronized(sessions){
            if(recovery){if(state!=State.RECOVERING_REVOCATIONS||recoveryExpired())return false;}
            else require(Operation.ADMINISTRATION);
            verifyRevocations(candidate);
            if(recovery&&(!requirement.covers(candidate)||!revocations.covers(candidate)))return false;
            base=admin.snapshot();prepared=admin.fork();boolean changed=prepared.acceptRevocations(candidate);
            if(!changed&&!recovery)return false;
            if(recovery&&(!requirement.covers(prepared.revocations())||!revocations.covers(prepared.revocations())))return false;
            next=prepared.snapshot();generation=sessions.generation();token=++operation;
            if(received){
                byte[] encoded=candidate.encode();
                if(encoded.length<=4*ManagementPage.PAGE_BYTES)for(byte[] subject:candidate.entries()){
                    var verified=sessions.verifiedSession(subject);
                    if(verified!=null)notices.put(new DhtId(subject),new Notice(verified.sessionId(),generation,deadlines.millis(),encoded));
                }
                revocations.add(candidate);
                sessions.rejectRevokedPeers();
            }
            state=State.PERSISTING;
        }
        try{
            if(received)hooks.active(next);
            hooks.save(next);admin.persistPrepared(base,prepared);
            if(received)hooks.clear(next);
            final boolean selfRevoked;
            synchronized(sessions){
                if(operation!=token||state!=State.PERSISTING||sessions.generation()!=generation||!AdminState.sameSnapshot(base,admin.snapshot()))
                    throw new IllegalStateException("Stale persistence completion");
                verifyRevocations(candidate);
                admin.publishPrepared(base,prepared);if(!received)revocations.add(candidate);
                sessions.rejectRevokedPeers();sessions.refresh();
                state=State.RUNNING;requirement=null;recoveryPages.clear();
                selfRevoked=sessions.localRevoked();
            }
            if(selfRevoked)hooks.selfRevoked();return true;
        }catch(RuntimeException failure){
            synchronized(sessions){
                if(operation==token){
                    if(received){state=State.STORAGE_FAILED;sessions.storageFailed();recoveryPages.clear();}
                    else state=State.RUNNING;
                }
            }
            if(received)hooks.stopped();return false;
        }
    }
    /**
     * 署名済みの正確な失効ページだけに、対象の旧セッションで最長1秒の一方向通知を認める。送信予算は既存の通知部品が管理する。
     * <p>
     * Allows only exact signed revocation pages on the target's old session for at most one second. Existing notice components enforce send budgets.
     */
    public boolean maySendFinalNotice(byte[] peer,byte[] session,long generation,byte[] wire){synchronized(sessions){
        if(state==State.STORAGE_FAILED||state==State.RECOVERING_REVOCATIONS)return false;
        var notice=notices.get(new DhtId(peer));
        if(notice==null||notice.generation!=generation||!Arrays.equals(session,notice.session)||deadlines.millis()-notice.began>=1000)return false;
        try{
            var page=ManagementPage.decodeEnvelope(wire);
            if(page.kind()!=ManagementPage.Kind.REVOCATION||!Crypto.equal(page.group(),group))return false;
            var expected=ManagementPage.split(ManagementPage.Kind.REVOCATION,page.operationId(),group,notice.record,
                    AdminRecords.decode(notice.record).entries().size());
            return page.pageIndex()<expected.size()&&Arrays.equals(wire,expected.get(page.pageIndex()).envelope());
        }catch(RuntimeException invalid){return false;}
    }}
    /**
     * 回復要求を認証済みの相手・セッション・世代へ結ぶ。同じ要求の再送では開始期限も操作も変えない。
     * <p>
     * Binds recovery requests to an authenticated peer, session and generation. Retries change neither deadline nor operation.
     */
    public boolean bindRecovery(byte[] peer,byte[] session,long generation,RevocationsRecoveryRequest request){synchronized(sessions){
        if(state!=State.RECOVERING_REVOCATIONS||recoveryExpired()||!current(peer,session,generation)
                ||!Crypto.equal(group,request.group())||request.requiredVersion()!=requirement.version||!Crypto.equal(request.targetDigest(),requirement.digest))return false;
        if(recoveryPeer!=null&&!current(recoveryPeer,recoverySession,recoveryGeneration)){
            recoveryPages.forget(recoveryPeer);recoveryPeer=null;recoverySession=null;
        }
        if(recoveryPeer!=null)return Arrays.equals(peer,recoveryPeer)&&Arrays.equals(session,recoverySession)
                &&generation==recoveryGeneration&&Arrays.equals(request.operationId(),recoveryOperation);
        recoveryPeer=peer.clone();recoverySession=session.clone();recoveryGeneration=generation;recoveryOperation=request.operationId();return true;
    }}
    private boolean current(byte[] peer,byte[] session,long generation){
        var verified=sessions.verifiedSession(peer);return verified!=null&&verified.generation()==generation&&Arrays.equals(session,verified.sessionId());
    }
    public ManagementPageAssembler.Result receiveRecoveryPage(byte[] peer,byte[] session,long generation,ManagementPage page,PersistenceHooks hooks){
        final ManagementPageAssembler.Result result;
        synchronized(sessions){
            if(state!=State.RECOVERING_REVOCATIONS||recoveryExpired()||recoveryPeer==null||!Arrays.equals(peer,recoveryPeer)
                    ||!Arrays.equals(session,recoverySession)||generation!=recoveryGeneration||!current(peer,session,generation)
                    ||page.kind()!=ManagementPage.Kind.REVOCATION||!Arrays.equals(page.operationId(),recoveryOperation))
                return new ManagementPageAssembler.Result(ManagementPageAssembler.Status.REJECTED,null);
            result=recoveryPages.receive(peer,session,generation,page);
        }
        if(result.completed()!=null){
            try{persist(AdminRecords.decode(result.completed().data()),hooks,true,true);}
            catch(RuntimeException invalid){return new ManagementPageAssembler.Result(ManagementPageAssembler.Status.REJECTED,null);}
        }
        return result;
    }
    /**
     * 失効本体を保存した後でだけ包みを開く。新鍵の保存後も期限・世代・現在版を再検査する。
     * <p>
     * Opens wraps only after persisting their revocation body. Rechecks deadlines, generation and current version after key persistence.
     */
    public KeyResult applyGroupKey(KeyAnnouncement announcement,AdminRecords.Record wrap,byte[] recipient,byte[] handshakeSecret,
            long expectedVersion,long expectedGeneration,PersistenceHooks hooks){
        byte[] next=null;long token;final AdminRecordStore.Snapshot base;
        synchronized(sessions){
            if(state!=State.RUNNING)return KeyResult.DEFERRED;
            sessions.refresh();if(sessions.isClosed()||sessions.generation()!=expectedGeneration||sessions.keyVersion()!=expectedVersion)return KeyResult.REJECTED;
            var r=admin.revocations();
            if(r.version()!=announcement.revocationVersion()||!Crypto.equal(Crypto.blake2s(r.signedBytes()),announcement.revocationDigest()))return KeyResult.DEFERRED;
            try{
                verifyRevocations(r);var admins=admin.administrators();announcement.verify(group,admins.entries());
                if(announcement.adminVersion()!=admins.version()||!Crypto.equal(announcement.adminDigest(),Crypto.blake2s(admins.signedBytes()))
                        ||announcement.signedAt()>wall.millis()+300_000||!revocations.covers(r)||revocations.contains(recipient)
                        ||!sessions.matchesLocalRecipient(recipient,Crypto.x25519Public(handshakeSecret))
                        ||wrap.format()!=2||wrap.version()!=announcement.keyVersion()||!Crypto.equal(wrap.field(4),Crypto.blake2s(announcement.signedBytes())))return KeyResult.REJECTED;
                wrap.verify(AdminRecords.Kind.WRAPPED_KEY,group,admins);
                if(wrap.signedAt()>wall.millis()+300_000)return KeyResult.REJECTED;
                try(var opened=GroupKeyEnvelope.open(wrap,recipient,handshakeSecret,expectedVersion)){next=opened.copy();}
                if(!Crypto.equal(KeyAnnouncement.commitment(group,wrap.version(),next),announcement.keyCommitment())){Crypto.wipe(next);return KeyResult.REJECTED;}
            }catch(RuntimeException invalid){Crypto.wipe(next);return KeyResult.REJECTED;}
            base=admin.snapshot();state=State.PERSISTING;token=++operation;
        }
        try{
            byte[] borrowed=next.clone();
            try{hooks.saveKey(borrowed,wrap.version());}finally{Crypto.wipe(borrowed);}
            synchronized(sessions){
                sessions.refresh();
                if(state!=State.PERSISTING||operation!=token||sessions.isClosed()||sessions.generation()!=expectedGeneration
                        ||sessions.keyVersion()!=expectedVersion||!AdminState.sameSnapshot(base,admin.snapshot())){
                    if(operation==token)state=State.RUNNING;return KeyResult.STALE;
                }
                state=State.RUNNING;sessions.rotateGroupKey(next,wrap.version());return KeyResult.APPLIED;
            }
        }catch(RuntimeException failure){synchronized(sessions){if(operation==token)state=State.RUNNING;}return KeyResult.CANCELLED;}
        finally{Crypto.wipe(next);}
    }
    private static List<byte[]> canonical(List<byte[]> subjects){
        if(subjects.size()>AdminRecords.MAX_ENTRIES)throw invalid();var sorted=new TreeSet<byte[]>(AdminRecords::compareBytes);
        for(byte[] subject:subjects){Crypto.length(subject,32);sorted.add(subject.clone());}return List.copyOf(sorted);
    }
    public static byte[] revocationDigest(List<byte[]> subjects){
        var sorted=canonical(subjects);byte[] bytes=new byte[sorted.size()*32];int offset=0;
        for(byte[] subject:sorted){System.arraycopy(subject,0,bytes,offset,32);offset+=32;}return Crypto.blake2s(bytes);
    }
    @Override public String toString(){return "Core persistence coordinator";}
}
