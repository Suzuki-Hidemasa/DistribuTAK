// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.time.Clock;
import java.io.IOException;
import java.util.function.Consumer;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
/** stateを原子的に確定し、そのあとsettingsを追いつかせる。AndroidとPCで同じ順を使う。 */
final class GroupStateStorage {
    private final StateEnvelope envelope;
    private final StateEnvelope.AtomicTarget target,settingsTarget;
    private final SyncStateStorage.Source source,settingsSource;
    private final Consumer<String> log;
    private boolean large;
    private VersionSixStorage six;
    GroupStateStorage(StateEnvelope envelope,StateEnvelope.AtomicTarget target,SyncStateStorage.Source source,
                      StateEnvelope.AtomicTarget settingsTarget,SyncStateStorage.Source settingsSource,Consumer<String> log) {
        this.envelope=envelope;this.target=target;this.source=source;this.settingsTarget=settingsTarget;this.settingsSource=settingsSource;this.log=log;
    }
    GroupStateStorage(StateEnvelope envelope,StateEnvelope.AtomicTarget target,SyncStateStorage.Source source,
                      StateEnvelope.AtomicTarget settingsTarget,SyncStateStorage.Source settingsSource,Consumer<String> log,
                      ManagementFiles files,StopMarker marker){
        this(envelope,target,source,settingsTarget,settingsSource,log);six=new VersionSixStorage(envelope,files,marker);
    }
    io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator.PersistenceHooks persistenceHooks(LanGroup group){
        if(six==null)throw new IllegalStateException("管理保存先がありません");return six.hooks(group,target,()->writeSettings(group));
    }
    void saveDirectory(LanGroup group,io.github.hidemas_suzuki_aka_ziek.distributak.core.MemberDirectory directory,java.util.Map<String,String> labels)throws Exception{
        if(six==null)throw new IllegalStateException("管理保存先がありません");
        int size=six.saveDirectory(group,target,directory,labels);writeSettings(group);observeSize(size);six.cleanup(group);
    }
    void prepareNetwork(LanGroup group)throws Exception{if(six!=null)six.prepareNetwork(group);}
    void saveMembership(LanGroup group,io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordStore.Snapshot snapshot,byte[] secret)throws Exception{
        if(six==null)throw new IllegalStateException("管理保存先がありません");
        int size=six.saveMembership(group,target,snapshot,secret);writeSettings(group);observeSize(size);six.cleanup(group);
    }
    private void diagnostic(String fixed){try{log.accept(fixed);}catch(RuntimeException ignored){}}
    LanGroup load(Clock clock)throws Exception {
        if(!source.exists())return null;
        byte[] wire=source.read(),plain=null;LanGroup group=null;
        try {
            plain=envelope.open(wire);group=LanGroup.decode(plain,clock,true,six==null?null:six::read);
            StateSettings settings=readSettings();
            if(settings!=null)settings.check(group);
            if(settings==null||settings.saveSeq<group.saveSeq||settings.port!=group.port)writeSettings(group);
            if(group.management!=null)six.inspect(group);else if(six!=null)six.inspectLegacy(group);
            // 保存時の形で停止印を照合したあとに、失効相手と更新待ちを整理する。
            // Clean up revoked peers and pending renewals after checking the marker against the saved shape.
            group.cleanPendingRenewals();
            group.forgetRevokedPeer();
            if(group.revokedPeerForgotten&&!group.storageBlocked&&(six==null||group.management!=null))try{save(group);}catch(Exception e){diagnostic("LAN_REVOKED_PEER_SAVE_FAILED");}
            observeSize(wire.length);var result=group;group=null;return result;
        }finally{Crypto.wipe(wire);Crypto.wipe(plain);if(group!=null)group.close();}
    }
    private StateSettings readSettings()throws Exception {
        if(!settingsSource.exists())return null;
        byte[] bytes=null;
        try{bytes=settingsSource.read();return StateSettings.decode(bytes);}
        catch(IOException|RuntimeException e){return null;}
        finally{Crypto.wipe(bytes);}
    }
    private void writeSettings(LanGroup group) {
        try{StateEnvelope.writeAtomic(StateSettings.of(group).encode(),settingsTarget);}
        catch(Exception e){diagnostic("LAN_SETTINGS_SAVE_FAILED");}
    }
    void save(LanGroup group)throws Exception {
        if(six!=null){int size=six.save(group,target);writeSettings(group);observeSize(size);six.cleanup(group);return;}
        long previous=group.saveSeq;group.saveSeq=Math.addExact(previous,1);byte[] plain=null,wire=null;int size;
        try {
            plain=group.encode();wire=envelope.seal(plain);size=wire.length;
            StateEnvelope.writeAtomic(wire,target);wire=null;
        }catch(Exception e){group.saveSeq=previous;throw e;}
        finally{Crypto.wipe(plain);Crypto.wipe(wire);}
        writeSettings(group);observeSize(size);
    }
    /**
     * DHT に出す記録の次の版を予約する（04 の 8.3）。版を1つ上げ、saveSeq を1つ上げて state を保存し、settings が追いつく。
     * state の保存に失敗したら版と saveSeq を元に戻して失敗を返す。settings だけ失敗したときは save と同じく成功として扱う（state が正）。
     * 版は Long.MAX_VALUE-1 で止まる。上限では何も進めず失敗を返す。
     * 呼ぶスレッドは save と同じ（Controller の作業スレッドだけ。同時には呼ばない）。
     */
    long reserveDhtVersion(LanGroup group)throws Exception {
        long previous=group.dhtLocalVersion;
        if(previous<0||previous>=Long.MAX_VALUE-1)throw new IllegalStateException("DHT の版が上限です");
        group.dhtLocalVersion=previous+1;
        try{save(group);return group.dhtLocalVersion;}
        catch(Exception e){group.dhtLocalVersion=previous;throw e;}
    }
    private final class Pending implements LanRuntime.Pending {
        final LanGroup group;final long previous;final StagedState staged;final int size;final byte[] digest;
        boolean finished;
        VersionSixStorage.Candidate candidate;
        Pending(LanGroup group,long previous,StagedState staged,int size,byte[] digest){this.group=group;this.previous=previous;this.staged=staged;this.size=size;this.digest=digest;}
        public void commit()throws Exception {
            if(finished)throw new IllegalStateException("仮の保存は確定か取消済みです");
            try{
                if(candidate!=null&&!ManagementState.sameSnapshot(group.state.snapshot(),candidate.management.snapshot))throw new SecurityException("仮の管理状態が変わっています");
                byte[] current=candidate==null?group.encode():group.encodeSix(candidate.management,candidate.management.generation,candidate.digest,null,group.keyVersion);
                try{if(!Crypto.equal(digest,Crypto.blake2s(current)))throw new SecurityException("仮の保存の中身が変わっています");}
                finally{Crypto.wipe(current);}
                staged.commit();
            }
            catch(Exception e){
                if(!staged.committed()){group.saveSeq=previous;throw e;}
                diagnostic("LAN_STAGING_CLEANUP_FAILED");
            }
            if(candidate!=null){six.stagedCommitted(group,candidate);candidate.close();candidate=null;}
            finished=true;Crypto.wipe(digest);writeSettings(group);observeSize(size);if(six!=null)six.cleanup(group);
        }
        public void abort()throws Exception {
            if(finished)return;
            try{staged.abort();}finally{group.saveSeq=previous;finished=true;Crypto.wipe(digest);if(candidate!=null){candidate.close();candidate=null;}}
        }
    }
    LanRuntime.Pending stage(LanGroup group,StateEnvelope.AtomicTarget temporary,StagedState.Read read,LanController.Action delete)throws Exception {
        long previous=group.saveSeq;byte[] plain=null;VersionSixStorage.Candidate candidate=null;
        try {
            if(six!=null)candidate=six.stage(group);
            group.saveSeq=Math.addExact(previous,1);
            byte[] check=candidate==null?group.encode():candidate.state.clone();byte[] digest;
            try{digest=Crypto.blake2s(check);}finally{Crypto.wipe(check);}
            plain=candidate==null?group.encode():candidate.state.clone();int size=plain.length+StateEnvelope.HEADER_BYTES+12+16;
            var staged=new StagedState(envelope,plain,temporary,read,delete,target);plain=null;
            var result=new Pending(group,previous,staged,size,digest);result.candidate=candidate;candidate=null;return result;
        }catch(Exception e){group.saveSeq=previous;throw e;}
        finally{Crypto.wipe(plain);if(candidate!=null)candidate.close();}
    }
    void acceptRejoined(LanGroup previous,LanGroup candidate,java.util.concurrent.Future<?> future,LanRuntime.Pending staged)throws Exception {
        if(!(staged instanceof GroupStateStorage.Pending pending)||pending.group!=candidate)
            throw new SecurityException("入り直しの仮の保存が違います");
        try {
            LanGroup.checkRejoined(previous,candidate);
            if(candidate.saveSeq!=Math.addExact(previous.saveSeq,1))throw new SecurityException("入り直しの保存の順が違います");
            StoreRecovery.acceptJoined(future,staged::commit);
        }catch(Exception e){
            if(!pending.finished&&!pending.staged.committed())try{pending.abort();}catch(Exception cleanup){e.addSuppressed(cleanup);}
            throw e;
        }
    }
    boolean saveIssuedRenewal(LanGroup group,byte[] peerId,byte[] certificate)throws Exception {
        byte[] previous=group.pendingRenewal(peerId);
        if(java.util.Arrays.equals(previous,certificate)){Crypto.wipe(previous);return false;}
        try {
            group.rememberRenewal(peerId,certificate);
            try{save(group);return true;}
            catch(Exception e){Crypto.wipe(group.removeRenewal(peerId));group.restoreRenewal(peerId,previous);previous=null;throw e;}
        }finally{Crypto.wipe(previous);}
    }
    boolean saveLocalRenewal(LanGroup group,io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Record certificate)throws Exception {
        group.state.verifyCertificate(certificate,Crypto.x25519Public(group.handshakeSecret));
        if(!Crypto.equal(certificate.field(0),group.certificate.field(0)))throw new SecurityException("自分の身元が違います");
        if(java.util.Arrays.equals(certificate.encode(),group.certificate.encode()))return false;
        if(certificate.issuedAt()<=group.certificate.issuedAt())throw new SecurityException("証明書の発行が新しくありません");
        var previous=group.certificate;int count=group.renewalCount;
        group.renewalCount=Math.addExact(count,1);group.certificate=certificate;
        try{save(group);return true;}catch(Exception e){group.certificate=previous;group.renewalCount=count;throw e;}
    }
    boolean savePeer(LanGroup group,io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Record certificate,java.net.InetSocketAddress address)throws Exception {
        group.state.verifyCertificate(certificate,certificate.field(1));
        var previous=group.peerCertificate;
        if(previous!=null) {
            if(!Crypto.equal(previous.field(0),certificate.field(0)))throw new SecurityException("相手の身元が違います");
            if(java.util.Arrays.equals(previous.encode(),certificate.encode()))return false;
            if(certificate.issuedAt()<=previous.issuedAt())throw new SecurityException("証明書の発行が新しくありません");
        }
        var oldAddress=group.peerAddress;byte[] pin=group.pendingHandshake;var pinAddress=group.pendingAddress;
        byte[] id=Crypto.blake2s(certificate.field(0)),renewal=group.removeRenewal(id);
        group.peerCertificate=certificate;group.peerAddress=address;group.pendingHandshake=null;group.pendingAddress=null;
        try{save(group);group.retainPeerCertificatePermission();Crypto.wipe(pin);Crypto.wipe(renewal);return true;}
        catch(Exception e){group.peerCertificate=previous;group.peerAddress=oldAddress;group.pendingHandshake=pin;group.pendingAddress=pinAddress;group.restoreRenewal(id,renewal);throw e;}
    }
    void observeSize(int size){large=size>512*1024;if(large)diagnostic("LAN_STATE_LARGE");}
    boolean largeState(){return large;}
}
