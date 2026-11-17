// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * 管理世代を先に確定し、state の参照だけを原子的に切り替える。
 * <p>
 * Commits management generations first, atomically switching only the state reference.
 */
final class VersionSixStorage {
    private static final byte[] PURPOSE="DistribuTAK/state-candidate/v6".getBytes(StandardCharsets.US_ASCII);
    private final StateEnvelope stateEnvelope,managementEnvelope;
    private final ManagementFiles files;
    private final StopMarker marker;
    private Candidate pending;
    private LanGroup owner;
    VersionSixStorage(StateEnvelope envelope,ManagementFiles files,StopMarker marker){
        stateEnvelope=envelope;managementEnvelope=envelope.withMaximum(ManagementState.MAX_ENVELOPE_BYTES);this.files=files;this.marker=marker;
    }
    ManagementState read(long generation,byte[] digest)throws Exception{
        byte[] wire=files.read(generation),plain=null;
        try{if(!Crypto.equal(Crypto.blake2s(wire),digest))throw new IOException("管理ファイルの参照が違います");
            plain=managementEnvelope.open(wire);return ManagementState.decode(plain);
        }finally{Crypto.wipe(wire);Crypto.wipe(plain);}
    }
    static final class Candidate implements AutoCloseable {
        final long sequence;final ManagementState management;final byte[] state,wire,digest,key;final long keyVersion;
        Candidate(long sequence,ManagementState management,byte[] state,byte[] wire,byte[] digest,byte[] key,long keyVersion){
            this.sequence=sequence;this.management=management;this.state=state;this.wire=wire;this.digest=digest;this.key=key==null?null:key.clone();this.keyVersion=keyVersion;
        }
        public void close(){Crypto.wipe(state);Crypto.wipe(wire);Crypto.wipe(digest);Crypto.wipe(key);}
    }
    private Candidate prepare(LanGroup group,AdminRecordStore.Snapshot snapshot,CorePersistenceCoordinator.PersistenceRequest request,
                              byte[] key,long keyVersion,Map<String,long[]> reservations,List<byte[]> outgoing)throws Exception {
        return prepare(group,snapshot,request,key,keyVersion,reservations,outgoing,null,null);
    }
    private Candidate prepare(LanGroup group,AdminRecordStore.Snapshot snapshot,CorePersistenceCoordinator.PersistenceRequest request,
                              byte[] key,long keyVersion,Map<String,long[]> reservations,List<byte[]> outgoing,MemberDirectory directory,Map<String,String> labels)throws Exception {
        long seq=Math.addExact(group.saveSeq,1),generation=files.nextGeneration();
        var management=ManagementState.candidate(group,generation,snapshot,group.clock);
        if(directory!=null){management=management.directory(directory,labels);
            for(byte[] encoded:management.roster)group.state.verifyStoredCertificateEvidence(AdminRecords.decode(encoded));}
        if(reservations!=null||outgoing!=null)management=new ManagementState(generation,snapshot,management.union,management.roster,management.legacyPermissions,
                management.aliases,reservations==null?management.reservations:reservations,outgoing==null?management.outgoing:outgoing,management.legacyAdministratorBasis,management.stopReason,management.checkpoint);
        boolean newCheckpoint=management.checkpoint==null||request!=null&&request.received();
        if(newCheckpoint){
            var previous=request!=null&&request.recovery()?marker.inspect().target():null;
            if(request!=null&&request.recovery()&&(previous==null||request.requirement().version()!=previous.requiredVersion()
                    ||!Crypto.equal(request.requirement().digest(),previous.revocationDigest())))throw new IOException("復旧要件が違います");
            long number=management.checkpoint==null?1:Math.addExact(management.checkpoint.number,1);
            var received=request==null?AdminRecords.decode(snapshot.revocations()):request.revocations();
            var target=new StopMarker.Target(seq,received.version(),new byte[32],CorePersistenceCoordinator.revocationDigest(management.union),previous==null?StopMarker.RECEIVED:StopMarker.RECOVERY);
            management=management.checkpoint(new ManagementState.Checkpoint(number,generation,snapshot.records().size(),snapshot.administratorVersion(),snapshot.revocationVersion(),
                    snapshot.revocations(),received.encode(),target,previous,previous==null?null:request.requirement().subjects()));
            if(previous!=null&&previous.candidateLess())management=management.checkpoint(management.checkpoint.basis(group.state.snapshot()));
            byte[] canonicalState=encode(group,management,seq,new byte[32],key,keyVersion),canonicalManagement=management.encode(true);
            byte[] digest;
            try{digest=candidateDigest(canonicalState,canonicalManagement);}finally{Crypto.wipe(canonicalState);Crypto.wipe(canonicalManagement);}
            management=management.checkpoint(management.checkpoint.digest(digest));Crypto.wipe(digest);
        }
        byte[] plain=management.encode(false),wire=null,state=null;
        try{
            wire=managementEnvelope.seal(plain);byte[] digest=Crypto.blake2s(wire);
            state=encode(group,management,seq,digest,key,keyVersion);
            var checked=management;
            boolean selfRevoked=management.union.stream().anyMatch(id->Crypto.equal(id,group.id()));
            if(!selfRevoked)try(var restored=LanGroup.decode(state,group.clock,true,(g,d)->checked)){
                if(!ManagementState.sameSnapshot(restored.state.snapshot(),snapshot))throw new IOException("保存候補の管理状態が違います");
            }
            return new Candidate(seq,management,state,wire,digest,key,keyVersion);
        }catch(Exception e){Crypto.wipe(wire);Crypto.wipe(state);throw e;}finally{Crypto.wipe(plain);}
    }
    private void checkSpace(Candidate candidate)throws IOException{
        if(!files.hasSpace(Math.addExact(candidate.wire.length,Math.addExact(2L*(candidate.state.length+38),StopMarker.BYTES+StateSettings.MAX_BYTES*2L))))
            throw new IOException("保存先の空きが足りません");
    }
    static byte[] candidateDigest(byte[] state,byte[] management)throws IOException{
        try(var buffer=new WipingOutput();var out=new DataOutputStream(buffer)){
            out.writeInt(PURPOSE.length);out.write(PURPOSE);out.writeInt(state.length);out.write(state);out.writeInt(management.length);out.write(management);
            byte[] bytes=buffer.toByteArray();try{return Crypto.blake2s(bytes);}finally{Crypto.wipe(bytes);}
        }
    }
    private static byte[] encode(LanGroup group,ManagementState management,long sequence,byte[] digest,byte[] key,long version)throws IOException{
        long old=group.saveSeq;group.saveSeq=sequence;
        try{return group.encodeSix(management,management.generation,digest,key,version);}finally{group.saveSeq=old;}
    }
    synchronized int save(LanGroup group,StateEnvelope.AtomicTarget target)throws Exception{
        if(pending!=null||group.storageBlocked)throw new IllegalStateException("保存を待たせています");
        try(var candidate=prepare(group,group.state.snapshot(),null,null,group.keyVersion,null,null)){return commit(group,candidate,target);}
    }
    synchronized int saveDirectory(LanGroup group,StateEnvelope.AtomicTarget target,MemberDirectory directory,Map<String,String> labels)throws Exception{
        if(pending!=null||group.storageBlocked)throw new IllegalStateException("保存を待たせています");
        try(var candidate=prepare(group,group.state.snapshot(),null,null,group.keyVersion,null,null,directory,labels)){return commit(group,candidate,target);}
    }
    private void initialize(StopMarker.Target target)throws IOException{marker.initializeMigration(target);}
    synchronized void prepareNetwork(LanGroup group)throws Exception{
        if(group.storageBlocked||group.recoveryRequirement!=null)throw new IOException("通常通信を開始できません");
        if(group.management!=null){inspect(group);if(group.storageBlocked)throw new IOException("停止の印を確認できません");return;}
        try(var candidate=prepare(group,group.state.snapshot(),null,null,group.keyVersion,null,null)){initialize(candidate.management.checkpoint.target);}
    }
    synchronized Candidate stage(LanGroup group)throws Exception{
        if(pending!=null||group.storageBlocked)throw new IllegalStateException("失効の保存中です");
        var candidate=prepare(group,group.state.snapshot(),null,null,group.keyVersion,null,null);
        try{
            checkSpace(candidate);
            if(group.management==null)initialize(candidate.management.checkpoint.target);
            files.write(candidate.management.generation,candidate.wire);return candidate;
        }catch(Exception e){candidate.close();throw e;}
    }
    synchronized void stagedCommitted(LanGroup group,Candidate candidate){install(group,candidate);}
    private void install(LanGroup group,Candidate candidate){
        group.saveSeq=candidate.sequence;group.management=candidate.management;group.managementGeneration=candidate.management.generation;
        Crypto.wipe(group.managementDigest);group.managementDigest=candidate.digest.clone();
        if(candidate.key!=null){Crypto.wipe(group.groupKey);group.groupKey=candidate.key.clone();group.keyVersion=candidate.keyVersion;}
    }
    private int commit(LanGroup group,Candidate candidate,StateEnvelope.AtomicTarget target)throws Exception {
        // 受信では active の確定後に空きを検査する。予約済みの印の書込みを妨げない。
        // For received changes, check space after active is committed, preserving writes to the reserved marker.
        checkSpace(candidate);
        if(group.management==null&&pending!=candidate)initialize(candidate.management.checkpoint.target);
        files.write(candidate.management.generation,candidate.wire);
        byte[] wire=stateEnvelope.seal(candidate.state);int size=wire.length;StateEnvelope.writeAtomic(wire,target);
        install(group,candidate);
        return size;
    }
    synchronized void cleanup(LanGroup group){try{files.cleanup(group.managementGeneration);}catch(IOException ignored){}}
    synchronized void inspectLegacy(LanGroup group)throws IOException{
        var current=marker.inspect();
        if(current.status()==StopMarker.Status.ACTIVE){block(group,current.target());return;}
        if(current.status()==StopMarker.Status.CLEAR&&(!Crypto.equal(current.target().revocationDigest(),CorePersistenceCoordinator.revocationDigest(group.state.revokedSubjects()))
                ||current.target().requiredVersion()!=group.state.revocations().version()))group.storageBlocked=true;
    }
    private static void block(LanGroup group,StopMarker.Target target){
        group.storageBlocked=true;
        List<byte[]> subjects=group.state.revokedSubjects();
        if(target.candidateLess()){
            group.recoveryRequirement=CorePersistenceCoordinator.RecoveryRequirement.candidateLess(target.requiredVersion(),subjects);return;
        }
        if(!Crypto.equal(CorePersistenceCoordinator.revocationDigest(subjects),target.revocationDigest()))subjects=null;
        group.recoveryRequirement=new CorePersistenceCoordinator.RecoveryRequirement(target.requiredVersion(),target.revocationDigest(),subjects);
    }
    synchronized void inspect(LanGroup group)throws Exception {
        var current=marker.inspect();var cp=group.management.checkpoint;
        if(current.status()==StopMarker.Status.INVALID){group.storageBlocked=true;group.invalidStopMarker=true;return;}
        if(current.status()==StopMarker.Status.CLEAR){
            if(!cp.target.matches(current.target()))group.storageBlocked=true;
            return;
        }
        boolean exact=cp.target.matches(current.target());boolean recovery=cp.previous!=null&&cp.previous.sameRequirement(current.target());
        if((exact||recovery)&&group.saveSeq==cp.target.saveSeq()&&group.managementGeneration==cp.generation){
            byte[] state=encode(group,group.management,group.saveSeq,new byte[32],null,group.keyVersion),management=group.management.encode(true);
            boolean matches;
            try{matches=Crypto.equal(candidateDigest(state,management),cp.target.stateDigest());}finally{Crypto.wipe(state);Crypto.wipe(management);}
            if(matches){if(recovery)marker.active(cp.target);marker.clear(cp.target);return;}
        }
        block(group,current.target());
    }
    CorePersistenceCoordinator.PersistenceHooks hooks(LanGroup group,StateEnvelope.AtomicTarget target,Runnable settings){
        return new CorePersistenceCoordinator.PersistenceHooks(){
            public void active(CorePersistenceCoordinator.PersistenceRequest request){run(()->{
                synchronized(VersionSixStorage.this){
                    if(pending!=null)throw new IllegalStateException("失効の保存中です");
                    var existing=marker.inspect();
                    if(!request.recovery()&&(group.storageBlocked||existing.status()==StopMarker.Status.ACTIVE))
                        throw new IOException("停止の要件を保持します");
                    // 旧形式では領域だけを確保し、管理保存より先に新候補の active を書く。
                    // For legacy state, allocate only the region and write the new candidate's active marker before management persistence.
                    if(group.management==null&&!request.recovery())prepareNetwork(group);
                    try{pending=prepare(group,request.management(),request,null,group.keyVersion,null,null);}
                    catch(Exception failure){
                        // 候補を作れない上限超過も停止を残す。全ゼロは確定候補に一致しない記号。
                        // Persist a stop even when limits prevent a candidate; all zeroes are a sentinel that matches no committed candidate.
                        if(!request.recovery()&&ManagementState.limitExceeded(failure))
                            marker.active(new StopMarker.Target(group.saveSeq,request.revocations().version(),new byte[32],new byte[32],StopMarker.RECEIVED));
                        throw failure;
                    }
                    owner=group;
                    if(!request.recovery())marker.active(pending.management.checkpoint.target);
                }
            });}
            public void save(AdminRecordStore.Snapshot snapshot){saveSnapshot(snapshot,null,group.keyVersion,null,null);}
            public void save(CorePersistenceCoordinator.PersistenceRequest request){
                if(!request.received()){save(request.management());return;}
                run(()->{synchronized(VersionSixStorage.this){
                    if(pending==null||owner!=group||!ManagementState.sameSnapshot(pending.management.snapshot,request.management()))throw new IOException("保存候補が違います");
                    commit(group,pending,target);settings.run();
                }});
            }
            public void clear(CorePersistenceCoordinator.PersistenceRequest request){run(()->{synchronized(VersionSixStorage.this){
                if(pending==null||owner!=group||group.management!=pending.management)throw new IOException("確定候補が違います");
                var current=read(group.managementGeneration,group.managementDigest);
                if(!ManagementState.sameSnapshot(current.snapshot,request.management()))throw new IOException("確定内容が違います");
                if(request.recovery())marker.active(pending.management.checkpoint.target);
                marker.clear(pending.management.checkpoint.target);pending.close();pending=null;owner=null;
                group.storageBlocked=false;group.recoveryRequirement=null;cleanup(group);
            }});}
            public void saveAcceptedKey(AdminRecordStore.Snapshot snapshot,byte[] key,long version){saveSnapshot(snapshot,key,version,null,List.of());}
            public void reserveRotationVersions(long key,long revoked){
                var reservations=new TreeMap<String,long[]>();if(group.management!=null)reservations.putAll(group.management.reservations);
                String administrator=Base64.getEncoder().encodeToString(Crypto.ed25519Public(group.administratorSecret));
                var old=reservations.get(administrator);reservations.put(administrator,new long[]{Math.max(key,old==null?0:old[0]),Math.max(revoked,old==null?0:old[1])});
                saveSnapshot(group.state.snapshot(),null,group.keyVersion,reservations,null);
            }
            public void saveRotation(KeyRotationCoordinator.SavedRotation rotation,byte[] key){
                var outgoing=new ArrayList<byte[]>();for(var record:rotation.envelopes())outgoing.add(record.encode());
                saveSnapshot(rotation.management(),key,rotation.keyVersion(),null,outgoing);
            }
            private void saveSnapshot(AdminRecordStore.Snapshot snapshot,byte[] key,long version,Map<String,long[]> numbers,List<byte[]> outgoing){
                run(()->{synchronized(VersionSixStorage.this){
                    if(pending!=null||group.storageBlocked)throw new IllegalStateException("失効の保存中です");
                    try(var candidate=prepare(group,snapshot,null,key,version,numbers,outgoing)){commit(group,candidate,target);settings.run();cleanup(group);}
                }});
            }
            public void stopped(CorePersistenceCoordinator.StopReason reason){synchronized(VersionSixStorage.this){
                group.storageBlocked=true;if(pending!=null){pending.close();pending=null;owner=null;}
            }}
        };
    }
    private static final class WipingOutput extends ByteArrayOutputStream {
        @Override public void close(){Arrays.fill(buf,(byte)0);reset();}
    }
    private interface IO {void run()throws Exception;}
    private static void run(IO action){try{action.run();}catch(Exception e){throw new IllegalStateException("管理状態の保存に失敗しました",e);}}
}
