// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.io.*;
import java.time.Clock;
import java.util.*;

/**
 * 署名根拠と受信 checkpoint を世代ごとに保持する管理平文。
 * <p>
 * Management plaintext retaining signature evidence and received checkpoints by generation.
 */
final class ManagementState {
    static final int MAX_BYTES=16*1024*1024,MAX_ENVELOPE_BYTES=MAX_BYTES+38;
    static final int MAX_HISTORY=65_536,HISTORY_BYTES=12*1024*1024;
    final long generation;
    final AdminRecordStore.Snapshot snapshot;
    final List<byte[]> union,roster,legacyPermissions;
    final Map<String,String> aliases;
    final Map<String,long[]> reservations;
    final List<byte[]> outgoing;
    final List<byte[]> legacyAdministratorBasis;
    final CorePersistenceCoordinator.StopReason stopReason;
    final Checkpoint checkpoint;
    static final class Checkpoint {
        final long number,generation,administratorVersion,revocationVersion;
        final int prefix;
        final byte[] winner,received;
        final StopMarker.Target target,previous;
        final List<byte[]> previousSubjects;
        Checkpoint(long number,long generation,int prefix,long administrators,long revocations,byte[] winner,byte[] received,
                   StopMarker.Target target,StopMarker.Target previous,List<byte[]> previousSubjects){
            this.number=number;this.generation=generation;this.prefix=prefix;administratorVersion=administrators;revocationVersion=revocations;
            this.winner=winner.clone();this.received=received.clone();this.target=target;this.previous=previous;this.previousSubjects=previousSubjects==null?null:copy(previousSubjects);
        }
        Checkpoint digest(byte[] digest){return new Checkpoint(number,generation,prefix,administratorVersion,revocationVersion,winner,received,
                new StopMarker.Target(target.saveSeq(),target.requiredVersion(),digest,target.revocationDigest(),target.reason()),previous,previousSubjects);}
    }
    ManagementState(long generation,AdminRecordStore.Snapshot snapshot,List<byte[]> union,List<byte[]> roster,List<byte[]> legacy,
                    Map<String,String> aliases,Map<String,long[]> reservations,List<byte[]> outgoing,List<byte[]> basis,
                    CorePersistenceCoordinator.StopReason reason,Checkpoint checkpoint){
        this.generation=generation;this.snapshot=snapshot;this.union=copy(union);this.roster=copy(roster);legacyPermissions=copy(legacy);
        this.aliases=Collections.unmodifiableMap(new TreeMap<>(aliases));var numbers=new TreeMap<String,long[]>();
        reservations.forEach((k,v)->numbers.put(k,v.clone()));this.reservations=Collections.unmodifiableMap(numbers);
        this.outgoing=copy(outgoing);legacyAdministratorBasis=copy(basis);stopReason=reason;this.checkpoint=checkpoint;
    }
    ManagementState checkpoint(Checkpoint value){return new ManagementState(generation,snapshot,union,roster,legacyPermissions,aliases,reservations,outgoing,legacyAdministratorBasis,stopReason,value);}
    static List<byte[]> copy(List<byte[]> input){var result=new ArrayList<byte[]>();for(byte[] b:input)result.add(b.clone());return List.copyOf(result);}
    static final class LimitExceeded extends IOException {
        LimitExceeded(String message){super(message);}
    }
    static boolean limitExceeded(Exception failure){return failure instanceof LimitExceeded||failure instanceof UncheckedIOException&&failure.getCause() instanceof LimitExceeded;}
    static void checkHistory(AdminRecordStore.Snapshot value)throws IOException{
        var history=value.records();if(history.isEmpty())throw new IOException("管理履歴がありません");
        if(history.size()>MAX_HISTORY)throw new LimitExceeded("管理履歴の件数が上限です");
        long length=4;for(byte[] bytes:history){length+=4L+bytes.length;if(length>HISTORY_BYTES)throw new LimitExceeded("管理履歴の大きさが上限です");}
    }
    static ManagementState candidate(LanGroup group,long generation,AdminRecordStore.Snapshot snapshot,Clock clock)throws IOException {
        checkHistory(snapshot);var state=LanGroup.restore(group.groupId,group.urlAdmin,snapshot,clock);
        try{
            var old=group.management;var roster=old==null?new ArrayList<byte[]>():new ArrayList<>(old.roster);
            putCertificate(roster,group.certificate);if(group.peerCertificate!=null)putCertificate(roster,group.peerCertificate);
            return new ManagementState(generation,snapshot,state.revokedSubjects(),roster,legacyPermissions(group,old),
                    old==null?Map.of():old.aliases,old==null?Map.of():old.reservations,old==null||!Arrays.equals(old.snapshot.announcement(),snapshot.announcement())||old.snapshot.administratorVersion()!=snapshot.administratorVersion()||!sameSubjects(old.union,state.revokedSubjects())?List.of():old.outgoing,
                    legacyBasis(group,old,state),CorePersistenceCoordinator.StopReason.NONE,old==null?null:old.checkpoint);
        }finally{state.clear();}
    }
    private static List<byte[]> legacyPermissions(LanGroup group,ManagementState old){
        var records=new ArrayList<byte[]>();if(old!=null)records.addAll(old.legacyPermissions);
        for(byte[] bytes:group.state.storedLegacyCertificates())if(records.stream().noneMatch(value->Arrays.equals(value,bytes)))records.add(bytes);
        return records;
    }
    ManagementState directory(MemberDirectory directory,Map<String,String> labels){
        var values=directory.snapshot();var identities=new HashSet<String>();
        for(byte[] encoded:values)identities.add(Base64.getEncoder().encodeToString(AdminRecords.decode(encoded).field(0)));
        if(!identities.containsAll(labels.keySet()))throw new SecurityException("呼び名の根拠がありません");
        return new ManagementState(generation,snapshot,union,values,legacyPermissions,labels,reservations,outgoing,legacyAdministratorBasis,stopReason,checkpoint);
    }
    void restoreRotation(LanGroup group,KeyRotationCoordinator rotation){
        if(!group.isAdministrator())throw new SecurityException("管理者の鍵がありません");
        String key=Base64.getEncoder().encodeToString(Crypto.ed25519Public(group.administratorSecret));var saved=reservations.get(key);
        if(saved!=null)rotation.restoreReservations(saved[0],saved[1]);
        if(!outgoing.isEmpty()){
            var envelopes=new ArrayList<AdminRecords.Record>();for(byte[] bytes:outgoing)envelopes.add(AdminRecords.decode(bytes));
            rotation.restorePublication(new KeyRotationCoordinator.SavedRotation(snapshot,envelopes,group.keyVersion,snapshot.revocationVersion()),group.groupKey);
        }
    }
    private static List<byte[]> legacyBasis(LanGroup group,ManagementState old,AdminState candidate){
        if(candidate.administrators().hasAdminBindings())return List.of();
        if(old!=null)return old.legacyAdministratorBasis;
        if(group.certificate.format()!=1||group.peerCertificate==null||group.state.administrators().entries().size()!=1||group.isAdministrator())return List.of();
        var basis=List.of(group.certificate.encode(),group.peerCertificate.encode());
        try(var administration=new GroupAdministration(group.state,group.certificate,group.identitySecret,group.handshakeSecret,
                group.administratorSecret,group.clock,()->0,new java.security.SecureRandom())){
            administration.restoreLegacyAdministratorBasis(basis);return administration.legacyAdministratorBasis();
        }
    }
    private static void putCertificate(List<byte[]> roster,AdminRecords.Record certificate){
        byte[] id=certificate.field(0);for(int i=0;i<roster.size();i++)if(Crypto.equal(AdminRecords.decode(roster.get(i)).field(0),id)){
            if(AdminRecords.decode(roster.get(i)).issuedAt()<=certificate.issuedAt())roster.set(i,certificate.encode());return;
        }roster.add(certificate.encode());
    }
    void verify(LanGroup group,Clock clock)throws IOException {
        checkHistory(snapshot);
        if(generation!=group.managementGeneration||!sameSubjects(union,group.state.revokedSubjects()))throw new IOException("管理状態の結び付きが違います");
        group.state.restoreStoredLegacyCertificates(legacyPermissions);
        group.state.checkRestoredGroupKey(group.groupKey,group.keyVersion);
        if(!legacyAdministratorBasis.isEmpty())try(var administration=new GroupAdministration(group.state,group.certificate,group.identitySecret,group.handshakeSecret,
                group.administratorSecret,clock,()->0,new java.security.SecureRandom())){administration.restoreLegacyAdministratorBasis(legacyAdministratorBasis);}
        if(!outgoing.isEmpty()){
            var announcement=group.state.announcement();if(announcement==null)throw new IOException("送信待ちの告知がありません");
            for(byte[] bytes:outgoing){var envelope=AdminRecords.decode(bytes);envelope.verify(AdminRecords.Kind.WRAPPED_KEY,group.groupId,group.state.administrators().entries());
                if(envelope.format()!=2||envelope.version()!=group.keyVersion||!Crypto.equal(envelope.field(4),Crypto.blake2s(announcement.signedBytes()))
                        ||union.stream().anyMatch(id->Crypto.equal(id,envelope.field(0))))throw new IOException("送信待ちが現在の鍵と違います");}
        }
        var members=new HashSet<String>();for(byte[] bytes:roster){var cert=AdminRecords.decode(bytes);
            if(!Crypto.equal(cert.group(),group.groupId)||!members.add(Base64.getEncoder().encodeToString(cert.field(0))))throw new IOException("名簿が違います");
            group.state.verifyStoredCertificateEvidence(cert);
        }
        for(String alias:aliases.keySet())if(!members.contains(alias))throw new IOException("呼び名の根拠がありません");
        if(checkpoint==null||checkpoint.number<=0||checkpoint.generation<=0||checkpoint.generation>generation
                ||checkpoint.target.saveSeq()>group.saveSeq||checkpoint.prefix<1||checkpoint.prefix>snapshot.records().size())throw new IOException("checkpoint が違います");
        var proof=new AdminRecordStore.Snapshot(snapshot.records().subList(0,checkpoint.prefix),snapshot.anchorSignature(),checkpoint.winner,
                checkpoint.administratorVersion,checkpoint.revocationVersion);
        var past=LanGroup.restore(group.groupId,group.urlAdmin,proof,clock);
        try{
            var body=AdminRecords.decode(checkpoint.received);var fork=LanGroup.restore(group.groupId,group.urlAdmin,proof,clock);
            try{fork.acceptRevocations(body);if(!sameSnapshot(proof,fork.snapshot()))throw new IOException("受信一覧の根拠が違います");}finally{fork.clear();}
            if(body.version()!=checkpoint.target.requiredVersion()
                    ||!Crypto.equal(CorePersistenceCoordinator.revocationDigest(past.revokedSubjects()),checkpoint.target.revocationDigest())
                    ||!contains(union,past.revokedSubjects()))throw new IOException("checkpoint の失効根拠が違います");
            if(checkpoint.previous!=null){var previous=checkpoint.previous;
                if(checkpoint.target.reason()!=StopMarker.RECOVERY||body.version()<previous.requiredVersion()
                        ||!(Crypto.equal(CorePersistenceCoordinator.revocationDigest(body.entries()),previous.revocationDigest())
                        ||checkpoint.previousSubjects!=null&&Crypto.equal(CorePersistenceCoordinator.revocationDigest(checkpoint.previousSubjects),previous.revocationDigest())
                            &&contains(body.entries(),checkpoint.previousSubjects)))
                    throw new IOException("復旧の根拠が違います");
            }
        }finally{past.clear();}
    }
    static boolean sameSnapshot(AdminRecordStore.Snapshot a,AdminRecordStore.Snapshot b){
        if(a.administratorVersion()!=b.administratorVersion()||a.revocationVersion()!=b.revocationVersion()
                ||!Arrays.equals(a.anchorSignature(),b.anchorSignature())||!Arrays.equals(a.revocations(),b.revocations())
                ||!Arrays.equals(a.announcement(),b.announcement()))return false;
        var x=a.records();var y=b.records();if(x.size()!=y.size())return false;
        for(int n=0;n<x.size();n++)if(!Arrays.equals(x.get(n),y.get(n)))return false;return true;
    }
    static boolean sameSubjects(List<byte[]> a,List<byte[]> b){return a.size()==b.size()&&Crypto.equal(CorePersistenceCoordinator.revocationDigest(a),CorePersistenceCoordinator.revocationDigest(b));}
    static boolean contains(List<byte[]> a,List<byte[]> b){for(byte[] id:b)if(a.stream().noneMatch(x->Crypto.equal(id,x)))return false;return true;}
    static void bytes(DataOutputStream out,byte[] value)throws IOException{if(value==null){out.writeInt(-1);return;}out.writeInt(value.length);out.write(value);}
    static byte[] bytes(DataInputStream in,boolean nullable)throws IOException{
        int n=in.readInt();if(n==-1&&nullable)return null;if(n<0||n>in.available())throw new IOException("管理項目の長さが違います");byte[] bytes=new byte[n];in.readFully(bytes);return bytes;
    }
    static int count(DataInputStream in,int max)throws IOException{int n=in.readInt();if(n<0||n>max||n>in.available()/4)throw new IOException("管理項目の件数が違います");return n;}
    static void list(DataOutputStream out,List<byte[]> values)throws IOException{out.writeInt(values.size());for(byte[] b:values)bytes(out,b);}
    static List<byte[]> list(DataInputStream in,int max)throws IOException{int n=count(in,max);var list=new ArrayList<byte[]>();for(int i=0;i<n;i++)list.add(bytes(in,false));return list;}
    static void target(DataOutputStream out,StopMarker.Target t,boolean omitDigest)throws IOException{
        out.writeLong(t.saveSeq());out.writeLong(t.requiredVersion());out.writeInt(t.reason());out.write(omitDigest?new byte[32]:t.stateDigest());out.write(t.revocationDigest());
    }
    static StopMarker.Target target(DataInputStream in)throws IOException{long seq=in.readLong(),version=in.readLong();int reason=in.readInt();byte[] state=new byte[32],r=new byte[32];in.readFully(state);in.readFully(r);return new StopMarker.Target(seq,version,state,r,reason);}
    byte[] encode(boolean omitDigest)throws IOException{
        checkHistory(snapshot);
        try(var buffer=new LimitedOutput();var out=new DataOutputStream(buffer)){
            out.writeInt(1);out.writeLong(generation);list(out,snapshot.records());bytes(out,snapshot.anchorSignature());bytes(out,snapshot.revocations());
            out.writeLong(snapshot.administratorVersion());out.writeLong(snapshot.revocationVersion());bytes(out,snapshot.announcement());
            list(out,union);list(out,roster);list(out,legacyPermissions);list(out,legacyAdministratorBasis);
            out.writeInt(aliases.size());for(var entry:aliases.entrySet()){out.writeUTF(entry.getKey());out.writeUTF(entry.getValue());}
            out.writeInt(reservations.size());for(var entry:reservations.entrySet()){out.writeUTF(entry.getKey());out.writeLong(entry.getValue()[0]);out.writeLong(entry.getValue()[1]);}
            list(out,outgoing);out.writeInt(stopReason.ordinal());
            var cp=checkpoint;if(cp==null)throw new IOException("checkpoint がありません");
            out.writeLong(cp.number);out.writeLong(cp.generation);out.writeInt(cp.prefix);out.writeLong(cp.administratorVersion);out.writeLong(cp.revocationVersion);
            bytes(out,cp.winner);bytes(out,cp.received);target(out,cp.target,omitDigest);out.writeBoolean(cp.previous!=null);if(cp.previous!=null)target(out,cp.previous,false);
            out.writeBoolean(cp.previousSubjects!=null);if(cp.previousSubjects!=null)list(out,cp.previousSubjects);
            out.flush();return buffer.toByteArray();
        }
    }
    static ManagementState decode(byte[] plain)throws IOException{
        if(plain.length>MAX_BYTES)throw new IOException("管理状態が上限です");
        try(var in=new DataInputStream(new ByteArrayInputStream(plain))){
            if(in.readInt()!=1)throw new IOException("管理形式が違います");long generation=in.readLong();if(generation<=0)throw new IOException("管理世代が違います");
            var history=list(in,MAX_HISTORY);byte[] anchor=bytes(in,false),revocations=bytes(in,false);long av=in.readLong(),rv=in.readLong();
            var snapshot=new AdminRecordStore.Snapshot(history,anchor,revocations,av,rv,bytes(in,true));checkHistory(snapshot);
            var union=list(in,65_536);byte[] prior=null;for(byte[] id:union){
                if(id.length!=32||prior!=null&&AdminRecords.compareBytes(prior,id)>=0)throw new IOException("失効の順序が違います");prior=id;}
            var roster=list(in,65_536);var legacy=list(in,65_536);var basis=list(in,2);
            var aliases=new TreeMap<String,String>();for(int n=count(in,65_536);n>0;n--)if(aliases.put(in.readUTF(),in.readUTF())!=null)throw new IOException("呼び名が重複しています");
            var reservations=new TreeMap<String,long[]>();for(int n=count(in,65_536);n>0;n--){String key=in.readUTF();long k=in.readLong(),r=in.readLong();
                if(k<0||r<0||reservations.put(key,new long[]{k,r})!=null)throw new IOException("予約番号が違います");}
            var outgoing=list(in,65_536);int reason=in.readInt();if(reason<0||reason>=CorePersistenceCoordinator.StopReason.values().length)throw new IOException("停止理由が違います");
            long number=in.readLong(),cpGeneration=in.readLong();int prefix=in.readInt();long admins=in.readLong(),revoked=in.readLong();
            byte[] winner=bytes(in,false),received=bytes(in,false);var target=target(in);int previous=in.readUnsignedByte();if(previous>1)throw new IOException("復旧の印が違います");
            var oldTarget=previous==1?target(in):null;int hasSubjects=in.readUnsignedByte();if(hasSubjects>1)throw new IOException("復旧集合の印が違います");
            var cp=new Checkpoint(number,cpGeneration,prefix,admins,revoked,winner,received,target,oldTarget,hasSubjects==1?list(in,65_536):null);
            if(in.available()!=0)throw new IOException("管理状態に余分な値があります");
            return new ManagementState(generation,snapshot,union,roster,legacy,aliases,reservations,outgoing,basis,CorePersistenceCoordinator.StopReason.values()[reason],cp);
        }
    }
    private static final class LimitedOutput extends ByteArrayOutputStream {
        private void room(int n){if(n<0||count>MAX_BYTES-n)throw new UncheckedIOException(new LimitExceeded("管理状態が上限です"));}
        @Override public synchronized void write(int b){room(1);super.write(b);}
        @Override public synchronized void write(byte[] b,int offset,int length){room(length);super.write(b,offset,length);}
        @Override public void close(){Arrays.fill(buf,(byte)0);reset();}
    }
    @Override public String toString(){return "Management state";}
}
