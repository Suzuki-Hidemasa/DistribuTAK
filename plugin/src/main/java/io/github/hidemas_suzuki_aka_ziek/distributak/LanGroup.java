// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.*;
import org.bouncycastle.util.encoders.Hex;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;

/** 第9段の1グループ・相手1台の保存状態。秘密の所有をまとめる。 */
final class LanGroup implements AutoCloseable {
    /** 自分以外の相手の最大数（第12段で 32→128。ADR 0030 答え 190・192）。SessionManager へ渡す台数は自分を含む MAX_PEERS+1（核 C1。答え 181）。揮発の相手は保存した相手の 1 枠を除いて 127 台まで。 */
    static final int MAX_PEERS=128;
    /** SessionManager へ渡す台数（自分を含む）。LanController の加入と LanGroup.sessions の両方がこの値を使う。 */
    static int coreGroupSize(){return MAX_PEERS+1;}
    byte[] identitySecret,handshakeSecret,administratorSecret,groupKey,groupId,urlAdmin;
    long keyVersion,saveSeq;
    long managementGeneration;
    byte[] managementDigest;
    ManagementState management;
    boolean storageBlocked;
    CorePersistenceCoordinator.RecoveryRequirement recoveryRequirement;
    /** この端末が DHT に出した記録の版。0 以上で、Long.MAX_VALUE-1 を上限とする（04 の 8.3）。他人の記録は保存しない。 */
    long dhtLocalVersion;
    int renewalCount;
    boolean syncInitialized;
    int port;
    Clock clock;
    AdminState state;
    AdminRecords.Record certificate,peerCertificate;
    InetSocketAddress peerAddress,pendingAddress;
    byte[] pendingHandshake;
    private final Map<String,byte[]> pendingRenewals=new LinkedHashMap<>();
    private UdpEndpoint.CloseReason pendingRenewalFailure=UdpEndpoint.CloseReason.RUNNING;
    private boolean closed;
    boolean revokedPeerForgotten;
    private LanGroup(){}
    boolean isAdministrator(){return administratorSecret!=null&&administratorSecret.length==32;}
    byte[] id(){return Crypto.blake2s(Crypto.ed25519Public(identitySecret));}
    static byte[] random(SecureRandom random){byte[] bytes=new byte[32];random.nextBytes(bytes);return bytes;}
    static LanGroup create(int port,Clock clock,SecureRandom random) {
        LanGroup group=new LanGroup();
        try {
            group.clock=clock;group.port=LanSupport.port(port,random);group.identitySecret=random(random);group.handshakeSecret=random(random);
            group.administratorSecret=random(random);group.groupId=random(random);group.groupKey=random(random);
            group.urlAdmin=Crypto.ed25519Public(group.administratorSecret);
            group.state=new AdminState(group.groupId,group.urlAdmin,clock,new InMemoryAdminRecordStore());
            var proof=AdminControl.keyProof(group.groupId,new byte[16],0,group.identitySecret,group.administratorSecret);
            var first=AdminRecords.administrators(group.groupId,0,clock.millis(),List.of(AdminBinding.bound(group.urlAdmin,group.id(),proof.encode())),group.administratorSecret);
            group.state.bootstrap(first,AdminRecords.signAnchor(first,group.administratorSecret));
            group.state.acceptRevocations(AdminRecords.initialRevocations(group.groupId,clock.millis(),group.administratorSecret));
            byte[] publicHandshake=Crypto.x25519Public(group.handshakeSecret);
            group.certificate=AdminRecords.certificate(group.groupId,Crypto.ed25519Public(group.identitySecret),publicHandshake,
                    SignaturePurpose.identityProof(group.identitySecret,group.groupId,publicHandshake),clock.millis(),group.administratorSecret);
            group.validate();return group;
        }catch(RuntimeException e){group.close();throw e;}
    }
    static LanGroup joined(int port,byte[] identity,byte[] handshake,byte[] urlAdmin,JoinHandshake.Joined joined,Clock clock) {
        LanGroup group=new LanGroup();
        try {
            group.clock=clock;group.port=port;group.identitySecret=identity.clone();group.handshakeSecret=handshake.clone();group.administratorSecret=new byte[0];
            group.groupKey=joined.groupKey();group.keyVersion=joined.groupKeyVersion();group.certificate=joined.certificate();
            group.groupId=group.certificate.group();group.urlAdmin=urlAdmin.clone();
            group.state=restore(group.groupId,group.urlAdmin,joined.state().snapshot(),clock);
            group.validate();return group;
        }catch(RuntimeException e){group.close();throw e;}
    }
    /** 核の照合済みの結果から、保存する候補だけを作る。元のグループは変更しない。 */
    static LanGroup rejoined(LanGroup previous,byte[] handshake,byte[] urlAdmin,JoinHandshake.Joined joined,Clock clock)throws IOException {
        LanGroup group=joined(previous.port,previous.identitySecret,handshake,urlAdmin,joined,clock);
        try {
            group.administratorSecret=previous.administratorSecret.clone();group.saveSeq=previous.saveSeq;
            group.management=previous.management;group.managementGeneration=previous.managementGeneration;
            group.managementDigest=previous.managementDigest==null?null:previous.managementDigest.clone();
            group.renewalCount=previous.renewalCount;group.syncInitialized=previous.syncInitialized;group.dhtLocalVersion=previous.dhtLocalVersion;
            group.peerCertificate=previous.peerCertificate;group.peerAddress=previous.peerAddress;
            if(group.peerCertificate!=null)group.state.inheritStoredLegacyCertificate(previous.state,group.peerCertificate);
            if(previous.pendingHandshake!=null)group.pendingPeer(previous.pendingHandshake,previous.pendingAddress);
            for(var entry:previous.pendingRenewals.entrySet())group.pendingRenewals.put(entry.getKey(),entry.getValue().clone());
            checkRejoined(previous,group);group.validate(true);return group;
        }catch(RuntimeException e){group.close();throw e;}
    }
    private static boolean sameCertificate(AdminRecords.Record a,AdminRecords.Record b){return a==null?b==null:b!=null&&Arrays.equals(a.encode(),b.encode());}
    static void checkRejoined(LanGroup previous,LanGroup candidate) {
        if(!Crypto.equal(previous.groupId,candidate.groupId)||!Crypto.equal(previous.id(),candidate.id())
                ||!Crypto.equal(previous.identitySecret,candidate.identitySecret)||previous.port!=candidate.port
                ||Crypto.equal(previous.handshakeSecret,candidate.handshakeSecret)
                ||candidate.state.administrators().version()<previous.state.administrators().version()
                ||candidate.state.revocations().version()<previous.state.revocations().version()||candidate.keyVersion<previous.keyVersion
                ||candidate.renewalCount!=previous.renewalCount||candidate.syncInitialized!=previous.syncInitialized
                ||candidate.dhtLocalVersion!=previous.dhtLocalVersion
                || !sameCertificate(previous.peerCertificate,candidate.peerCertificate)||!Objects.equals(previous.peerAddress,candidate.peerAddress)
                || !Arrays.equals(previous.pendingHandshake,candidate.pendingHandshake)||!Objects.equals(previous.pendingAddress,candidate.pendingAddress))
            throw new SecurityException("入り直しの結果が保存したグループと合いません");
        candidate.validate(true);
    }
    static AdminState restore(byte[] group,byte[] admin,AdminRecordStore.Snapshot snapshot,Clock clock) {
        var store=new InMemoryAdminRecordStore();store.save(snapshot);
        var state=new AdminState(group,admin,clock,store);
        try{state.restore();return state;}catch(AdminState.ClockFailure e){state.clear();throw new StoredCertificateFailure(UdpEndpoint.CloseReason.CLOCK_FAILURE);}
    }
    void pendingPeer(byte[] key,InetSocketAddress address) {
        if(key==null||key.length!=32||address==null||address.isUnresolved()||address.getPort()==0
                ||LanSupport.selectIpv4(List.of(address.getAddress()))==null)throw new SecurityException("相手の予約が違います");
        Crypto.wipe(pendingHandshake);pendingHandshake=key.clone();pendingAddress=address;
    }
    void clearPendingPeer(){Crypto.wipe(pendingHandshake);pendingHandshake=null;pendingAddress=null;}
    UdpEndpoint.CloseReason localCertificateReason(){return state.localCertificateReason(certificate,Crypto.x25519Public(handshakeSecret));}
    private void validate(){validate(false);}
    private void validate(boolean allowExpired) {validate(allowExpired,false);}
    private void validate(boolean allowExpired,boolean savedCandidate) {
        if(closed)throw new IllegalStateException("グループは消去済みです");
        LanSupport.port(port,new SecureRandom());
        if(keyVersion<0 || saveSeq<0 || renewalCount<0 || dhtLocalVersion<0 || dhtLocalVersion==Long.MAX_VALUE || identitySecret.length!=32 || handshakeSecret.length!=32 || groupKey.length!=32 || groupId.length!=32
                || urlAdmin.length!=32 || administratorSecret.length!=0&&administratorSecret.length!=32)
            throw new SecurityException("保存した鍵の長さが違います");
        var reason=localCertificateReason();
        if(reason!=UdpEndpoint.CloseReason.RUNNING&&!(allowExpired&&reason==UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED))
            throw new StoredCertificateFailure(reason);
        if(!Crypto.equal(certificate.field(0),Crypto.ed25519Public(identitySecret)))throw new SecurityException("身元が違います");
        if(isAdministrator()&&!state.administrators().hasEntry(Crypto.ed25519Public(administratorSecret)))
            throw new SecurityException("管理者の鍵が違います");
        if(peerCertificate!=null) {
            // 保存候補の失効相手は根拠だけを検証し、digest 照合後に取り除く。この緩和は版 6 の通常保存にも掛かり、残った失効相手は次の読み込みで消える。
            // Verify only evidence for a revoked saved peer, removing it after digest verification. This relaxation also applies to ordinary version-6 saves; a remaining revoked peer is removed at the next load.
            if(savedCandidate&&revokedPeer())state.verifyStoredCertificateEvidence(peerCertificate);
            else state.verifyCertificate(peerCertificate,peerCertificate.field(1),allowExpired);
            if(Crypto.equal(certificate.field(0),peerCertificate.field(0)) || peerAddress==null
                    || LanSupport.selectIpv4(List.of(peerAddress.getAddress()))==null || peerAddress.getPort()==0)
                throw new SecurityException("相手の記録が違います");
        }else if(peerAddress!=null)throw new SecurityException("相手の証明書がありません");
        if(pendingHandshake!=null) {
            if(peerCertificate!=null||isAdministrator()||pendingHandshake.length!=32||pendingAddress==null||pendingAddress.isUnresolved()
                    ||pendingAddress.getPort()==0||LanSupport.selectIpv4(List.of(pendingAddress.getAddress()))==null)
                throw new SecurityException("最初の相手の記録が違います");
        }else if(pendingAddress!=null)throw new SecurityException("最初の相手の鍵がありません");
    }
    private void verifyRenewal(byte[] peerId,byte[] encoded,boolean recovery) {
        var renewal=AdminRecords.decode(renewalCertificate(encoded));
        if(encoded[0]==0) {
            var delivery=RenewalMessage.pendingValue(encoded);
            if(!delivery.matchesBase(peerCertificate)||!Crypto.equal(delivery.administrator(),Crypto.ed25519Public(administratorSecret)))
                throw new SecurityException("保存した配送の基準が違います");
        }
        if(peerCertificate==null || !isAdministrator() || !Crypto.equal(peerId,Crypto.blake2s(peerCertificate.field(0)))
                || !Crypto.equal(peerId,Crypto.blake2s(renewal.field(0)))
                || !Crypto.equal(renewal.signer(),Crypto.ed25519Public(administratorSecret))
                || state.revocations().hasEntry(id()) || renewal.issuedAt()<=peerCertificate.issuedAt())
            throw new SecurityException("保存した更新の証明書が違います");
        var status=state.storedCertificateStatus(renewal,peerCertificate.field(1));
        if(status==AdminState.StoredCertificateStatus.CLOCK_FAILURE)throw new StoredCertificateFailure(UdpEndpoint.CloseReason.CLOCK_FAILURE);
        if(!recovery&&status!=AdminState.StoredCertificateStatus.VALID)throw new SecurityException("更新待ちの証明書は有効ではありません");
    }
    void rememberRenewal(byte[] peerId,byte[] encoded) {rememberRenewal(peerId,encoded,false);}
    private void rememberRenewal(byte[] peerId,byte[] encoded,boolean recovery) {
        verifyRenewal(peerId,encoded,recovery);String name=Hex.toHexString(peerId);byte[] previous=pendingRenewals.get(name);
        if(previous!=null&&!Arrays.equals(renewalCertificate(previous),renewalCertificate(encoded)))
            throw new SecurityException("発行済みの更新は差し替えません");
        pendingRenewals.put(name,encoded.clone());
    }
    static byte[] renewalCertificate(byte[] encoded) {
        if(encoded==null||encoded.length==0)throw new SecurityException("更新待ちの形式が違います");
        if(encoded[0]==0)return RenewalMessage.pendingValue(encoded).certificate();
        if(encoded[0]!=10)throw new SecurityException("更新待ちの形式が違います");
        AdminRecords.decode(encoded);return encoded.clone();
    }
    byte[] pendingRenewal(byte[] peerId){byte[] value=pendingRenewals.get(Hex.toHexString(peerId));return value==null?null:value.clone();}
    /** 保存に成功した相手の1枚だけを残す。取り外しと再設定の途中をUDPの検査に見せない。 */
    void retainPeerCertificatePermission() {
        synchronized(state) {
            state.forgetLegacyCertificate(peerCertificate.field(0));state.trustStoredLegacyCertificate(peerCertificate);
        }
    }
    UdpEndpoint.CloseReason pendingRenewalReason(){return pendingRenewalFailure;}
    byte[] removeRenewal(byte[] peerId){return pendingRenewals.remove(Hex.toHexString(peerId));}
    void restoreRenewal(byte[] peerId,byte[] value){if(value!=null)pendingRenewals.put(Hex.toHexString(peerId),value);}
    SessionManager sessions(Clock clock,java.util.function.LongSupplier ticker) {
        validate(true);var manager=new SessionManager(state,certificate,handshakeSecret,groupKey,keyVersion,clock,ticker,coreGroupSize());
        try{if(peerCertificate!=null && state.localCertificateReason(peerCertificate,peerCertificate.field(1))!=UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED)
                manager.rememberPeer(peerCertificate);
            if(isAdministrator())for(var entry:pendingRenewals.entrySet()) {
                byte[] id=Hex.decode(entry.getKey());
                if(manager.peerCertificate(id)!=null)manager.restorePeerRenewal(id,renewalCertificate(entry.getValue()),Crypto.ed25519Public(administratorSecret));
            }
            return manager;}
        catch(RuntimeException e){manager.close();throw e;}
    }
    /** ByteArrayOutputStreamの内部の平文も使い終わったら消す。 */
    private static final class WipingOutput extends ByteArrayOutputStream {
        private void reserve(int length){
            if(length<0||length>StateEnvelope.MAX_BYTES-64-count)throw new IllegalStateException("保存の上限を超えています");
            int needed=count+length;
            if(needed>buf.length){
                byte[] previous=buf;buf=Arrays.copyOf(previous,Math.min(StateEnvelope.MAX_BYTES-64,Math.max(needed,buf.length*2)));
                Arrays.fill(previous,(byte)0);
            }
        }
        @Override public synchronized void write(int value){reserve(1);super.write(value);}
        @Override public synchronized void write(byte[] bytes,int offset,int length){reserve(length);super.write(bytes,offset,length);}
        @Override public void close(){Arrays.fill(buf,(byte)0);reset();}
    }
    private static void bytes(DataOutputStream out,byte[] bytes)throws IOException {out.writeInt(bytes.length);out.write(bytes);}
    private static byte[] bytes(DataInputStream in)throws IOException {
        int length=in.readInt();if(length<0 || length>in.available())throw new IOException("保存した長さが違います");
        byte[] bytes=new byte[length];in.readFully(bytes);return bytes;
    }
    private static byte[] key(DataInputStream in,int size)throws IOException {
        byte[] bytes=bytes(in);if(bytes.length!=size){Crypto.wipe(bytes);throw new IOException("鍵の長さが違います");}return bytes;
    }
    byte[] encode()throws IOException {return encode(null,0,null,null,keyVersion);}
    byte[] encodeSix(ManagementState candidate,long generation,byte[] digest,byte[] key,long version)throws IOException {
        return encode(candidate,generation,digest,key,version);
    }
    private byte[] encode(ManagementState candidate,long generation,byte[] digest,byte[] key,long version)throws IOException {
        validate(true,candidate!=null);
        try(var buffer=new WipingOutput();var out=new DataOutputStream(buffer)) {
            out.writeInt(candidate==null?5:6);out.writeInt(port);bytes(out,identitySecret);bytes(out,handshakeSecret);bytes(out,administratorSecret);
            bytes(out,key==null?groupKey:key);out.writeLong(version);bytes(out,groupId);bytes(out,urlAdmin);bytes(out,certificate.encode());
            if(candidate!=null){out.writeLong(generation);bytes(out,digest);}else{
            var snapshot=state.snapshot();var records=snapshot.records();out.writeInt(records.size());
            for(byte[] record:records)bytes(out,record);
            bytes(out,snapshot.anchorSignature());bytes(out,snapshot.revocations());
            out.writeLong(snapshot.administratorVersion());out.writeLong(snapshot.revocationVersion());}
            out.writeBoolean(peerCertificate!=null);
            if(peerCertificate!=null){bytes(out,peerCertificate.encode());bytes(out,peerAddress.getAddress().getAddress());out.writeInt(peerAddress.getPort());}
            out.writeBoolean(pendingHandshake!=null);
            if(pendingHandshake!=null){bytes(out,pendingHandshake);bytes(out,pendingAddress.getAddress().getAddress());out.writeInt(pendingAddress.getPort());}
            out.writeBoolean(syncInitialized);out.writeInt(renewalCount);out.writeLong(saveSeq);
            out.writeInt(pendingRenewals.size());
            for(var entry:pendingRenewals.entrySet()){bytes(out,Hex.decode(entry.getKey()));bytes(out,entry.getValue());}
            out.writeLong(dhtLocalVersion);
            out.flush();if(buffer.size()>StateEnvelope.MAX_BYTES-64)throw new IOException("保存の上限を超えています");
            return buffer.toByteArray();
        }
    }
    static LanGroup decode(byte[] plain,Clock clock)throws IOException {return decode(plain,clock,false);}
    interface ManagementLoader {ManagementState load(long generation,byte[] digest)throws Exception;}
    static LanGroup decode(byte[] plain,Clock clock,boolean allowExpired)throws IOException {return decode(plain,clock,allowExpired,null);}
    static LanGroup decode(byte[] plain,Clock clock,boolean allowExpired,ManagementLoader loader)throws IOException {
        if(plain.length>StateEnvelope.MAX_BYTES)throw new IOException("保存の上限を超えています");
        LanGroup group=new LanGroup();
        try(var in=new DataInputStream(new ByteArrayInputStream(plain))) {
            group.clock=clock;int version=in.readInt();if(version<2||version>6)throw new IOException("保存した版が違います");
            group.port=in.readInt();group.identitySecret=key(in,32);group.handshakeSecret=key(in,32);group.administratorSecret=bytes(in);
            group.groupKey=key(in,32);group.keyVersion=in.readLong();group.groupId=key(in,32);group.urlAdmin=key(in,32);
            group.certificate=AdminRecords.decode(bytes(in));
            if(version==6){
                group.managementGeneration=in.readLong();group.managementDigest=key(in,32);
                if(loader==null||group.managementGeneration<=0)throw new IOException("管理ファイルがありません");
                try{group.management=loader.load(group.managementGeneration,group.managementDigest);}
                catch(Exception e){throw new IOException("管理ファイルを検証できません",e);}
                group.state=restore(group.groupId,group.urlAdmin,group.management.snapshot,clock);
            }else{
            int count=in.readInt();
            if(count<1 || count>in.available()/4)throw new IOException("記録の件数が違います");
            List<byte[]> records=new ArrayList<>();for(int i=0;i<count;i++)records.add(bytes(in));
            byte[] anchor=bytes(in),revoked=bytes(in);long admins=in.readLong(),revocations=in.readLong();
            group.state=restore(group.groupId,group.urlAdmin,new AdminRecordStore.Snapshot(records,anchor,revoked,admins,revocations),clock);}
            if(in.readBoolean()) {
                group.peerCertificate=AdminRecords.decode(bytes(in));byte[] address=key(in,4);int port=in.readInt();
                group.peerAddress=new InetSocketAddress(InetAddress.getByAddress(address),port);
            }
            if(in.readBoolean()) {
                group.pendingHandshake=key(in,32);byte[] address=key(in,4);int port=in.readInt();
                group.pendingAddress=new InetSocketAddress(InetAddress.getByAddress(address),port);
            }
            group.state.trustStoredLegacyCertificate(group.certificate);
            if(group.peerCertificate!=null)group.state.trustStoredLegacyCertificate(group.peerCertificate);
            if(version>=3){int initialized=in.readUnsignedByte();if(initialized>1)throw new IOException("同期の初期化の印が違います");group.syncInitialized=initialized==1;}
            if(version>=4){
                group.renewalCount=in.readInt();group.saveSeq=in.readLong();
                int pending=in.readInt();if(pending<0||pending>65535||pending>in.available()/8)throw new IOException("更新の件数が違います");
                Set<String> seen=new HashSet<>();
                for(int i=0;i<pending;i++) {
                    byte[] id=key(in,32),encoded=bytes(in);
                    try {
                        if(!seen.add(Hex.toHexString(id)))throw new SecurityException("更新の相手が重複しています");
                        if(encoded.length!=0) {
                            if(encoded[0]==10)group.state.trustStoredLegacyCertificate(AdminRecords.decode(encoded));
                            // 版 6 は期限切れの更新待ちも digest 照合のために残す（通信の許可にはならない）。
                            // Version 6 also keeps expired pending renewals for digest verification (they grant no communication permission).
                            group.rememberRenewal(id,encoded,version==6||encoded[0]==0);
                        }
                    }catch(RuntimeException e){
                        if(encoded.length>0&&encoded[0]!=10)throw e;
                        group.pendingRenewalFailure=UdpEndpoint.CloseReason.INTERNAL_FAILURE;
                        // 版6は停止印の照合まで元の符号化を保つ。通信の準備前に改めて整理する。
                        // Version six preserves original bytes until marker validation and cleans them before communication preparation.
                        if(version==6)group.restoreRenewal(id,encoded.clone());else group.removeRenewal(id);
                    }
                    finally{Crypto.wipe(encoded);}
                }
            }
            if(version>=5) {
                long dht=in.readLong();if(dht<0||dht==Long.MAX_VALUE)throw new IOException("DHT の版が違います");
                group.dhtLocalVersion=dht;
            }
            if(in.available()!=0)throw new IOException("保存した記録に余分な値があります");
            if(group.management!=null)group.management.verify(group,clock);
            if(version!=6)group.forgetRevokedPeer();
            group.validate(allowExpired,version==6);return group;
        }catch(IOException|RuntimeException e){group.close();throw e;}
    }
    private boolean revokedPeer(){return peerCertificate!=null&&state.revocations()!=null&&state.revokedSubjects().stream().anyMatch(id->Crypto.equal(id,Crypto.blake2s(peerCertificate.field(0))));}
    void cleanPendingRenewals(){
        for(var entry:new ArrayList<>(pendingRenewals.entrySet()))try{verifyRenewal(Hex.decode(entry.getKey()),entry.getValue(),true);}
        catch(RuntimeException invalid){pendingRenewalFailure=UdpEndpoint.CloseReason.INTERNAL_FAILURE;Crypto.wipe(pendingRenewals.remove(entry.getKey()));}
    }
    boolean forgetRevokedPeer(){
        if(!revokedPeer())return false;
        Crypto.wipe(removeRenewal(Crypto.blake2s(peerCertificate.field(0))));
        peerCertificate=null;peerAddress=null;revokedPeerForgotten=true;return true;
    }
    // AdminStateを変えられない段では、予約の例外文だけをここで見分ける。
    // Until AdminState can be changed, classify only its reservation message here.
    private static final String RESERVED_CLOSE="Management persistence is reserved";
    static boolean reservedClose(IllegalStateException failure){
        if(RESERVED_CLOSE.equals(failure.getMessage()))return true;
        throw failure;
    }
    boolean tryClose(){
        try{if(state!=null)state.clear();}
        catch(IllegalStateException failure){if(reservedClose(failure))return false;throw failure;}
        eraseOwned();return true;
    }
    @Override public void close() {
        // 予約中の拒否を先に受け、所有する秘密を途中まで消さない。
        // Check reservation refusal first so owned secrets are never partially erased.
        if(state!=null)state.clear();
        eraseOwned();
    }
    private void eraseOwned(){
        closed=true;Crypto.wipe(identitySecret);Crypto.wipe(handshakeSecret);Crypto.wipe(administratorSecret);Crypto.wipe(groupKey);
        for(byte[] renewal:pendingRenewals.values())Crypto.wipe(renewal);pendingRenewals.clear();
        clearPendingPeer();peerCertificate=null;peerAddress=null;certificate=null;
    }
    @Override public String toString(){return "LanGroup";}
}
