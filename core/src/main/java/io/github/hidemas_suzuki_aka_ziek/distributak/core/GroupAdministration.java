// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.*;
import java.util.function.LongSupplier;

/** 管理者の秘密鍵と、保存前の候補を所有する。通信と画面は持たない。 */
public final class GroupAdministration implements AutoCloseable {
    public static final int MAX_PENDING=32;
    public static final long PENDING_NANOS=600_000_000_000L;
    @FunctionalInterface public interface Saver {void save(AdminRecordStore.Snapshot snapshot);}
    @FunctionalInterface public interface Publisher {void publish(Candidate candidate);}
    @FunctionalInterface public interface CertificateSaver {void save(AdminRecords.Record certificate);}
    public enum Phase { PREPARE, REISSUE, CONFIRM, COMMIT, PUBLISH, COMPLETE, CANCELLED }
    public static final class NeedsRetainedAdministrator extends SecurityException {
        NeedsRetainedAdministrator(){super("残る管理者の協力が要ります");}
    }
    public static final class Candidate {
        private final GroupAdministration owner;private final AdminRecordStore.Snapshot expected;
        private final AdminState checked;private final AdminControl notice;private final String approvedPeer;
        private boolean used;private Preparation preparation;
        private Candidate(GroupAdministration owner,AdminState checked,AdminControl notice,String approvedPeer) {
            this.owner=owner;this.expected=owner.state.snapshot();this.checked=checked;this.notice=notice;this.approvedPeer=approvedPeer;
        }
        public AdminRecords.Record administrators(){return checked.administrators();}
        public AdminRecords.Record revocations(){return checked.revocations();}
        public AdminRecordStore.Snapshot snapshot(){return checked.snapshot();}
        public AdminControl notice(){return notice;}
        @Override public String toString(){return "Administration candidate";}
    }
    private static final class Pending {
        final byte[] peer,digest;final long began,version;final SessionManager sessions;final boolean outbound;
        AdminControl message;byte[] secret;
        Pending(SessionManager sessions,byte[] peer,AdminRecords.Record certificate,long now,long version,boolean outbound,AdminControl message,byte[] secret) {
            this.sessions=sessions;
            this.peer=peer.clone();digest=Crypto.blake2s(certificate.signedBytes());began=now;this.version=version;
            this.outbound=outbound;this.message=message;this.secret=secret;
        }
        void close(){Crypto.wipe(secret);secret=null;}
    }
    private final AdminState state;private final byte[] group,identitySecret,handshakeSecret,member;
    private final Clock clock;private final LongSupplier nanos;private final SecureRandom random;
    private final MemberDirectory directory;private final Map<String,Pending> pending=new HashMap<>();
    private byte[] administratorSecret,legacyAdministratorIdentity;private AdminRecords.Record certificate;
    private List<byte[]> legacyAdministratorBasis=List.of();
    private volatile boolean closed,stopped;
    private KeyRotationCoordinator rotations;
    private SessionManager rotationSessions;
    private io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.RevocationUnion rotationUnion;
    private final ProofRequests incomingProofs;
    private static final class AcceptedDelivery {
        final RenewalMessage message;final byte[] peer;
        AcceptedDelivery(RenewalMessage message,byte[] peer){this.message=message;this.peer=peer.clone();}
        void close(){Crypto.wipe(peer);}
    }
    private AcceptedDelivery acceptedDelivery;
    public GroupAdministration(AdminState state,AdminRecords.Record certificate,byte[] identitySecret,byte[] handshakeSecret,
            byte[] legacyAdministratorSecret,Clock clock,LongSupplier nanos,SecureRandom random) {
        this.state=Objects.requireNonNull(state);this.clock=Objects.requireNonNull(clock);this.nanos=Objects.requireNonNull(nanos);this.random=Objects.requireNonNull(random);
        Crypto.length(identitySecret,32);Crypto.length(handshakeSecret,32);state.verifyCertificate(certificate,Crypto.x25519Public(handshakeSecret),true);
        if(!Crypto.equal(certificate.field(0),Crypto.ed25519Public(identitySecret)))throw invalid();
        this.certificate=certificate;this.identitySecret=identitySecret.clone();this.handshakeSecret=handshakeSecret.clone();
        group=certificate.group();member=Crypto.blake2s(certificate.field(0));incomingProofs=new ProofRequests(random,nanos);
        if(legacyAdministratorSecret!=null&&legacyAdministratorSecret.length!=0){Crypto.length(legacyAdministratorSecret,32);
            if(!state.administrators().hasEntry(Crypto.ed25519Public(legacyAdministratorSecret)))throw invalid();administratorSecret=legacyAdministratorSecret.clone();}
        directory=new MemberDirectory(state,this::bindings);directory.saved(certificate);
    }
    /** 保存の読み戻し専用。保存相手は生成時にだけ渡し、通信の受け口に差し替えの口を出さない。 */
    public static GroupAdministration fromSaved(AdminState state,AdminRecords.Record certificate,byte[] identitySecret,byte[] handshakeSecret,
            byte[] administratorSecret,Clock clock,LongSupplier nanos,SecureRandom random,AdminRecords.Record savedPeer) {
        var result=new GroupAdministration(state,certificate,identitySecret,handshakeSecret,administratorSecret,clock,nanos,random);
        try{result.savedAdministratorPeer(savedPeer);return result;}catch(RuntimeException failure){result.close();throw failure;}
    }
    private void savedAdministratorPeer(AdminRecords.Record peer) {
        var list=state.administrators();
        if(certificate.format()!=1||list.hasAdminBindings()||list.entries().size()!=1||legacyAdministratorIdentity!=null)throw invalid();
        state.verifyCertificate(certificate,certificate.field(1));state.verifyCertificate(peer,peer.field(1));
        byte[] key=list.entries().get(0);
        if(administratorSecret!=null&&Crypto.equal(Crypto.ed25519Public(administratorSecret),key))throw invalid();
        if(!Crypto.equal(certificate.group(),group)||!Crypto.equal(certificate.signer(),key)||!Crypto.equal(peer.signer(),key)
                ||Crypto.equal(peer.field(0),certificate.field(0)))throw invalid();
        legacyAdministratorIdentity=peer.field(0);legacyAdministratorBasis=List.of(certificate.encode(),peer.encode());
    }
    /**
     * 保存時に固定した対応の根拠を返す。署名一覧に対応があれば旧根拠を捨てる。
     * <p>
     * Returns evidence pinned at save time, discarding legacy evidence once signed bindings exist.
     */
    public synchronized List<byte[]> legacyAdministratorBasis(){
        var list=state.administrators();
        if(list.hasAdminBindings()||list.entries().size()!=1){legacyAdministratorIdentity=null;legacyAdministratorBasis=List.of();}
        var result=new ArrayList<byte[]>();for(byte[] bytes:legacyAdministratorBasis)result.add(bytes.clone());return List.copyOf(result);
    }
    /**
     * 保存した対応を検証して復元する。根拠証明書の期限だけを緩め、通信権限には変換しない。
     * <p>
     * Verifies and restores a saved mapping, relaxing only evidence expiry without granting communication authority.
     */
    public synchronized void restoreLegacyAdministratorBasis(List<byte[]> basis){
        if(basis.isEmpty())return;
        if(basis.size()!=2)throw invalid();var own=AdminRecords.decode(basis.get(0));var peer=AdminRecords.decode(basis.get(1));
        var list=state.administrators();
        if(own.format()!=1||list.hasAdminBindings()||list.entries().size()!=1||!Crypto.equal(own.field(0),certificate.field(0)))throw invalid();
        byte[] key=list.entries().get(0);
        if(administratorSecret!=null&&Crypto.equal(Crypto.ed25519Public(administratorSecret),key)
                ||!Crypto.equal(own.group(),group)||!Crypto.equal(peer.group(),group)||!Crypto.equal(own.signer(),key)
                ||!Crypto.equal(peer.signer(),key)||Crypto.equal(own.field(0),peer.field(0)))throw invalid();
        if(!own.hasValidSignature()||!peer.hasValidSignature()||!own.verifyIdentityBinding()||!peer.verifyIdentityBinding())throw invalid();
        state.trustStoredLegacyCertificate(own);state.trustStoredLegacyCertificate(peer);
        state.verifyCertificate(own,own.field(1),true);state.verifyCertificate(peer,peer.field(1),true);
        legacyAdministratorIdentity=peer.field(0);legacyAdministratorBasis=List.of(own.encode(),peer.encode());
    }
    private static SecurityException invalid(){return new SecurityException("管理操作の条件が一致しません");}
    private static String name(byte[] value){return Base64.getEncoder().encodeToString(value);}
    private byte[] id(){byte[] id=new byte[16];random.nextBytes(id);return id;}
    private byte[] secret(){byte[] key=new byte[32];random.nextBytes(key);return key;}
    private void open(){if(closed||stopped)throw new IllegalStateException("管理操作は停止しています");}
    public synchronized boolean isAdministrator(){return !closed&&!stopped&&administratorSecret!=null&&state.administrators().hasEntry(Crypto.ed25519Public(administratorSecret));}
    private void requireAdministrator(){open();if(!isAdministrator())throw invalid();state.verifyCertificate(certificate,certificate.field(1));}
    /**
     * 手動操作と競合の統合で、同じ待機・番号予約を使う。
     * <p>
     * Shares delays and version reservations between manual operations and conflict consolidation.
     */
    public synchronized KeyRotationCoordinator rotations(SessionManager sessions,
            io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.RevocationUnion union,Clock deadlines){
        return rotations(sessions,union,deadlines,null);
    }
    /**
     * Controller と同じ保存調整層を使い、セッションへ二重に登録しない。
     * <p>
     * Shares the Controller's persistence coordinator without registering twice on the session manager.
     */
    public synchronized KeyRotationCoordinator rotations(SessionManager sessions,
            io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.RevocationUnion union,Clock deadlines,CorePersistenceCoordinator shared){
        requireAdministrator();
        if(rotations==null){
            rotations=new KeyRotationCoordinator(state,sessions,union,administratorSecret,clock,deadlines,random,member,()->!closed&&!stopped,shared);
            rotationSessions=sessions;rotationUnion=union;
        }else if(rotationSessions!=sessions||rotationUnion!=union||shared!=null&&rotations.persistence()!=shared)throw invalid();
        return rotations;
    }
    public synchronized AdminRecords.Record certificate(){return certificate;}
    /** 旧署名済み記録はそのままにし、自分の鍵だけの所持証明を上に重ねる。 */
    public synchronized List<AdminBinding> bindings() {
        open();var current=state.administrators();var values=new ArrayList<>(current.bindings());
        if(administratorSecret!=null&&current.hasEntry(Crypto.ed25519Public(administratorSecret))) {
            byte[] key=Crypto.ed25519Public(administratorSecret);
            for(int i=0;i<values.size();i++)if(Crypto.equal(values.get(i).administratorKey(),key)&&values.get(i).state()==AdminBinding.State.UNKNOWN) {
                var proof=AdminControl.keyProof(group,new byte[16],current.version(),identitySecret,administratorSecret);
                values.set(i,AdminBinding.bound(key,member,proof.encode()));
            }
        }return List.copyOf(values);
    }
    public synchronized MemberDirectory directory(){requireAdministrator();return directory;}
    public synchronized void joined(UdpEndpoint.AdminJoined joined){requireAdministrator();directory.joined(joined);}
    public synchronized void authenticatedFirst(SessionManager sessions,byte[] peer){requireAdministrator();directory.authenticatedFirst(sessions,peer);}
    /** 通信の入口で、DATAを復号したときのsessionを渡す。古いsessionの値は受けない。 */
    private AdminRecords.Record authenticate(SessionManager sessions,byte[] peer,byte[] session) {
        open();Crypto.length(peer,32);Crypto.length(session,16);
        if(!Crypto.equal(sessions.sessionId(peer),session))throw invalid();
        var cert=sessions.peerCertificate(peer);if(cert==null||!Crypto.equal(peer,Crypto.blake2s(cert.field(0))))throw invalid();
        state.verifyCertificate(cert,cert.field(1));return cert;
    }
    private boolean administratorPeer(AdminRecords.Record cert) {
        byte[] peer=Crypto.blake2s(cert.field(0));for(var binding:bindings())
            if(binding.state()==AdminBinding.State.BOUND&&Crypto.equal(binding.memberId(),peer)&&Crypto.equal(binding.identityKey(),cert.field(0)))return true;
        return false;
    }
    public synchronized void expire() {
        open();long now=nanos.getAsLong(),version=state.administrators().version();
        pending.values().removeIf(p->{boolean remove=now<p.began||now-p.began>=PENDING_NANOS||p.version!=version||!pendingPeerValid(p);
            if(remove)p.close();return remove;});
    }
    private boolean pendingPeerValid(Pending pending) {
        try {var cert=pending.sessions.peerCertificate(pending.peer);if(cert==null||!Crypto.equal(pending.digest,Crypto.blake2s(cert.signedBytes())))return false;
            state.verifyCertificate(cert,cert.field(1));return true;
        }catch(RuntimeException unavailable){return false;}
    }
    private Pending checkedPending(byte[] peer,AdminRecords.Record cert) {
        expire();String key=name(peer);var p=pending.get(key);
        if(p!=null&&!Crypto.equal(p.digest,Crypto.blake2s(cert.signedBytes()))){p.close();pending.remove(key);return null;}return p;
    }
    private void put(SessionManager sessions,byte[] peer,AdminRecords.Record cert,boolean outbound,AdminControl message,byte[] secret) {
        if(pending.containsKey(name(peer))||pending.size()>=MAX_PENDING){Crypto.wipe(secret);throw invalid();}
        pending.put(name(peer),new Pending(sessions,peer,cert,nanos.getAsLong(),state.administrators().version(),outbound,message,secret));
    }
    public synchronized AdminControl request(SessionManager sessions,byte[] peer) {
        var cert=authenticate(sessions,peer,sessions.sessionId(peer));if(!administratorPeer(cert)&&!legacySingleAdministratorPeer(cert))throw invalid();
        if(certificate.format()!=2)throw invalid();var previous=checkedPending(peer,cert);if(previous!=null){if(!previous.outbound)throw invalid();return previous.message;}
        byte[] key=secret();AdminControl request;
        try{request=AdminControl.request(group,id(),state.administrators().version(),identitySecret,key);}catch(RuntimeException e){Crypto.wipe(key);throw e;}
        put(sessions,peer,cert,true,request,key);return request;
    }
    private boolean legacySingleAdministratorPeer(AdminRecords.Record cert) {
        var current=state.administrators();
        if(current.hasAdminBindings()||current.entries().size()!=1){Crypto.wipe(legacyAdministratorIdentity);legacyAdministratorIdentity=null;return false;}
        return legacyAdministratorIdentity!=null&&Crypto.equal(cert.field(0),legacyAdministratorIdentity)&&Crypto.equal(cert.signer(),current.entries().get(0));
    }
    public synchronized AdminControl offer(SessionManager sessions,byte[] peer) {
        requireAdministrator();var cert=authenticate(sessions,peer,sessions.sessionId(peer));var previous=checkedPending(peer,cert);
        if(previous!=null){if(previous.outbound||previous.message.operation()!=AdminControl.Operation.OFFER)throw invalid();return previous.message;}
        var offer=AdminControl.offer(group,id(),peer,state.administrators().version(),administratorSecret);put(sessions,peer,cert,false,offer,null);return offer;
    }
    public synchronized AdminControl receive(SessionManager sessions,byte[] peer,byte[] session,AdminControl message) {
        var cert=authenticate(sessions,peer,session);var p=checkedPending(peer,cert);
        if(!Crypto.equal(message.group(),group))throw invalid();
        if(message.operation()==AdminControl.Operation.APPROVED||message.operation()==AdminControl.Operation.REJECTED) {
            if(p==null||!p.outbound||!Crypto.equal(message.requestId(),p.message.requestId())||!Crypto.equal(message.memberId(),member)
                    ||!Crypto.equal(message.administratorKey(),p.message.administratorKey()))throw invalid();
            if(message.operation()==AdminControl.Operation.APPROVED){if(message.baseVersion()!=p.version+1)throw invalid();return null;}
            if(message.baseVersion()!=p.version)throw invalid();p.close();pending.remove(name(peer));return null;
        }
        if(message.baseVersion()!=state.administrators().version())throw invalid();
        if(message.operation()==AdminControl.Operation.OFFER) {
            if(!Crypto.equal(message.memberId(),member)||!state.administrators().hasEntry(message.administratorKey())||!message.verifyOffer())throw invalid();
            var binding=state.administrators().binding(message.administratorKey());
            if(binding.state()==AdminBinding.State.BOUND&&(!Crypto.equal(binding.memberId(),peer)||!Crypto.equal(binding.identityKey(),cert.field(0))))throw invalid();
            if(p!=null){if(!p.outbound||!Crypto.equal(p.message.requestId(),message.requestId()))throw invalid();return p.message;}
            if(certificate.format()!=2)throw invalid();byte[] key=secret();var proof=AdminControl.keyProof(group,message.requestId(),message.baseVersion(),identitySecret,key);
            put(sessions,peer,cert,true,proof,key);return proof;
        }
        requireAdministrator();
        if(cert.format()!=2||!message.verifyPossessionProof()||!Crypto.equal(message.memberId(),peer)||!Crypto.equal(message.identityKey(),cert.field(0)))throw invalid();
        if(p!=null) {
            if(p.outbound)throw invalid();
            if(p.message.operation()==AdminControl.Operation.OFFER) {
                if(message.operation()!=AdminControl.Operation.KEY_PROOF||!Crypto.equal(p.message.requestId(),message.requestId()))throw invalid();p.message=message;
            }else if(!Arrays.equals(p.message.encode(),message.encode()))throw invalid();
        }else {if(message.operation()!=AdminControl.Operation.REQUEST)throw invalid();put(sessions,peer,cert,false,message,null);}
        return null;
    }
    public synchronized Candidate approve(SessionManager sessions,byte[] peer) {
        requireAdministrator();var cert=authenticate(sessions,peer,sessions.sessionId(peer));var p=checkedPending(peer,cert);
        if(p==null||p.outbound||!p.message.verifyPossessionProof())throw invalid();
        var bindings=new ArrayList<>(bindings());
        for(var b:bindings)if(Crypto.equal(b.administratorKey(),p.message.administratorKey())||b.state()==AdminBinding.State.BOUND&&Crypto.equal(b.memberId(),peer))throw invalid();
        bindings.add(AdminBinding.bound(p.message.administratorKey(),peer,p.message.encode()));
        var candidate=withBindings(bindings,AdminControl.approved(p.message,Math.addExact(state.administrators().version(),1)),name(peer));return candidate;
    }
    public synchronized AdminControl reject(SessionManager sessions,byte[] peer) {
        requireAdministrator();var cert=authenticate(sessions,peer,sessions.sessionId(peer));var p=checkedPending(peer,cert);
        if(p==null||p.outbound||!p.message.verifyPossessionProof())throw invalid();var reply=AdminControl.rejected(p.message);p.close();pending.remove(name(peer));return reply;
    }
    private Candidate withBindings(List<AdminBinding> bindings,AdminControl notice,String approvedPeer) {
        var current=state.administrators();var next=AdminRecords.administrators(group,Math.addExact(current.version(),1),clock.millis(),bindings,administratorSecret);
        var rev=state.revocations();var revocation=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group,Math.addExact(rev.version(),1),clock.millis(),rev.entries(),administratorSecret);
        var checked=state.fork();if(!checked.acceptAdministrators(next,v->{throw invalid();})||!checked.acceptRevocations(revocation))throw invalid();
        return new Candidate(this,checked,notice,approvedPeer);
    }
    public synchronized Candidate received(AdminRecords.Record administrators,AdminRecords.Record revocations) {
        open();var checked=state.fork();checked.acceptAdministrators(administrators,v->{throw invalid();});checked.acceptRevocations(revocations);
        return new Candidate(this,checked,null,null);
    }
    /** 失敗時は候補を再試行できる。公開の失敗は通信再開せず停止する。 */
    public synchronized void persist(Candidate candidate,Saver saver,Publisher publisher) {
        open();if(candidate.owner!=this||candidate.used)throw invalid();
        validateCandidate(candidate);
        var checked=candidate.checked.fork();
        boolean[] saved={false};
        try{state.applyCandidate(candidate.expected,checked,()->{validateCandidate(candidate);saver.save(candidate.snapshot());saved[0]=true;
            // 保存に成功した事実を Preparation に残す。以後 expired()・cancel() は状態を戻さない。 / Record the successful save on the Preparation so expired() and cancel() no longer revert the state.
            if(candidate.preparation!=null)candidate.preparation.saved=true;validateCandidate(candidate);});}
        catch(RuntimeException failure){if(saved[0])stopped=true;throw failure;}
        candidate.used=true;
        if(state.administrators().hasAdminBindings()){Crypto.wipe(legacyAdministratorIdentity);legacyAdministratorIdentity=null;}
        activateSavedProof();
        if(candidate.approvedPeer!=null){var p=pending.remove(candidate.approvedPeer);if(p!=null)p.close();}
        expire();
        if(administratorSecret!=null&&!state.administrators().hasEntry(Crypto.ed25519Public(administratorSecret))){Crypto.wipe(administratorSecret);administratorSecret=null;directory.clear();}
        try{publisher.publish(candidate);}catch(RuntimeException failure){stopped=true;throw failure;}
        // 公開まで成功したら Preparation を完了にする（publish 経由でも直接でも同じ）。 / After a successful publish, complete the Preparation (same via publish or directly).
        if(candidate.preparation!=null)candidate.preparation.completed();
    }
    private void validateCandidate(Candidate candidate) {
        if(candidate.preparation!=null)candidate.preparation.beforeCommit();
        if(candidate.approvedPeer!=null) {
            requireAdministrator();expire();var p=pending.get(candidate.approvedPeer);
            if(p==null||p.outbound)throw invalid();var binding=candidate.administrators().binding(p.message.administratorKey());
            if(binding==null||!Arrays.equals(binding.possessionProof(),p.message.encode()))throw invalid();
        }
    }
    private void activateSavedProof() {
        long now=nanos.getAsLong();
        for(var iterator=pending.values().iterator();iterator.hasNext();) {
            var p=iterator.next();if(!p.outbound||p.secret==null||!pendingPeerValid(p)||now<p.began||now-p.began>=PENDING_NANOS)continue;
            var binding=state.administrators().binding(Crypto.ed25519Public(p.secret));
            if(binding!=null&&binding.state()==AdminBinding.State.BOUND&&Crypto.equal(binding.memberId(),member)
                    &&Arrays.equals(binding.possessionProof(),p.message.encode())&&state.administrators().version()>=p.version+1) {
                Crypto.wipe(administratorSecret);administratorSecret=p.secret;p.secret=null;p.close();iterator.remove();return;
            }
        }
    }
    /** 秘密鍵を渡さずに、新しい加入の公開証明書を作る。保存と配送は上位が行う。 */
    public synchronized AdminRecords.Record issueCertificate(byte[] identity,byte[] handshake,byte[] proof) {
        requireAdministrator();return AdminRecords.certificate(group,identity,handshake,proof,clock.millis(),administratorSecret);
    }
    public synchronized byte[] respondInvitation(JoinHandshake.Admin invitation,byte[] request,byte[] groupKey,long keyVersion) {
        try(var materials=invitationMaterials(groupKey,keyVersion,null)){
            return invitation.respond(request,handshakeSecret,administratorSecret,materials);
        }
    }
    /**
     * 現在の管理者だけが告知を保存し、R を包含する加入の材料を返す。使い終わった材料は呼び出し側が閉じる。
     * <p>
     * Only a current administrator saves the announcement and returns R-complete join materials. The caller closes the materials after use.
     */
    public synchronized JoinHandshake.Materials invitationMaterials(byte[] groupKey,long keyVersion,byte[] expectedIdentity){
        requireAdministrator();
        if(!state.coversRevocations(state.revocations()))throw new SecurityException("Invitation omits accepted revocations");
        var current=state.announcement();
        if(current!=null&&current.keyVersion()==keyVersion)current.checkKey(group,keyVersion,groupKey);
        boolean reusable=false;
        if(current!=null)try{state.verifyAnnouncement(current,state.revocations());current.checkKey(group,keyVersion,groupKey);reusable=true;}catch(SecurityException stale){reusable=false;}
        if(!reusable){
            var r=state.revocations();var a=state.administrators();
            current=KeyAnnouncement.issue(group,administratorSecret,keyVersion,Math.max(r.signedAt(),a.signedAt()),r.version(),Crypto.blake2s(r.signedBytes()),
                KeyAnnouncement.commitment(group,keyVersion,groupKey),a.version(),Crypto.blake2s(a.signedBytes()));
            state.recordGroupKey(current,groupKey,keyVersion);
        }
        return expectedIdentity==null?JoinHandshake.Materials.verified(state,List.of(state.administrators()),keyVersion,groupKey)
            :JoinHandshake.Materials.verified(state,List.of(state.administrators()),keyVersion,groupKey,expectedIdentity);
    }
    public synchronized Invitation invitation(byte[] address,int port,byte[] totpSecret) {
        requireAdministrator();return new Invitation(address,port,Crypto.x25519Public(handshakeSecret),Crypto.ed25519Public(administratorSecret),totpSecret,group);
    }
    public synchronized JoinHandshake.Admin invitationIssuer(Invitation invitation) {
        requireAdministrator();var first=state.administrators();return new JoinHandshake.Admin(invitation,first,AdminRecords.signAnchor(first,administratorSecret),clock,nanos);
    }
    public synchronized AdminRecords.Record invitationCertificateCandidate() {
        requireAdministrator();return state.prepareInvitationCertificate(certificate,handshakeSecret,identitySecret,administratorSecret);
    }
    public synchronized void saveOwnCertificate(AdminRecords.Record next,CertificateSaver saver) {
        open();state.verifyCertificate(next,Crypto.x25519Public(handshakeSecret));
        if(!Crypto.equal(next.field(0),certificate.field(0))||next.issuedAt()<=certificate.issuedAt())throw invalid();
        saver.save(next);certificate=next;directory.saved(next);
    }
    /** 現在の認証済み管理者からの、本人用の要求だけを自動で返す。 */
    public synchronized RenewalMessage receiveProofRequest(SessionManager sessions,byte[] peer,byte[] session,RenewalMessage request) {
        var sender=authenticate(sessions,peer,session);
        if(request.operation()!=RenewalMessage.Operation.PROOF_REQUEST||!request.matchesBase(certificate)
                ||!state.administrators().hasEntry(request.administrator()))throw invalid();
        verifyRenewalAdministrator(sender,peer,request);
        verifyRenewalReason(request,certificate);
        if(request.reason()==RenewalMessage.Reason.AUTO_RENEWAL&&certificate.identityProofFormat()==2)throw invalid();
        if(!incomingProofs.remember(peer,session,request))throw invalid();return RenewalMessage.reply(request,identitySecret);
    }
    private void verifyRenewalAdministrator(AdminRecords.Record sender,byte[] peer,RenewalMessage message) {
        if(!Crypto.equal(message.group(),group)||!Crypto.equal(message.memberId(),member)||!state.administrators().hasEntry(message.administrator()))throw invalid();
        var binding=state.administrators().binding(message.administrator());
        boolean bound=binding!=null&&binding.state()==AdminBinding.State.BOUND&&Crypto.equal(binding.memberId(),peer)&&Crypto.equal(binding.identityKey(),sender.field(0));
        if(!bound&&!(message.reason()==RenewalMessage.Reason.INVITATION_PREPARE&&legacySingleAdministratorPeer(sender)))throw invalid();
    }
    private void verifyRenewalReason(RenewalMessage message,AdminRecords.Record base) {
        switch(message.reason()) {
            case AUTO_RENEWAL -> {if(message.managementOperation()!=null||!ProofRequests.due(base,clock.millis()))throw invalid();}
            case ADMIN_REMOVAL_PREPARE -> Crypto.length(message.managementOperation(),16);
            case INVITATION_PREPARE -> {Crypto.length(message.managementOperation(),16);if(base.format()!=1)throw invalid();}
        }
    }
    public synchronized AdminRecords.Record receiveCertificateDelivery(SessionManager sessions,byte[] peer,byte[] session,RenewalMessage delivery,CertificateSaver saver) {
        var sender=authenticate(sessions,peer,session);
        if(delivery.operation()!=RenewalMessage.Operation.CERTIFICATE_DELIVERY)throw invalid();
        verifyRenewalAdministrator(sender,peer,delivery);
        var next=AdminRecords.decode(delivery.certificate());
        if(next.format()!=2||next.identityProofFormat()!=2||!Crypto.equal(next.signer(),delivery.administrator())
                ||!Crypto.equal(next.field(0),certificate.field(0))||!Crypto.equal(next.field(1),certificate.field(1)))throw invalid();
        state.verifyCertificate(next,Crypto.x25519Public(handshakeSecret));
        if(Arrays.equals(next.encode(),certificate.encode())) {
            // 再鍵のあとは新しい要求番号で同じ証明書が届くので、要求番号以外が同じなら成功とする（04 §4.5、DTAK-7）。 / After a re-key the same certificate arrives with a new request id, so accept it when everything but the request id matches (04 §4.5, DTAK-7).
            var receipt=acceptedDelivery;
            if(receipt==null||!Crypto.equal(receipt.peer,peer)||!receipt.message.sameOperation(delivery)
                    ||!Arrays.equals(receipt.message.certificate(),delivery.certificate()))throw invalid();
            return certificate;
        }
        if(!delivery.matchesBase(certificate))throw invalid();
        state.verifyCertificate(certificate,certificate.field(1));verifyRenewalReason(delivery,certificate);
        if(certificate.identityProofFormat()==2) {
            if(!Crypto.equal(next.field(2),certificate.field(2)))throw invalid();
        } else if(incomingProofs.match(peer,session,delivery)==null)throw invalid();
        saveOwnCertificate(next,saver);incomingProofs.forget(peer);
        if(acceptedDelivery!=null)acceptedDelivery.close();acceptedDelivery=new AcceptedDelivery(delivery,peer);
        return next;
    }
    public record PreparationResult(boolean completed,int incomplete,boolean timedOut) {}
    public synchronized Preparation prepareRemoval(SessionManager sessions,List<byte[]> keys,boolean allUnknown) {
        requireAdministrator();return new Preparation(sessions,keys,allUnknown,false);
    }
    public synchronized Preparation prepareInvitation(SessionManager sessions) {
        requireAdministrator();return new Preparation(sessions,List.of(),false,true);
    }
    /** 途中で保存した証明書は取り消さず、一覧を確定する前だけ待つ。 */
    public final class Preparation {
        private final SessionManager sessions;private final List<byte[]> removed=new ArrayList<>();
        private final byte[] baseline,operation=id();private final boolean invitation,unknown;
        private final Map<String,AdminRecords.Record> waiting=new LinkedHashMap<>(),issued=new HashMap<>();
        private final Map<String,RenewalMessage> provenRequests=new HashMap<>();
        private final Map<String,byte[]> peers=new HashMap<>();private final Set<String> confirmed=new HashSet<>();
        private final ProofRequests requests=new ProofRequests(random,nanos);
        private Phase phase=Phase.PREPARE;private long confirmBegan;
        // 保存に成功したら true。以後は期限切れ・取り消しで状態を戻さない（04 §4.5、DTAK-8）。 / True once the save succeeded; expiry and cancel never revert the state afterwards (04 §4.5, DTAK-8).
        private boolean saved;
        private Preparation(SessionManager sessions,List<byte[]> keys,boolean unknown,boolean invitation) {
            this.sessions=Objects.requireNonNull(sessions);this.invitation=invitation;this.unknown=unknown;baseline=bindingStamp();
            for(byte[] key:keys){Crypto.length(key,32);if(removed.stream().anyMatch(k->Crypto.equal(k,key)))throw invalid();removed.add(key.clone());}
            var bindings=bindings();
            if(!invitation) {
                if(unknown) {var expected=bindings.stream().filter(b->b.state()==AdminBinding.State.UNKNOWN).collect(java.util.stream.Collectors.toList());
                    if(expected.size()!=removed.size()||expected.stream().anyMatch(b->!removes(b.administratorKey())))throw invalid();}
                if(removed.isEmpty()||bindings.stream().noneMatch(b->!removes(b.administratorKey())))throw invalid();
                for(byte[] key:removed)if(bindings.stream().noneMatch(b->Crypto.equal(key,b.administratorKey())))throw invalid();
                if(removes(Crypto.ed25519Public(administratorSecret)))throw new NeedsRetainedAdministrator();
                // 残る全管理者の身元が確かめられなければ、先に削除しない。
                for(var binding:bindings)if(!removes(binding.administratorKey())) {
                    if(binding.state()!=AdminBinding.State.BOUND)throw invalid();
                    if(!Crypto.equal(binding.memberId(),member)) {
                        var entry=directory.get(binding.memberId());if(entry==null)throw invalid();
                        state.verifyCertificate(entry.certificate(),entry.handshakeKey());
                        if(removes(entry.certificate().signer())&&sessions.verifiedSession(entry.memberId())==null)throw invalid();
                    }
                }
            }
            // 開始時のオンラインの集合を固定する。後からオフラインになっても外さない。
            for(var entry:directory.validRecipients()) {
                if(Crypto.equal(entry.memberId(),member)||sessions.verifiedSession(entry.memberId())==null)continue;
                if(invitation?entry.certificate().format()!=1:!removes(entry.certificate().signer()))continue;
                String key=name(entry.memberId());waiting.put(key,entry.certificate());peers.put(key,entry.memberId());
            }
        }
        private boolean removes(byte[] key){return removed.stream().anyMatch(k->Crypto.equal(k,key));}
        private void unchanged() {
            open();if(phase==Phase.CANCELLED||phase==Phase.COMPLETE||!Arrays.equals(baseline,bindingStamp())){cancel();throw invalid();}
        }
        public Phase phase(){return phase;}
        public int incomplete(){return waiting.size()-confirmed.size();}
        public PreparationResult result() {
            synchronized(GroupAdministration.this) {
                if(!invitation)throw invalid();if(phase==Phase.PREPARE)throw invalid();
                boolean timedOut=expired();boolean complete=incomplete()==0;
                if(complete){phase=Phase.COMPLETE;requests.close();}
                return new PreparationResult(complete,incomplete(),timedOut);
            }
        }
        /** PREPAREの次に1度呼ぶ。自分の切り替えも保存成功後だけ採る。 */
        public void reissue(CertificateSaver saver) {
            synchronized(GroupAdministration.this) {
                unchanged();if(phase!=Phase.PREPARE)throw invalid();
                if(invitation||removes(certificate.signer())) {
                    var next=invitation?invitationCertificateCandidate():state.issueCertificateRenewal(certificate,
                            SignaturePurpose.identityProof(identitySecret,group,certificate.field(1)),administratorSecret,RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,operation);
                    if(next!=null)saveOwnCertificate(next,saver);
                    if(invitation&&certificate.format()!=2)throw new IllegalStateException("時計が進むまで待ちます");
                }
                phase=Phase.REISSUE;confirmBegan=nanos.getAsLong();
            }
        }
        /** proof2は再利用し、形式1の相手には本人からの返信を求める。 */
        public RenewalMessage next(byte[] peer,CertificateSaver saver) {
            synchronized(GroupAdministration.this) {
                unchanged();if(phase!=Phase.REISSUE&&phase!=Phase.CONFIRM||expired())throw invalid();
                String key=name(peer);var base=waiting.get(key);if(base==null||confirmed.contains(key))return null;
                byte[] session=sessions.sessionId(peer);authenticate(sessions,peer,session);
                var reason=invitation?RenewalMessage.Reason.INVITATION_PREPARE:RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE;
                var request=requests.begin(peer,session,base,Crypto.ed25519Public(administratorSecret),reason,operation);if(request==null)return null;
                var ready=issued.get(key);
                if(base.identityProofFormat()!=2&&!request.sameRequest(provenRequests.get(key)))return request;
                if(ready!=null)return RenewalMessage.delivery(request,ready.encode());
                var next=state.issueCertificateRenewal(base,base.field(2),administratorSecret,reason,operation);
                saver.save(next);issued.put(key,next);phase=Phase.CONFIRM;return RenewalMessage.delivery(request,next.encode());
            }
        }
        public RenewalMessage reply(byte[] peer,byte[] session,RenewalMessage reply,CertificateSaver saver) {
            synchronized(GroupAdministration.this) {
                unchanged();if(phase!=Phase.REISSUE&&phase!=Phase.CONFIRM||expired())throw invalid();authenticate(sessions,peer,session);
                var request=requests.match(peer,session,reply);var base=waiting.get(name(peer));
                if(request==null||base==null||reply.operation()!=RenewalMessage.Operation.PROOF_REPLY||!request.matchesBase(base)
                        ||!Crypto.equal(reply.identity(),base.field(0))||!SignaturePurpose.verifyIdentity(group,reply.identity(),reply.handshake(),reply.proof()))throw invalid();
                var next=issued.get(name(peer));if(next==null){next=state.issueCertificateRenewal(base,reply.proof(),administratorSecret,reply.reason(),operation);saver.save(next);issued.put(name(peer),next);}
                if(!Crypto.equal(next.field(2),reply.proof()))throw invalid();
                state.verifyCertificate(next,base.field(1));provenRequests.put(name(peer),request);
                phase=Phase.CONFIRM;return RenewalMessage.delivery(request,next.encode());
            }
        }
        /** SECONDや保存の通知は見ず、実際に受けたFIRSTの正確な証明書を照合する。 */
        public boolean confirm(byte[] peer) {
            synchronized(GroupAdministration.this) {
                unchanged();if(phase!=Phase.REISSUE&&phase!=Phase.CONFIRM||expired())throw invalid();
                String key=name(peer);var next=issued.get(key);var first=sessions.authenticatedFirstCertificate(peer);
                if(next==null||first==null||!Arrays.equals(next.encode(),first.encode()))return false;
                directory.authenticatedFirst(sessions,peer);confirmed.add(key);phase=Phase.CONFIRM;return true;
            }
        }
        public boolean expired() {
            synchronized(GroupAdministration.this) {
                if(saved||phase==Phase.COMPLETE||phase==Phase.PUBLISH)return false;
                long now=nanos.getAsLong();boolean expired=phase!=Phase.PREPARE&&(now<confirmBegan||now-confirmBegan>=ProofRequests.TIMEOUT_NANOS);
                if(expired){phase=Phase.CANCELLED;requests.close();}return expired;
            }
        }
        public Candidate commit() {
            synchronized(GroupAdministration.this) {
                unchanged();if(invitation||phase!=Phase.REISSUE&&phase!=Phase.CONFIRM||expired()||incomplete()!=0)throw invalid();
                var kept=new ArrayList<AdminBinding>();for(var b:bindings())if(!removes(b.administratorKey()))kept.add(b);
                state.verifyCertificate(certificate,certificate.field(1));if(removes(certificate.signer()))throw invalid();
                for(var b:kept)if(!Crypto.equal(b.memberId(),member)) {
                    var entry=directory.get(b.memberId());if(entry==null||removes(entry.certificate().signer()))throw invalid();state.verifyCertificate(entry.certificate(),entry.handshakeKey());
                }
                phase=Phase.COMMIT;var candidate=withBindings(kept,null,null);candidate.preparation=this;return candidate;
            }
        }
        private void beforeCommit() {
            unchanged();if(phase!=Phase.COMMIT||expired()||incomplete()!=0)throw invalid();
            state.verifyCertificate(certificate,certificate.field(1));if(removes(certificate.signer()))throw invalid();
            for(var key:confirmed) {
                var entry=directory.get(peers.get(key));var expected=issued.get(key);var first=sessions.authenticatedFirstCertificate(peers.get(key));
                if(entry==null||expected==null||first==null||!Arrays.equals(entry.certificate().encode(),expected.encode())||!Arrays.equals(first.encode(),expected.encode()))throw invalid();
                state.verifyCertificate(entry.certificate(),entry.handshakeKey());
            }
            for(var binding:bindings())if(!removes(binding.administratorKey())&&!Crypto.equal(binding.memberId(),member)) {
                var entry=directory.get(binding.memberId());if(entry==null||removes(entry.certificate().signer()))throw invalid();state.verifyCertificate(entry.certificate(),entry.handshakeKey());
            }
        }
        public void publish(Candidate candidate,Saver saver,Publisher publisher) {
            synchronized(GroupAdministration.this) {
                unchanged();if(phase!=Phase.COMMIT||candidate.owner!=GroupAdministration.this)throw invalid();
                // 保存の印と COMPLETE への移行は persist が行う。直接 persist に渡しても同じ結果になる。 / persist sets the saved mark and moves to COMPLETE, so a direct persist call gives the same result.
                persist(candidate,saver,publisher);
            }
        }
        // persist が保存と公開に成功したあとに呼ぶ。persist の同期の中で呼ばれる。 / Called by persist after save and publish succeeded, inside persist's synchronization.
        private void completed(){phase=Phase.COMPLETE;requests.close();}
        public void cancel(){synchronized(GroupAdministration.this){if(saved||phase==Phase.COMPLETE||phase==Phase.PUBLISH)return;phase=Phase.CANCELLED;requests.close();provenRequests.clear();}}
        @Override public String toString(){return "Administration preparation";}
    }
    private byte[] bindingStamp() {
        var bytes=new java.io.ByteArrayOutputStream();byte[] list=state.administrators().encode();bytes.write(list,0,list.length);for(var binding:bindings()){byte[] value=binding.encode();bytes.write(value,0,value.length);}
        return Crypto.blake2s(bytes.toByteArray());
    }
    @Override public void close() {
        KeyRotationCoordinator old;
        synchronized(this){
            if(closed)return;closed=true;old=rotations;
            incomingProofs.close();if(acceptedDelivery!=null){acceptedDelivery.close();acceptedDelivery=null;}for(var p:pending.values())p.close();pending.clear();directory.clear();
            Crypto.wipe(administratorSecret);administratorSecret=null;Crypto.wipe(legacyAdministratorIdentity);legacyAdministratorIdentity=null;Crypto.wipe(identitySecret);Crypto.wipe(handshakeSecret);
        }
        if(old!=null)old.close();
    }
    @Override public String toString(){return "Group administration";}
}
