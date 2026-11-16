// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.function.LongConsumer;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;

/** 通信を持たないグループの管理状態。保存の成功後にだけ手元の状態を進める。 */
public final class AdminState {
    /** 検査結果の不正だけに使い、材料の不足や予想外の例外とは区別する。 */
    private static final class CertificateInvalidException extends SecurityException {
        CertificateInvalidException(String message) { super(message); }
    }
    /** 署名は正しいが、前の版の管理者の一覧と鎖がつながらない。 */
    public static final class ChainDisconnectedException extends SecurityException {
        public ChainDisconnectedException() { super("署名者が前の版の管理者に含まれておらず、鎖が切れています"); }
    }
    private final byte[] group,urlAdmin;
    private final Clock clock;
    private final AdminRecordStore store;
    private TreeMap<Long,AdminRecords.Record> chain=new TreeMap<>();
    private byte[] anchorSignature;
    private AdminRecords.Record revocations;
    private KeyAnnouncement announcement;
    private List<byte[]> journal=new ArrayList<>();
    private java.util.SortedSet<byte[]> revokedSubjects=new java.util.TreeSet<>(AdminRecords::compareBytes);
    private PreparedPersistence pendingPersistence;
    public AdminState(byte[] group, byte[] urlAdmin, Clock clock, AdminRecordStore store) {
        Crypto.length(group,32);Crypto.length(urlAdmin,32);
        this.group=group.clone();this.urlAdmin=urlAdmin.clone();this.clock=java.util.Objects.requireNonNull(clock);
        this.store=java.util.Objects.requireNonNull(store);
    }
    public static final class ClockFailure extends SecurityException {ClockFailure(){super("一覧の署名の時刻が先すぎます");}}
    private void checkFuture(AdminRecords.Record r) {
        long now=clock.millis();
        if(now<0 || r.signedAt()>now && r.signedAt()-now>300_000) throw new ClockFailure();
    }
    public synchronized AdminRecords.Record administrators() {
        if(chain.isEmpty()) throw new IllegalStateException("管理者の一覧がありません");return chain.lastEntry().getValue();
    }
    /**
     * 起点は招待で確かめた通信から受けたものを渡す。
     * URL を別のグループへ流用しないよう、group は呼び出し元が信頼して渡す。
     */
    public synchronized void bootstrap(AdminRecords.Record first, byte[] attachedSignature) {
        if(!chain.isEmpty()) throw new IllegalStateException("起点は設定済みです");
        checkFuture(first);
        if(first.kind()!=ADMINS || !Crypto.equal(group,first.group()) || !first.hasEntry(urlAdmin)
                || !Crypto.verify(urlAdmin,AdminRecords.anchorMessage(first),attachedSignature)) throw new SecurityException("最初の一覧の添えた署名が違います");
        // 元の署名者がこの版で外されていても、URL 管理者の添えた署名が起点を認証する。
        if(!first.hasValidSignature()) throw new SecurityException("起点の元の署名が違います");
        var next=new TreeMap<Long,AdminRecords.Record>();next.put(first.version(),first);
        List<byte[]> events=List.of(first.encode());
        save(events,next,attachedSignature,null);chain=next;anchorSignature=attachedSignature.clone();journal=new ArrayList<>(events);
    }
    /**
     * 抜けた最初の版を知らせる。記録は保留せず、鎖が届いてから呼び出し元が再送する。
     * missingVersion は確かめていない候補にもとづく知らせで、通信の許可ではない。
     */
    public synchronized boolean acceptAdministrators(AdminRecords.Record candidate, LongConsumer missingVersion) {
        return acceptAdministrators(candidate,missingVersion,false);
    }
    private boolean acceptAdministrators(AdminRecords.Record candidate,LongConsumer missingVersion,boolean history) {
        var current=administrators();
        if(candidate.kind()!=ADMINS || !Crypto.equal(group,candidate.group())) throw new SecurityException("一覧の種類かグループが違います");
        if(candidate.format()==1&&!history)return trustedLegacyList(candidate);
        if(candidate.format()<current.format())throw new SecurityException("一覧の形式を戻せません");
        checkFuture(candidate);
        if(candidate.version()<current.version()) return false;
        if(candidate.version()>current.version() && candidate.version()-current.version()>1) {
            missingVersion.accept(Math.addExact(current.version(),1));return false;
        }
        if(candidate.version()==current.version() && AdminRecords.compare(candidate,current)<=0) return false;
        checkChain(candidate,history);
        var next=new TreeMap<>(chain);next.put(candidate.version(),candidate);
        List<byte[]> events=append(candidate);
        save(events,next,anchorSignature,revocations);chain=next;journal=events;return true;
    }
    /**
     * 候補の一覧が、手元の信頼済みの鎖（直前の版）からつながるかを調べる。状態は変えない。
     * <p>
     * Checks that the candidate list continues from the trusted chain held here (the directly preceding version). State is not changed.
     */
    private void checkChain(AdminRecords.Record candidate,boolean history) {
        var previous=chain.lowerEntry(candidate.version());
        if(previous==null) throw new SecurityException("起点の差し替えには URL の管理者の添えた署名が必要です");
        candidate.verifySignature(ADMINS,group);
        for(var binding:candidate.bindings()) {
            if(!history&&!previous.getValue().hasEntry(binding.administratorKey())&&binding.state()!=AdminBinding.State.BOUND)
                throw new SecurityException("新しい管理者には所持証明が必要です");
            for(var trusted:chain.values()) {
                var old=trusted.binding(binding.administratorKey());
                if(old!=null&&old.state()==AdminBinding.State.BOUND&&(binding.state()!=AdminBinding.State.BOUND||!Crypto.equal(old.memberId(),binding.memberId())))
                    throw new SecurityException("検証済みの管理者の身元を変えられません");
            }
        }
        if(!previous.getValue().hasEntry(candidate.signer())) throw new ChainDisconnectedException();
    }
    /**
     * 信頼済みの鎖にある、指定の版の管理者の一覧。持っていなければ null。
     * <p>
     * The administrator list of the given version in the trusted chain, or null when it is not held.
     */
    public synchronized AdminRecords.Record administratorsAt(long version) { return chain.get(version); }
    /**
     * 候補が今の最新の版と同じ版か、その次の版で、直前の信頼済みの版から鎖がつながるか。状態も保存も変えない。
     * 管理用 DHT 記録の検査（04 §4.5）が、鎖の規則をもう一度書かずに使う。
     * <p>
     * Whether the candidate has the latest version or the next one and chains from the directly preceding trusted version.
     * Neither state nor storage is changed. The managed DHT record check (04 §4.5) uses this instead of rewriting the chain rules.
     */
    public synchronized boolean continuesChain(AdminRecords.Record candidate) {
        try {
            var current=administrators();
            if(candidate.kind()!=ADMINS||!Crypto.equal(group,candidate.group())||candidate.format()!=2) return false;
            checkFuture(candidate);
            if(candidate.version()>current.version()+1||candidate.version()<current.version()) return false;
            checkChain(candidate,false);return true;
        } catch(RuntimeException notChained) { return false; }
    }
    private boolean trustedLegacyList(AdminRecords.Record candidate) {
        for(byte[] trusted:journal)if(java.util.Arrays.equals(trusted,candidate.encode()))return false;
        throw new SecurityException("新しい一覧には形式2が必要です");
    }
    public synchronized boolean acceptRevocations(AdminRecords.Record candidate) {
        return acceptRevocations(candidate,false);
    }
    private boolean acceptRevocations(AdminRecords.Record candidate,boolean history) {
        if(candidate.format()==1&&!history)return trustedLegacyList(candidate);
        if(revocations!=null&&candidate.format()<revocations.format())throw new SecurityException("失効の一覧の形式を戻せません");
        var administrators=administrators();candidate.verify(REVOCATIONS,group,administrators);checkFuture(candidate);
        boolean winner=revocations==null || (administrators.hasEntry(revocations.signer()) || candidate.version()>revocations.version())
                && AdminRecords.compare(candidate,revocations)>0;
        var subjects=new java.util.TreeSet<byte[]>(AdminRecords::compareBytes);subjects.addAll(revokedSubjects);
        subjects.addAll(candidate.entries());
        if(subjects.size()>AdminRecords.MAX_ENTRIES)throw new AdminRecords.RevocationLimitException();
        if(!winner&&subjects.size()==revokedSubjects.size())return false;
        List<byte[]> events=append(candidate);
        var next=winner?candidate:revocations;
        save(events,chain,anchorSignature,next);revocations=next;journal=events;revokedSubjects=subjects;return true;
    }
    /**
     * 当時の権限で検証して受理した失効の和を返す。
     * <p>
     * Returns the union of revocations accepted under the authority valid at receipt.
     */
    public synchronized List<byte[]> revokedSubjects(){
        var result=new ArrayList<byte[]>();for(byte[] subject:revokedSubjects)result.add(subject.clone());return List.copyOf(result);
    }
    /**
     * 勝者の一覧とは別に、受理済みの失効の和を調べる。
     * <p>
     * Queries accepted revocations independently of the winning list.
     */
    synchronized boolean isRevoked(byte[] subject){return revokedSubjects.contains(subject);}
    public synchronized KeyAnnouncement announcement(){return announcement;}
    /**
     * 告知の現在の権限と参照本体を検査する。
     * <p>
     * Checks the current authority and referenced bodies of an announcement.
     */
    public synchronized void verifyAnnouncement(KeyAnnouncement value,AdminRecords.Record body){
        var admins=administrators();value.verify(group,admins.entries());body.verify(REVOCATIONS,group,admins);checkFuture(body);
        long now=clock.millis();
        if(value.signedAt()>now&&value.signedAt()-now>300_000||value.adminVersion()!=admins.version()
                ||!Crypto.equal(value.adminDigest(),Crypto.blake2s(admins.signedBytes()))
                ||value.revocationVersion()!=body.version()||!Crypto.equal(value.revocationDigest(),Crypto.blake2s(body.signedBytes())))
            throw new SecurityException("Announcement references differ");
    }
    public synchronized boolean coversRevocations(AdminRecords.Record body){
        for(byte[] subject:revokedSubjects)if(!body.hasEntry(subject))return false;return true;
    }
    /**
     * 鍵に一致する告知だけを保存候補へ結ぶ。同版では順位と鍵を戻さない。
     * <p>
     * Binds only a matching announcement to the saved candidate. Neither rank nor key regresses at the same version.
     */
    synchronized void recordGroupKey(KeyAnnouncement value,byte[] key,long version){
        requireWritable();checkGroupKeyCandidate(value,key,version);
        var next=new AdminRecordStore.Snapshot(journal,anchorSignature,revocations.encode(),chain.lastKey(),revocations.version(),value.encode());
        store.save(next);announcement=value;
    }
    /**
     * 保存済みの告知を、保存済みの鍵そのものと照合する。告知のない旧保存も読める。
     * <p>
     * Checks the saved announcement against the saved key itself. Legacy snapshots without announcements remain readable.
     */
    public synchronized void checkRestoredGroupKey(byte[] key,long version){
        if(announcement!=null)announcement.checkKey(group,version,key,announcement);
    }
    /**
     * 現在の権限と失効の和を検証し、保存する前に鍵と告知の一致を調べる。状態は変えない。
     * <p>
     * Verifies current authority and the revocation union, then checks the key and announcement before saving without changing state.
     */
    public synchronized void checkGroupKeyCandidate(KeyAnnouncement value,byte[] key,long version){
        verifyAnnouncement(value,revocations());
        if(!coversRevocations(revocations()))throw new SecurityException("Revocations omit accepted subjects");
        value.checkKey(group,version,key,announcement);
    }
    /** この1か所で、失効一覧が使える状態かを判定する。 */
    public synchronized AdminRecords.Record revocations() {
        if(revocations==null) throw new SecurityException("有効な失効の一覧がありません");
        // 答え140: 受けたとき有効だった中身は、署名者を外しても残す。
        return revocations;
    }
    public synchronized void verifyCertificate(AdminRecords.Record certificate, byte[] peerHandshake) {
        verifyCertificateCached(certificate,peerHandshake,new CertificateChecks());
    }
    /** 期限だけを緩める保存読み戻し用。ほかの検査は通常と同じ。 */
    public synchronized void verifyCertificate(AdminRecords.Record certificate,byte[] peerHandshake,boolean allowExpired) {
        var reason=localCertificateReason(certificate,peerHandshake);
        if(reason!=UdpEndpoint.CloseReason.RUNNING && !(allowExpired && reason==UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED))
            throw new SecurityException("証明書を受け入れられません");
    }
    // 版5から読んだ正確な証明書だけを許す。ネットワーク入力からは追加しない。
    private final java.util.Map<String,java.util.List<byte[]>> legacyCertificates=new java.util.HashMap<>();
    private static String identityName(byte[] identity){return java.util.Base64.getEncoder().encodeToString(identity);}
    public synchronized void trustStoredLegacyCertificate(AdminRecords.Record certificate) {
        if(certificate.format()!=1)return;
        if(certificate.kind()!=CERTIFICATE||!Crypto.equal(group,certificate.group())||!certificate.hasValidSignature()
                ||!certificate.verifyIdentityBinding()||!administrators().hasEntry(certificate.signer()))
            throw new SecurityException("保存した旧証明書が無効です");
        var values=legacyCertificates.computeIfAbsent(identityName(certificate.field(0)),ignored->new java.util.ArrayList<>());
        byte[] encoded=certificate.encode();if(values.stream().noneMatch(value->java.util.Arrays.equals(value,encoded)))values.add(encoded);
    }
    /** 入り直し候補へ、前の保存で許可済みの正確な証明書だけを引き継ぐ。 */
    public void inheritStoredLegacyCertificate(AdminState previous,AdminRecords.Record certificate) {
        if(certificate.format()!=1)return;
        synchronized(previous) {
            if(!previous.permitsLegacy(certificate))throw new SecurityException("保存にない旧証明書は引き継げません");
        }
        trustStoredLegacyCertificate(certificate);
    }
    private boolean permitsLegacy(AdminRecords.Record certificate){
        var values=legacyCertificates.get(identityName(certificate.field(0)));
        if(values!=null)for(byte[] value:values)if(java.util.Arrays.equals(value,certificate.encode()))return true;
        return false;
    }
    /**
     * 正確な旧許可を履歴の管理者権限と照合して一括復元する。
     * <p>
     * Atomically restores exact legacy permissions after checking historical administrator authority.
     */
    public synchronized void restoreStoredLegacyCertificates(java.util.List<byte[]> encoded){
        var records=new java.util.ArrayList<AdminRecords.Record>();
        for(byte[] bytes:encoded){var certificate=AdminRecords.decode(bytes);if(certificate.format()!=1)throw new SecurityException("旧許可の形式が違います");
            verifyStoredCertificateEvidence(certificate,false);records.add(certificate);}
        for(var certificate:records){var values=legacyCertificates.computeIfAbsent(identityName(certificate.field(0)),ignored->new java.util.ArrayList<>());
            byte[] bytes=certificate.encode();if(values.stream().noneMatch(value->java.util.Arrays.equals(value,bytes)))values.add(bytes);}
    }
    /**
     * 保存名簿の署名根拠だけを検査する。期限切れ・失効済みの項目から通信権限を作らない。
     * <p>
     * Verifies only signature evidence for a saved roster, granting no communication rights to expired or revoked entries.
     */
    public synchronized void verifyStoredCertificateEvidence(AdminRecords.Record certificate){verifyStoredCertificateEvidence(certificate,true);}
    private void verifyStoredCertificateEvidence(AdminRecords.Record certificate,boolean requirePermission){
        if(certificate.kind()!=CERTIFICATE||!Crypto.equal(group,certificate.group())||!certificate.hasValidSignature()||!certificate.verifyIdentityBinding()
                ||requirePermission&&certificate.format()==1&&!permitsLegacy(certificate))throw new SecurityException("保存証明書の根拠が違います");
        boolean authorized=false;for(byte[] encoded:journal){var record=AdminRecords.decode(encoded);
            if(record.kind()==ADMINS&&record.hasEntry(certificate.signer())){authorized=true;break;}}
        if(!authorized)throw new SecurityException("保存証明書の管理者根拠がありません");
    }
    /**
     * 正確な旧許可の防御的な写しを返す。
     * <p>
     * Returns defensive copies of exact legacy permissions.
     */
    public synchronized java.util.List<byte[]> storedLegacyCertificates(){
        var result=new java.util.ArrayList<byte[]>();
        new java.util.TreeMap<>(legacyCertificates).values().forEach(values->{for(byte[] value:values)result.add(value.clone());});
        return java.util.List.copyOf(result);
    }
    public synchronized void forgetLegacyCertificate(byte[] identity){legacyCertificates.remove(identityName(identity));}
    /** SessionManagerの作成前に呼ぶ。更新不要ならnull。保存は呼び出し元が行う。 */
    public synchronized AdminRecords.Record renewOwnCertificate(AdminRecords.Record certificate,byte[] handshakeSecret,byte[] identitySecret,byte[] administratorSecret) {
        byte[] handshake=Crypto.x25519Public(handshakeSecret),identity=Crypto.ed25519Public(identitySecret);
        verifyCertificate(certificate,handshake,true);
        if(!Crypto.equal(identity,certificate.field(0)) || !administrators().hasEntry(Crypto.ed25519Public(administratorSecret)))
            throw new SecurityException("自分の証明書を更新できません");
        long now=clock.millis();
        if(now<certificate.expiresAt() && certificate.expiresAt()-now>(certificate.expiresAt()-certificate.issuedAt())/3) return null;
        if(now<=certificate.issuedAt()) throw new SecurityException("自分の証明書を更新できません");
        return AdminRecords.certificate(group,identity,handshake,SignaturePurpose.identityProof(identitySecret,group,handshake),now,administratorSecret);
    }
    /** 管理者だけが呼ぶ発行前の検査。証明をコピーするのは形式2で検証できたときだけ。 */
    public synchronized AdminRecords.Record issueCertificateRenewal(AdminRecords.Record base,byte[] proof,byte[] administratorSecret,
            RenewalMessage.Reason reason,byte[] managementOperation) {
        verifyCertificate(base,base.field(1));
        if(!administrators().hasEntry(Crypto.ed25519Public(administratorSecret)))throw new SecurityException("管理者ではありません");
        if(reason==RenewalMessage.Reason.AUTO_RENEWAL){if(managementOperation!=null)throw new SecurityException("余分な管理操作です");}
        else if(reason==RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE||reason==RenewalMessage.Reason.INVITATION_PREPARE)Crypto.length(managementOperation,16);
        else throw new SecurityException("未対応の更新理由です");
        if(reason==RenewalMessage.Reason.INVITATION_PREPARE&&base.format()!=1)throw new SecurityException("招待の更新は形式1だけです");
        long now=clock.millis();
        if(now<=base.issuedAt()||reason==RenewalMessage.Reason.AUTO_RENEWAL&&!ProofRequests.due(base,now))throw new SecurityException("更新の時期ではありません");
        if(!SignaturePurpose.verifyIdentity(group,base.field(0),base.field(1),proof))throw new SecurityException("形式2の本人証明が違います");
        return AdminRecords.certificate(group,base.field(0),base.field(1),proof,now,administratorSecret);
    }
    /** 有効ならRUNNING。失効や署名・結びつきの不正は、時計や期限切れより先に判定する。 */
    public synchronized UdpEndpoint.CloseReason localCertificateReason(AdminRecords.Record certificate,byte[] localHandshake) {
        return localCertificateReason(certificate,localHandshake,new CertificateChecks());
    }
    synchronized UdpEndpoint.CloseReason localCertificateReason(AdminRecords.Record certificate,byte[] localHandshake,CertificateChecks cache) {
        try { verifyCertificateStructure(certificate,localHandshake,cache); }
        catch(CertificateInvalidException e) { return UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_INVALID; }
        catch(RuntimeException e) { return UdpEndpoint.CloseReason.INTERNAL_FAILURE; }
        long now;
        try { now=clock.millis(); }
        catch(RuntimeException e) { return UdpEndpoint.CloseReason.CLOCK_FAILURE; }
        if(now<0 || certificate.issuedAt()>now && certificate.issuedAt()-now>300_000)
            return UdpEndpoint.CloseReason.CLOCK_FAILURE;
        return now>=certificate.expiresAt() ? UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED : UdpEndpoint.CloseReason.RUNNING;
    }
    public enum StoredCertificateStatus { VALID, EXPIRED, REVOKED, CLOCK_FAILURE }
    /** 保存の復旧用。形・署名・結びつきは通常どおり検査し、運用上の状態だけを分ける。 */
    public synchronized StoredCertificateStatus storedCertificateStatus(AdminRecords.Record certificate,byte[] handshake) {
        verifyCertificateStructure(certificate,handshake,new CertificateChecks(),true);
        if(revokedSubjects.contains(Crypto.blake2s(certificate.field(0))))return StoredCertificateStatus.REVOKED;
        long now;
        try{now=clock.millis();}catch(RuntimeException failure){return StoredCertificateStatus.CLOCK_FAILURE;}
        if(now<0||certificate.issuedAt()>now&&certificate.issuedAt()-now>300_000)return StoredCertificateStatus.CLOCK_FAILURE;
        return now>=certificate.expiresAt()?StoredCertificateStatus.EXPIRED:StoredCertificateStatus.VALID;
    }
    /** SessionManagerの各相手と自分に1つずつ置く。参照を版やハッシュで代用しない。 */
    static final class CertificateChecks {
        private AdminRecords.Record certificate,administrators,revocations;
        private boolean recordSignature,identitySignature;
        long checks;
    }
    synchronized void verifyCertificateCached(AdminRecords.Record certificate,byte[] peerHandshake,CertificateChecks cache) {
        var reason=localCertificateReason(certificate,peerHandshake,cache);
        if(reason!=UdpEndpoint.CloseReason.RUNNING) throw new SecurityException("証明書を受け入れられません");
    }
    private void verifyCertificateStructure(AdminRecords.Record certificate,byte[] peerHandshake,CertificateChecks cache) {
        verifyCertificateStructure(certificate,peerHandshake,cache,false);
    }
    private void verifyCertificateStructure(AdminRecords.Record certificate,byte[] peerHandshake,CertificateChecks cache,boolean recovery) {
        java.util.Objects.requireNonNull(certificate);java.util.Objects.requireNonNull(peerHandshake);java.util.Objects.requireNonNull(cache);
        var administrators=administrators();
        var revoked=revocations();
        if(certificate.format()==1&&!permitsLegacy(certificate))
            throw new CertificateInvalidException("保存に固定されていない旧証明書です");
        if(certificate.kind()!=CERTIFICATE || !Crypto.equal(certificate.group(),group))
            throw new IllegalArgumentException("管理記録の種類か宛先が違います");
        if(cache.certificate!=certificate || cache.administrators!=administrators || cache.revocations!=revocations) {
            // 動的な失敗（失効・期限など）でも、同じ署名を次のrefreshで計算し直さない。
            cache.recordSignature=certificate.hasValidSignature();
            cache.identitySignature=certificate.verifyIdentityBinding();
            cache.certificate=certificate;cache.administrators=administrators;cache.revocations=revocations;cache.checks++;
        }
        if(!cache.recordSignature) throw new CertificateInvalidException("管理記録の署名か宛先が違います");
        if(!administrators.hasEntry(certificate.signer())) throw new CertificateInvalidException("署名者が今の管理者に含まれていません");
        byte[] identity=certificate.field(0),handshake=certificate.field(1);
        if(!recovery&&revokedSubjects.contains(Crypto.blake2s(identity))) throw new CertificateInvalidException("メンバーは失効しています");
        if(!Crypto.equal(handshake,peerHandshake)) throw new CertificateInvalidException("相手の握手の鍵が違います");
        if(!cache.identitySignature) throw new CertificateInvalidException("身元の鍵の署名が違います");
    }
    /** currentVersion は信頼できる手元の現在版。-1 はグループの鍵を1度も持っていないときだけ渡す。 */
    public synchronized GroupKeyEnvelope.OpenedKey openGroupKey(AdminRecords.Record record, byte[] recipient, byte[] handshakeSecret, long currentVersion) {
        record.verify(WRAPPED_KEY,group,administrators());
        return GroupKeyEnvelope.open(record,recipient,handshakeSecret,currentVersion);
    }
    /** 入り直しの全体の照合を終えた呼び出し元だけが使う。同じ鍵の版も受け入れる。 */
    synchronized GroupKeyEnvelope.OpenedKey openRejoinedGroupKey(AdminRecords.Record record,byte[] recipient,byte[] handshakeSecret,long currentVersion) {
        record.verify(WRAPPED_KEY,group,administrators());
        return GroupKeyEnvelope.open(record,recipient,handshakeSecret,currentVersion,true);
    }
    /**
     * 自分の変更を最新の一覧へ足す。自動で出すきっかけは上位の責務。
     * previous は自分が変更を作ったときの信頼済みの一覧を渡す。この口では previous の署名を確かめない。
     * @throws AdminRecords.RevocationLimitException 失効を足した結果が65536件を超えるとき。古い失効は捨てない。
     */
    public synchronized AdminRecords.Record reissue(AdminRecords.Record previous, AdminRecords.Record own, byte[] mySecret) {
        var base=own.kind()==ADMINS ? administrators() : own.kind()==REVOCATIONS ? revocations() : null;
        byte[] me=Crypto.ed25519Public(mySecret);
        if(base==null || !administrators().hasEntry(me) || !Crypto.equal(own.signer(),me)
                || previous.kind()!=own.kind() || !Crypto.equal(previous.group(),group) || !Crypto.equal(own.group(),group)
                || previous.version()==Long.MAX_VALUE || own.version()!=previous.version()+1 || base.version()<own.version())
            throw new SecurityException("一覧を出し直せる条件を満たしていません");
        own.verify(own.kind(),group,List.of(me));
        return AdminRecords.reissueList(base,previous,own,clock.millis(),mySecret);
    }
    private List<byte[]> append(AdminRecords.Record record) {
        List<byte[]> events=new ArrayList<>(journal);events.add(record.encode());return events;
    }
    private void save(List<byte[]> events, TreeMap<Long,AdminRecords.Record> records, byte[] anchor, AdminRecords.Record revoked) {
        requireWritable();
        store.save(new AdminRecordStore.Snapshot(events,anchor,revoked==null ? null : revoked.encode(),records.lastKey(),revoked==null ? -1 : revoked.version(),announcement==null?null:announcement.encode()));
    }
    /**
     * 入り直しの返事の鎖と失効一覧を、全体の検査が済んでから一度に採用する。
     * 起点は招待で確かめた通信から受けたものを渡す。
     */
    public synchronized void join(List<AdminRecords.Record> history, byte[] attachedSignature, AdminRecords.Record revoked) {
        if(!chain.isEmpty()) throw new IllegalStateException("管理状態は設定済みです");
        if(history.isEmpty()) throw new SecurityException("入り直しの鎖が空です");
        var checked=new AdminState(group,urlAdmin,clock,new InMemoryAdminRecordStore());
        checked.bootstrap(history.get(0),attachedSignature);
        for(int i=1;i<history.size();i++) {
            if(history.get(i).version()!=Math.addExact(checked.administrators().version(),1)
                    || !checked.acceptAdministrators(history.get(i),v->{throw new SecurityException("入り直しの鎖が切れています");},true))
                throw new SecurityException("入り直しの鎖の順が違います");
        }
        checked.acceptRevocations(revoked,true);
        save(checked.journal,checked.chain,checked.anchorSignature,checked.revocations);
        chain=checked.chain;anchorSignature=checked.anchorSignature;revocations=checked.revocations;journal=checked.journal;revokedSubjects=checked.revokedSubjects;
    }
    /** 完全に確かめてから状態を置き換える。読み戻した記録を検査せず採用しない。 */
    public synchronized void restore() {
        requireWritable();
        if(!chain.isEmpty()) throw new IllegalStateException("起動後の読み戻しは1度だけです");
        var snapshot=store.load();if(snapshot==null) return;
        try {
            if(snapshot.records().isEmpty()) throw new SecurityException("保存した鎖が空です");
            var checked=new AdminState(group,urlAdmin,clock,new InMemoryAdminRecordStore());
            List<byte[]> history=snapshot.records();
            checked.bootstrap(AdminRecords.decode(history.get(0)),snapshot.anchorSignature());
            for(int i=1;i<history.size();i++) {
                var candidate=AdminRecords.decode(history.get(i));
                boolean accepted=candidate.kind()==REVOCATIONS ? checked.acceptRevocations(candidate,true)
                    : checked.acceptAdministrators(candidate,v->{throw new SecurityException("保存した鎖が切れています");},true);
                if(!accepted)
                    throw new SecurityException("保存した鎖の版が違います");
            }
            if(checked.administrators().version()!=snapshot.administratorVersion()
                    || (checked.revocations==null ? -1 : checked.revocations.version())!=snapshot.revocationVersion()
                    || !java.util.Arrays.equals(snapshot.revocations(),checked.revocations==null ? null : checked.revocations.encode()))
                throw new SecurityException("保存した版が一致しません");
            KeyAnnouncement savedAnnouncement=snapshot.announcement()==null?null:KeyAnnouncement.decode(snapshot.announcement());
            if(savedAnnouncement!=null)checked.verifyStoredAnnouncement(savedAnnouncement);
            chain=checked.chain;anchorSignature=checked.anchorSignature;revocations=checked.revocations;journal=checked.journal;revokedSubjects=checked.revokedSubjects;announcement=savedAnnouncement;
        } catch(IllegalArgumentException | ArithmeticException e) { throw new SecurityException("保存した管理記録を検証できません",e); }
    }
    private void verifyStoredAnnouncement(KeyAnnouncement value){
        AdminRecords.Record admins=null,body=null;
        for(byte[] raw:journal){
            var record=AdminRecords.decode(raw);
            if(record.kind()==ADMINS&&record.version()==value.adminVersion()&&Crypto.equal(Crypto.blake2s(record.signedBytes()),value.adminDigest()))admins=record;
            if(record.kind()==REVOCATIONS&&record.version()==value.revocationVersion()&&Crypto.equal(Crypto.blake2s(record.signedBytes()),value.revocationDigest()))body=record;
        }
        if(admins==null||body==null)throw new SecurityException("Saved announcement references are missing");
        value.verify(group,admins.entries());body.verify(REVOCATIONS,group,admins);
        long now=clock.millis();if(value.signedAt()>now&&value.signedAt()-now>300_000)throw new ClockFailure();
    }
    /** 検査済みの公開記録だけを保存用の写しとして返す。 */
    public synchronized AdminRecordStore.Snapshot snapshot() {
        if(chain.isEmpty())throw new IllegalStateException("管理者の一覧がありません");
        return new AdminRecordStore.Snapshot(journal,anchorSignature,revocations==null ? null : revocations.encode(),
                chain.lastKey(),revocations==null ? -1 : revocations.version(),announcement==null?null:announcement.encode());
    }
    /** 公開記録の候補の検証に使う。保存と現在の状態を変更しない。 */
    synchronized AdminState fork() {
        var memory=new InMemoryAdminRecordStore();memory.save(snapshot());
        var copy=new AdminState(group,urlAdmin,clock,memory);copy.restore();
        legacyCertificates.forEach((key,values)->{var entries=new ArrayList<byte[]>();for(byte[] value:values)entries.add(value.clone());copy.legacyCertificates.put(key,entries);});
        return copy;
    }
    static boolean sameSnapshot(AdminRecordStore.Snapshot a,AdminRecordStore.Snapshot b) {
        if(a.administratorVersion()!=b.administratorVersion()||a.revocationVersion()!=b.revocationVersion()
                ||!java.util.Arrays.equals(a.anchorSignature(),b.anchorSignature())||!java.util.Arrays.equals(a.revocations(),b.revocations())
                ||!java.util.Arrays.equals(a.announcement(),b.announcement()))return false;
        var x=a.records();var y=b.records();if(x.size()!=y.size())return false;
        for(int i=0;i<x.size();i++)if(!java.util.Arrays.equals(x.get(i),y.get(i)))return false;return true;
    }
    private void requireWritable(){
        if(pendingPersistence!=null)throw new IllegalStateException("Management persistence is reserved");
    }
    /**
     * 基準と候補を保存前に固定する。予約中の更新は待たせず断り、読み取りは止めない。
     * <p>
     * Fixes the base and candidate before persistence. Updates are refused during the reservation without blocking reads.
     */
    synchronized PreparedPersistence preparePersistence(AdminRecordStore.Snapshot expected,AdminState candidate){
        requireWritable();
        if(!sameSnapshot(snapshot(),expected))throw new SecurityException("候補の基準が変わりました");
        pendingPersistence=new PreparedPersistence(candidate);return pendingPersistence;
    }
    /**
     * 保存 I/O は管理状態のロックの外で実行し、確定後の公開には再検証や追加 I/O を要しない。
     * <p>
     * Runs persistence I/O outside the admin state lock; publishing after commit requires no revalidation or further I/O.
     */
    final class PreparedPersistence implements AutoCloseable {
        private final AdminRecordStore.Snapshot next;
        private final TreeMap<Long,AdminRecords.Record> nextChain;
        private final byte[] nextAnchor;
        private final AdminRecords.Record nextRevocations;
        private final List<byte[]> nextJournal;
        private final java.util.SortedSet<byte[]> nextSubjects;
        private final KeyAnnouncement nextAnnouncement;
        private boolean committed;
        private PreparedPersistence(AdminState candidate){
            next=candidate.snapshot();nextChain=new TreeMap<>(candidate.chain);nextAnchor=candidate.anchorSignature.clone();
            nextRevocations=candidate.revocations;nextJournal=new ArrayList<>(candidate.journal);
            nextSubjects=new java.util.TreeSet<>(AdminRecords::compareBytes);nextSubjects.addAll(candidate.revokedSubjects);
            nextAnnouncement=candidate.announcement;
        }
        void save(){store.save(next);committed=true;}
        void publish(){synchronized(AdminState.this){
            if(pendingPersistence!=this||!committed)throw new IllegalStateException("Persistence is not committed");
            chain=nextChain;anchorSignature=nextAnchor;revocations=nextRevocations;journal=nextJournal;revokedSubjects=nextSubjects;announcement=nextAnnouncement;
        }}
        public void close(){synchronized(AdminState.this){if(pendingPersistence==this)pendingPersistence=null;}}
    }
    /** callbackが成功し、基準が変わっていない候補だけを、一括で保存して適用する。 */
    synchronized void applyCandidate(AdminRecordStore.Snapshot expected,AdminState candidate,Runnable saved) {
        requireWritable();
        if(!sameSnapshot(snapshot(),expected))throw new SecurityException("候補の基準が変わりました");
        saved.run();
        if(!sameSnapshot(snapshot(),expected))throw new SecurityException("保存中に候補の基準が変わりました");
        var next=candidate.snapshot();store.save(next);
        chain=new TreeMap<>(candidate.chain);anchorSignature=candidate.anchorSignature.clone();
        revocations=candidate.revocations;journal=new ArrayList<>(candidate.journal);
        revokedSubjects=new java.util.TreeSet<>(AdminRecords::compareBytes);revokedSubjects.addAll(candidate.revokedSubjects);
        announcement=candidate.announcement;
    }
    /** 招待操作専用。形式1だけを更新し、同じミリ秒なら作らず待つ。 */
    public synchronized AdminRecords.Record prepareInvitationCertificate(AdminRecords.Record certificate,byte[] handshakeSecret,byte[] identitySecret,byte[] administratorSecret) {
        verifyCertificate(certificate,Crypto.x25519Public(handshakeSecret),true);
        if(!Crypto.equal(certificate.field(0),Crypto.ed25519Public(identitySecret))||!administrators().hasEntry(Crypto.ed25519Public(administratorSecret)))
            throw new SecurityException("招待を準備できません");
        if(certificate.format()==2)return null;
        long now=clock.millis();if(now<=certificate.issuedAt())return null;
        byte[] handshake=Crypto.x25519Public(handshakeSecret);
        return AdminRecords.certificate(group,certificate.field(0),handshake,SignaturePurpose.identityProof(identitySecret,group,handshake),now,administratorSecret);
    }
    public synchronized void clear() { requireWritable();store.clear();chain.clear();anchorSignature=null;revocations=null;announcement=null;journal.clear();revokedSubjects.clear();legacyCertificates.clear(); }
}
