// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import java.util.function.LongSupplier;
import org.bouncycastle.util.encoders.Hex;

/**
 * 相手ごとのメンバーセッション。ソケットとタイマーのスレッドは持たない。
 * 管理一覧を更新した直後に refresh、時間が進んだら poll を呼び、戻ったパケットを上位で渡す。
 * close 後は再利用しない。入り直した材料で新しい SessionManager を作る。
 * 照会も refresh を行い、期限や失効により相手または管理全体を閉じる場合がある。
 * 証明書の期限切れだけでは相手の台数の枠は空かない。
 * 同時開始は自分の握手中だけ公開鍵の順で選ぶ。成立後の新しい1通目には候補で答える。
 * 候補が最初の認証済みDATAで確かめられるまでは、成立済みの鍵で送受信を続ける。
 * 2通目の時刻では1通目を棄却せず、受けた1通目の再送防止の記録で新旧を比べる。
 */
public final class SessionManager implements AutoCloseable {
    public static final long RETRY_NANOS=Duration.ofSeconds(5).toNanos();
    public static final long ATTEMPT_NANOS=Duration.ofSeconds(90).toNanos();
    private static final long ROTATION_NANOS=Duration.ofSeconds(180).toNanos();
    private final AdminState admin;
    private final Clock clock;
    private final LongSupplier ticker;
    private final byte[] localSecret,localPublic,localId,group;
    private AdminRecords.Record localCertificate;
    private final AdminState.CertificateChecks localChecks=new AdminState.CertificateChecks();
    private byte[] psk;
    private long version;
    private final int maxPeers;
    private boolean storedSlotReserved;
    private java.util.function.Predicate<AdminRecords.Record> storedMatcher=c->false;
    private final Map<String,Peer> peers=new LinkedHashMap<>();
    private final Map<String,Peer> routes=new HashMap<>();
    /** 発見で見つけた、まだ証明書を確かめていない宛先への開始。peers には入れない（核 C1 必修 3）。 */
    private final Map<String,Unconfirmed> unconfirmed=new LinkedHashMap<>();
    private final Map<String,Unconfirmed> unconfirmedRoutes=new HashMap<>();
    /** 同時に開始できる未確認の宛先の数。 */
    public static final int MAX_UNCONFIRMED=8;
    private final TimestampReplayGuard replay=new TimestampReplayGuard();
    private final SecureRandom random=new SecureRandom();
    private Instant lastTimestamp;
    private boolean closed;
    /** ネットワークが変わるたびに増える数。VerifiedSession が作られたときの値を持つ（核 C1）。 */
    private long generation;
    private UdpEndpoint.CloseReason closeReason=UdpEndpoint.CloseReason.RUNNING;
    private long firstCalculations;
    private CorePersistenceCoordinator coordinator;

    /**
     * 調整層を一度だけ接続する。回復には、まだ通信していない新しい管理を使う。
     * <p>
     * Attaches the coordinator once. Recovery uses a fresh manager that has not communicated.
     */
    synchronized void coordinate(CorePersistenceCoordinator coordinator,boolean recovering){
        open();if(this.coordinator!=null||recovering&&(!routes.isEmpty()||!unconfirmed.isEmpty()))
            throw new IllegalStateException("Coordinator requires a fresh session manager");
        this.coordinator=coordinator;
    }
    private void requireHandshake(){if(coordinator!=null)coordinator.require(CorePersistenceCoordinator.Operation.HANDSHAKE);}
    private void requirePeer(byte[] id){if(coordinator!=null&&coordinator.isRevoked(id))throw new SecurityException("Peer is revoked");}
    synchronized long keyVersion(){return version;}
    synchronized boolean matchesLocalRecipient(byte[] recipient,byte[] handshake){return Crypto.equal(localId,recipient)&&Crypto.equal(localPublic,handshake);}
    synchronized boolean localRevoked(){return admin.isRevoked(localId);}
    synchronized void storageFailed(){close();}
    synchronized void rejectRevokedPeers(){
        for(var entry:peers.entrySet())if(coordinator!=null&&coordinator.isRevoked(identity(entry.getValue().certificate))){
            destroy(entry.getValue());entry.getValue().invalid=true;
        }
        for(var u:new ArrayList<>(unconfirmed.values()))if(coordinator!=null&&coordinator.isRevoked(u.nodeId))dropUnconfirmed(u);
    }

    private static final class Peer {
        AdminRecords.Record certificate,authenticatedFirst;
        byte[] renewal;
        final AdminState.CertificateChecks checks=new AdminState.CertificateChecks();
        Connection active,candidate;
        Pending pending;
        Attempt attempt;
        long rotationAt;
        boolean rotating,invalid,exhausted,restartScheduled;
        /** rememberPeer で入れた保存した相手か。入る握手で入った追加の相手は false（核 C1 手順 4）。 */
        boolean stored;
        /** この相手から認証を通った最後のパケット（握手の 1・2 通目・DATA）を受けた時刻（ticker の値）。満杯のとき一番古い揮発の相手を手放す目安。 */
        long lastAuthenticated;
        Peer(AdminRecords.Record certificate) { this.certificate=certificate; }
    }
    /** 発見で見つけた宛先。相手の番号と握手の鍵だけを知っている。2 通目の検査が全部通るまで Peer にしない。 */
    private static final class Unconfirmed {
        final byte[] nodeId,handshakeKey;
        Pending pending;
        Attempt attempt;
        Unconfirmed(byte[] nodeId,byte[] handshakeKey) { this.nodeId=nodeId.clone();this.handshakeKey=handshakeKey.clone(); }
    }
    /** 個々のNoiseの状態を作り直しても、この開始時刻と直前の1通目の時刻を引き継ぐ。 */
    private static final class Attempt {
        final long started;
        long lastFirst;
        boolean sent;
        Attempt(long now) { started=now; }
    }
    private static final class Connection implements AutoCloseable {
        final byte[] id;
        final long version,created;
        long lastSent;
        final NoiseTransport transport;
        final boolean initiator;
        final Duration offset;
        // 公開の握手だけを残す。重なった1通目への返事と、2通目への確認に使う。
        byte[] first,second;
        Connection(byte[] id,long version,long created,NoiseTransport transport,boolean initiator,Duration offset) {
            this.id=id.clone();this.version=version;this.created=created;lastSent=created;this.transport=transport;this.initiator=initiator;this.offset=offset;
        }
        public void close() { transport.close();first=null;second=null; }
    }
    private static final class Pending implements AutoCloseable {
        final byte[] id,first;
        final long version;
        final TimedHandshake handshake;
        Pending(byte[] id,byte[] first,long version,TimedHandshake handshake) {
            this.id=id.clone();this.first=first;this.version=version;this.handshake=handshake;
        }
        public void close() { handshake.close(); }
    }
    public record Outbound(byte[] peerId,byte[] packet) {
        public Outbound { peerId=peerId.clone();packet=packet.clone(); }
        @Override public byte[] peerId() { return peerId.clone(); }
        @Override public byte[] packet() { return packet.clone(); }
        @Override public String toString() { return "Outbound"; }
    }
    /**
     * plaintextはDATAのときだけ。空のDATAは鍵の確認にも使う。closeで所有する写しを消去する。
     * <p>
     * Plaintext exists only for DATA; empty DATA also confirms keys. Close wipes owned copies.
     */
    public record Received(byte[] peerId,byte[] plaintext,List<Outbound> outbound,byte[] sessionId) implements AutoCloseable {
        public Received(byte[] peerId,byte[] plaintext,List<Outbound> outbound){this(peerId,plaintext,outbound,new byte[0]);}
        public Received { peerId=peerId.clone();plaintext=plaintext==null ? null : plaintext.clone();outbound=List.copyOf(outbound);sessionId=sessionId.clone(); }
        @Override public byte[] peerId() { return peerId.clone(); }
        @Override public byte[] plaintext() { return plaintext==null ? null : plaintext.clone(); }
        @Override public byte[] sessionId() { return sessionId.clone(); }
        @Override public void close(){Crypto.wipe(plaintext);Crypto.wipe(peerId);Crypto.wipe(sessionId);}
        @Override public String toString() { return "Received"; }
    }
    /** plaintextSent が false なら中身は送らず預からない。outbound だけを相手に渡す。 */
    public record SendResult(boolean plaintextSent,List<Outbound> outbound) {
        public SendResult { outbound=List.copyOf(outbound); }
    }
    /** groupSize は自分を含めた上限（2〜65536）。通常は256。 */
    public SessionManager(AdminState admin,AdminRecords.Record localCertificate,byte[] localSecret,byte[] groupKey,
                          long groupKeyVersion,Clock clock,LongSupplier monotonicNanos,int groupSize) {
        Crypto.length(localSecret,32);Crypto.length(groupKey,32);
        admin.checkRestoredGroupKey(groupKey,groupKeyVersion);
        if(groupKeyVersion<0 || groupSize<2 || groupSize>65536) throw new IllegalArgumentException("鍵の版か台数の上限が違います");
        this.admin=Objects.requireNonNull(admin);this.clock=Objects.requireNonNull(clock);ticker=Objects.requireNonNull(monotonicNanos);
        localPublic=Crypto.x25519Public(localSecret);admin.verifyCertificate(localCertificate,localPublic);
        group=localCertificate.group();localId=Crypto.blake2s(localCertificate.field(0));
        this.localCertificate=localCertificate;this.localSecret=localSecret.clone();psk=groupKey.clone();version=groupKeyVersion;maxPeers=groupSize-1;
        if(localCertificate.format()==2)admin.forgetLegacyCertificate(localCertificate.field(0));
    }
    private static String key(byte[] bytes) { return Hex.toHexString(bytes); }
    private static byte[] identity(AdminRecords.Record cert) { return Crypto.blake2s(cert.field(0)); }
    private void open() { if(closed) throw new IllegalStateException("セッションの管理は閉じています"); }
    private Peer peer(byte[] id) {
        Crypto.length(id,32);requirePeer(id);Peer p=peers.get(key(id));
        if(p==null || p.invalid) throw new SecurityException("有効な相手の証明書がありません");return p;
    }
    private void verify(byte[] encoded,byte[] handshakeKey) {
        var certificate=AdminRecords.decode(encoded);admin.verifyCertificate(certificate,handshakeKey);
        byte[] id=identity(certificate);
        requirePeer(id);
        if(Crypto.equal(id,localId)) throw new SecurityException("自分とはセッションを張れません");
        Peer known=peers.get(key(id));
        if(known!=null) checkCertificateOrder(known,certificate);
        // 保存した相手には、空けておいた 1 枠を使わせる。総数の上限は誰にも超えさせない。
        if(known==null && !(storedMatcher.test(certificate)?peers.size()<maxPeers:hasVolatileSlot()))
            throw new SecurityException("相手の数が上限に達しています");
    }
    /**
     * 登録していない（揮発の）相手を新しく入れられるか。総数は台数-1 まで。
     * 保存した相手の登録があるとき（rememberPeer・期待する証明書・pin）は、保存した相手の 1 枠を空けておく。
     */
    private boolean hasVolatileSlot() {
        if(peers.size()>=maxPeers) return false;
        return !storedSlotReserved() || unstoredPeers()<maxPeers-1;
    }
    private boolean storedSlotReserved() {
        if(storedSlotReserved) return true;
        for(Peer p:peers.values()) { if(p.stored) return true; }
        return false;
    }
    private int unstoredPeers() {
        int count=0;
        for(Peer p:peers.values()) { if(!p.stored) count++; }
        return count;
    }
    /**
     * UDP の口が、期待する相手の証明書・pin を持っている間 true にする。
     * rememberPeer で入れた保存した相手と同じく、1 枠を空けておく。
     */
    synchronized void setStoredSlotReserved(boolean reserved) { storedSlotReserved=reserved; }
    /**
     * 揮発（保存していない）の相手 1 台の握手・鍵・経路を片付けて、枠を空ける。1 通目の時刻の記録は消さない。
     * 保存した相手・知らない相手は何もせず false。
     */
    synchronized boolean forgetVolatile(byte[] peerId) {
        Crypto.length(peerId,32);
        if(closed) return false;
        Peer p=peers.get(key(peerId));
        if(p==null || p.stored) return false;
        peers.remove(key(peerId));destroy(p);return true;
    }
    /**
     * 揮発の相手のうち、認証のパケットを最後に受けてから一番長い 1 台を手放す（forgetVolatile と同じ片付け）。
     * 同じ時刻なら表に入った順で古い方。保存した相手は手放さない。手放せる相手がいなければ false。
     */
    private boolean releaseOldestVolatile() {
        String oldestKey=null;Peer oldest=null;
        for(var entry:peers.entrySet()) {
            Peer candidate=entry.getValue();
            if(candidate.stored) continue;
            if(oldest==null || candidate.lastAuthenticated-oldest.lastAuthenticated<0) { oldest=candidate;oldestKey=entry.getKey(); }
        }
        if(oldest==null) return false;
        peers.remove(oldestKey);destroy(oldest);return true;
    }
    private void authenticated(Peer p) { p.lastAuthenticated=ticker.getAsLong(); }
    /** 相手の表に載っているか（保存した相手・揮発の相手のどちらでも）。UDP の口が片付けの要否を見るのに使う。 */
    synchronized boolean hasPeer(byte[] peerId) { Crypto.length(peerId,32);return !closed&&peers.containsKey(key(peerId)); }
    /** 表に載っていて、保存した相手ではない（揮発の）相手か。 */
    synchronized boolean isUnregistered(byte[] peerId) {
        Crypto.length(peerId,32);Peer p=closed?null:peers.get(key(peerId));
        return p!=null&&!p.stored;
    }
    /**
     * 1 通目で新しく入る相手が「保存した相手」（期待する証明書・予約した相手）かを決める。
     * UDP の口が自分のロックを持った状態で呼ばれる。null は「どれも保存した相手ではない」。
     */
    synchronized void setStoredMatcher(java.util.function.Predicate<AdminRecords.Record> matcher) {
        storedMatcher=matcher==null?c->false:matcher;
    }
    /** ネットワークが変わったとき。揮発の相手を全部片付け、消した数を返す。保存した相手は残す。 */
    synchronized int forgetAllVolatile() {
        if(closed) return 0;
        generation++;
        int count=0;
        for(Unconfirmed u:new ArrayList<>(unconfirmed.values())) dropUnconfirmed(u);
        for(var it=peers.values().iterator();it.hasNext();) {
            Peer p=it.next();
            if(!p.stored) { it.remove();destroy(p);count++; }
        }
        return count;
    }
    private void adopt(Peer p,AdminRecords.Record certificate) {
        checkCertificateOrder(p,certificate);
        if(!Crypto.equal(p.certificate.field(1),certificate.field(1))) {
            // Noiseと証明書の検査が終わったあとにだけ、古い鍵の通信状態を片付ける。
            destroy(p);replay.remove(p.certificate.field(1));p.exhausted=false;
        }
        p.certificate=certificate;p.invalid=false;
        discardObsoleteRenewal(p);
    }
    private void discardObsoleteRenewal(Peer p) {
        if(p.renewal==null)return;
        var renewal=AdminRecords.decode(p.renewal);
        if(!Crypto.equal(renewal.field(0),p.certificate.field(0))
                || !Crypto.equal(renewal.field(1),p.certificate.field(1))
                || p.certificate.issuedAt()>=renewal.issuedAt())p.renewal=null;
    }
    private void checkCertificateOrder(Peer p,AdminRecords.Record certificate) {
        if(!Crypto.equal(p.certificate.field(0),certificate.field(0))) throw new SecurityException("相手の身元が違います");
        if(certificate.issuedAt()<p.certificate.issuedAt()
                || certificate.issuedAt()==p.certificate.issuedAt() && !Arrays.equals(certificate.signedBytes(),p.certificate.signedBytes()))
            throw new SecurityException("証明書が古いか同じ発行時刻の内容が違います");
    }
    /**
     * 古い発行の証明書、または同じ発行時刻で署名対象が違う証明書は状態を変えず断る。
     * 新しい握手の鍵を受けたら、転送鍵・握手・古い鍵の時刻の記録を消す。
     * 新しい証明書を先に覚えた側は、前の証明書を出す相手とは握手しない。
     * 相手も新しい証明書を覚えるまで張れず、5秒ごと・最初から90秒の上限であきらめる。
     */
    public synchronized void rememberPeer(AdminRecords.Record certificate) {
        open();admin.verifyCertificate(certificate,certificate.field(1));
        byte[] id=identity(certificate);
        requirePeer(id);
        if(Crypto.equal(id,localId)) throw new IllegalArgumentException("自分の証明書です");
        Peer p=peers.get(key(id));
        if(p==null) {
            // 揮発の相手で枠が埋まっていても、保存する相手は入れる。最後に認証のパケットを受けたのが一番古い揮発の相手を手放す。
            if(peers.size()>=maxPeers && !releaseOldestVolatile()) throw new IllegalStateException("相手の数が上限に達しています");
            p=new Peer(certificate);p.stored=true;p.lastAuthenticated=ticker.getAsLong();peers.put(key(id),p);
        } else {
            checkCertificateOrder(p,certificate);p.stored=true;
            if(!Crypto.equal(p.certificate.field(1),certificate.field(1))) {
                destroy(p);replay.remove(p.certificate.field(1));p.exhausted=false;p.renewal=null;
            }
            p.certificate=certificate;p.invalid=false;
            discardObsoleteRenewal(p);
        }
    }
    /** 自分の証明書を同じ握手の鍵で更新する口。鍵自体を替えるときは管理を作り直す。 */
    public synchronized void updateLocalCertificate(AdminRecords.Record certificate) {
        if(validateLocalCertificateRenewal(certificate)) {
            // refreshと同じロックで差し替えてから旧許可を外す。保存処理からは外さない。
            localCertificate=certificate;
            if(certificate.format()==2)admin.forgetLegacyCertificate(certificate.field(0));
        }
    }
    /** 保存前の検査だけを行う。同じバイト列はfalse。状態は差し替えない。 */
    public synchronized boolean validateLocalCertificateRenewal(AdminRecords.Record certificate) {
        open();admin.verifyCertificate(certificate,localPublic);
        if(!Crypto.equal(certificate.field(0),localCertificate.field(0))) throw new SecurityException("自分の身元が違います");
        if(localCertificate.format()==2&&certificate.format()!=2)throw new SecurityException("旧形式へは戻しません");
        if(Arrays.equals(certificate.encode(),localCertificate.encode()))return false;
        if(certificate.issuedAt()<=localCertificate.issuedAt())throw new SecurityException("証明書の発行が新しくありません");
        return true;
    }
    /** pluginが保存から戻した発行済み更新。採用済みの相手の証明書は変えない。 */
    public synchronized void restorePeerRenewal(byte[] peerId,byte[] encoded,byte[] administratorPublic) {
        open();Peer p=peer(peerId);var certificate=AdminRecords.decode(encoded);
        admin.verifyCertificate(certificate,p.certificate.field(1));
        if(!Crypto.equal(certificate.signer(),administratorPublic)
                || !admin.administrators().hasEntry(administratorPublic)
                || admin.isRevoked(localId)
                || !Crypto.equal(certificate.field(0),p.certificate.field(0))
                || certificate.issuedAt()<=p.certificate.issuedAt())throw new SecurityException("保存した更新の証明書が違います");
        if(p.renewal!=null && !Arrays.equals(p.renewal,encoded))throw new SecurityException("発行済みの更新は差し替えません");
        p.renewal=encoded.clone();
    }
    /**
     * 失効が確定した相手だけを忘れて台数の枠を空ける。
     * 期限切れや通常の鍵更新では時刻を忘れず、古い1通目の再受理を防ぐ。
     */
    synchronized void forgetRevokedPeer(byte[] peerId) {
        removeRevokedPeer(peerId);
    }
    synchronized AdminRecords.Record removeRevokedPeer(byte[] peerId) {
        open();Crypto.length(peerId,32);
        if(!admin.isRevoked(peerId)) throw new SecurityException("失効が確定していない相手は忘れません");
        Peer p=peers.remove(key(peerId));
        if(p!=null) { destroy(p);replay.remove(p.certificate.field(1)); }
        return p==null ? null : p.certificate;
    }
    private byte[] prologue(byte[] id,long keyVersion) {
        return Crypto.concat("DistribuTAK/member-session/v1".getBytes(StandardCharsets.US_ASCII),group,
                SessionPacket.header(SessionPacket.FIRST,id,keyVersion,0));
    }
    private Instant nextTimestamp() {
        Instant now=clock.instant();
        // 2通目も含めて増やし、取り消した同時開始の1通目より必ず後にする。
        if(lastTimestamp!=null && !now.isAfter(lastTimestamp)) now=lastTimestamp.plusNanos(1);
        lastTimestamp=now;return now;
    }
    private byte[] newId() {
        byte[] id=new byte[16];
        try { do { random.nextBytes(id); } while(routes.containsKey(key(id))||unconfirmedRoutes.containsKey(key(id)));return id; }
        catch(RuntimeException e) { closeReason=UdpEndpoint.CloseReason.RANDOM_FAILURE;close();throw new RandomFailure(); }
    }
    private Outbound outbound(Peer p,byte[] wire) { return new Outbound(identity(p.certificate),wire); }
    private boolean firstDue(Peer p,long now) {
        return p.attempt==null || !p.attempt.sent || now-p.attempt.lastFirst>=RETRY_NANOS;
    }
    private void firstSent(Peer p,long now) { p.attempt.lastFirst=now;p.attempt.sent=true; }
    private Outbound begin(Peer p) {
        requireHandshake();requirePeer(identity(p.certificate));
        if(p.candidate!=null) throw new IllegalStateException("相手からの握手の確認待ちです");
        long now=ticker.getAsLong();
        if(!firstDue(p,now)) throw new IllegalStateException("次の1通目まで待ち、pollを呼んでください");
        if(p.attempt==null) p.attempt=new Attempt(now);
        if(p.pending!=null) { firstSent(p,now);return outbound(p,p.pending.first); }
        p.exhausted=false;p.restartScheduled=false;byte[] id=newId();
        var noise=new NoiseHandshake(true,localSecret,p.certificate.field(1),psk,prologue(id,version));
        var handshake=new TimedHandshake(noise,true,clock,replay,(cert,pub)->{
            verify(cert,pub);
            if(!Crypto.equal(identity(AdminRecords.decode(cert)),identity(p.certificate))) throw new SecurityException("求めた相手の身元と違います");
        });
        try {
            byte[] body=handshake.writeMessage(localCertificate.encode(),nextTimestamp());
            byte[] first=new SessionPacket(SessionPacket.FIRST,id,version,0,body).encode();
            p.pending=new Pending(id,first,version,handshake);firstSent(p,now);routes.put(key(id),p);return outbound(p,first);
        } catch(RuntimeException e) { handshake.close();throw e; }
    }
    /**
     * 発見で見つけた宛先（相手の番号と握手の鍵だけ）へ 1 通目を作る。核 C1 必修 3。
     * 2 通目の証明書・身元・握手の鍵の検査が全部通るまで Peer は作らず、peers・routes にも入れない。
     * 既に表にいる相手は既存の begin の道を使う（握手の鍵が違えば断る）。
     * 同じ宛先をもう一度呼ぶと、同じ 1 通目を返す（5 秒未満は IllegalStateException）。同時は MAX_UNCONFIRMED 件まで。
     * 例外の文に番号・鍵は出さない。
     */
    synchronized Outbound startUnconfirmed(byte[] nodeId,byte[] handshakeKey) {
        open();Crypto.length(nodeId,32);Crypto.length(handshakeKey,32);refresh();open();
        requireHandshake();requirePeer(nodeId);
        if(Crypto.equal(nodeId,localId)) throw new SecurityException("自分とはセッションを張れません");
        Peer known=peers.get(key(nodeId));
        if(known!=null) {
            if(known.invalid || !Crypto.equal(known.certificate.field(1),handshakeKey)) throw new SecurityException("有効な相手の証明書がありません");
            return begin(known);
        }
        long now=ticker.getAsLong();
        Unconfirmed u=unconfirmed.get(key(nodeId));
        if(u!=null) {
            if(!Crypto.equal(u.handshakeKey,handshakeKey)) throw new SecurityException("握手の鍵が違います");
            if(u.attempt!=null && u.attempt.sent && now-u.attempt.lastFirst<RETRY_NANOS) throw new IllegalStateException("次の1通目まで待ってください");
            u.attempt.lastFirst=now;u.attempt.sent=true;
            return new Outbound(u.nodeId.clone(),u.pending.first);
        }
        if(unconfirmed.size()>=MAX_UNCONFIRMED) throw new IllegalStateException("同時に始められる数に達しています");
        u=new Unconfirmed(nodeId,handshakeKey);byte[] id=newId();
        var noise=new NoiseHandshake(true,localSecret,handshakeKey,psk,prologue(id,version));
        var handshake=new TimedHandshake(noise,true,clock,replay,(cert,pub)->{
            verify(cert,pub);
            if(!Crypto.equal(identity(AdminRecords.decode(cert)),nodeId)) throw new SecurityException("求めた相手の身元と違います");
            if(!Crypto.equal(pub,handshakeKey)) throw new SecurityException("求めた相手の握手の鍵と違います");
        });
        try {
            byte[] body=handshake.writeMessage(localCertificate.encode(),nextTimestamp());
            byte[] first=new SessionPacket(SessionPacket.FIRST,id,version,0,body).encode();
            u.pending=new Pending(id,first,version,handshake);u.attempt=new Attempt(now);u.attempt.lastFirst=now;u.attempt.sent=true;
            unconfirmed.put(key(nodeId),u);unconfirmedRoutes.put(key(id),u);
            return new Outbound(u.nodeId.clone(),first);
        } catch(RuntimeException e) { handshake.close();throw e; }
    }
    /** 未確認の宛先を 1 件片付ける。1 通目の時刻の記録は消さない。 */
    private void dropUnconfirmed(Unconfirmed u) {
        unconfirmed.remove(key(u.nodeId));
        if(u.pending!=null) { unconfirmedRoutes.remove(key(u.pending.id));u.pending.close();u.pending=null; }
        u.attempt=null;
    }
    /** 未確認の宛先を消す。表にあったら true。UDP の口が失敗・期限切れ・ネットワーク変更で呼ぶ。 */
    synchronized boolean dropUnconfirmed(byte[] nodeId) {
        Crypto.length(nodeId,32);Unconfirmed u=unconfirmed.get(key(nodeId));
        if(u==null) return false;
        dropUnconfirmed(u);return true;
    }
    synchronized boolean hasUnconfirmed(byte[] nodeId) { Crypto.length(nodeId,32);return !closed&&unconfirmed.containsKey(key(nodeId)); }
    synchronized int unconfirmedCount() { return unconfirmed.size(); }
    /** 未確認の宛先の 2 通目。全部の検査が通ったときだけ Peer を作る。失敗は Peer を作らず宛先を消して投げる。 */
    private Received unconfirmedSecond(Unconfirmed u,SessionPacket packet) {
        Pending pending=u.pending;
        try {
            if(pending==null || !Crypto.equal(pending.id,packet.id())) throw new SecurityException("2通目を待っていません");
            if(packet.version()!=pending.version || packet.version()!=version) throw new SecurityException("握手の版が違います");
            var received=pending.handshake.readMessage(packet.body());
            var certificate=AdminRecords.decode(received.certificate());
            byte[] id=identity(certificate);
            if(!Crypto.equal(id,u.nodeId) || !Crypto.equal(certificate.field(1),u.handshakeKey)) throw new SecurityException("求めた相手と違います");
            Connection c=new Connection(packet.id(),version,ticker.getAsLong(),pending.handshake.transport(ticker),true,received.peerClockOffset());
            c.second=null;
            Peer p=peers.get(key(id));
            try {
                if(p==null) {
                    // 全部の検査が通ったので、ここで初めて表に入れる。揮発の枠も数え直す。
                    if(!(storedMatcher.test(certificate)?peers.size()<maxPeers:hasVolatileSlot())) throw new SecurityException("相手の数が上限に達しています");
                    p=new Peer(certificate);p.stored=storedMatcher.test(certificate);
                    peers.put(key(id),p);
                } else adopt(p,certificate);
                authenticated(p);
                dropUnconfirmed(u);
                dropPending(p);dropCandidate(p);promote(p,c);routes.put(key(c.id),p);
                return new Received(id,null,List.of(outbound(p,encrypt(c,new byte[0]))));
            } catch(RuntimeException e) { c.close();throw e; }
        } catch(RuntimeException e) { dropUnconfirmed(u);throw e; }
    }
    /**
     * 明示した開始。途中で呼び直しても、1通目は5秒に1通までで、試みの90秒は延ばさない。
     * 5秒未満の呼び直しは状態を変えずIllegalStateException。待ってpollを呼ぶ。
     * あきらめた後の明示したstartは、sendと同じく新しい90秒の試みを始める。
     */
    public synchronized Outbound start(byte[] peerId) { open();refresh();open();return begin(peer(peerId)); }
    /**
     * 戻ったすべてのパケットを渡す。作り直しの1通目と古い鍵の DATA が同時に返る場合がある。
     * 張ったセッションがなければ握手を開始し、中身は送らず預からない。
     * 中身を送れたか知る必要がある呼び出し元は sendWithStatus を使う。
     */
    public synchronized List<Outbound> send(byte[] peerId,byte[] plaintext) {
        return sendWithStatus(peerId,plaintext).outbound();
    }
    /**
     * plaintextSent で中身を送ったかを返す。未成立なら新しい一時鍵で握手を始め、false を返す。
     * 握手中はその握手を続け、確認待ちなら新しい開始は返さない。中身は保持しない。
     * 失効・未知の相手・閉鎖済みなら拒む。1176バイトを超える中身も状態を変えず拒む。
     */
    public synchronized SendResult sendWithStatus(byte[] peerId,byte[] plaintext) {
        if(coordinator!=null)coordinator.requireData(plaintext);
        open();if(plaintext.length>SessionPacket.MAX_PLAINTEXT) throw new IllegalArgumentException("パケットの中身が長すぎます");
        refresh();open();Peer p=peer(peerId);List<Outbound> out=new ArrayList<>();
        if(p.active==null) {
            if(p.pending==null && p.candidate==null && firstDue(p,ticker.getAsLong())) out.add(begin(p));
            return new SendResult(false,out);
        }
        if(p.pending==null && p.candidate==null && firstDue(p,ticker.getAsLong())
                && (p.active.version!=version || p.active.transport.needsRehandshake())) out.add(begin(p));
        try { out.add(outbound(p,encrypt(p.active,plaintext))); }
        catch(RuntimeException e) { if(p.active.transport.isClosed()) dropActive(p);throw e; }
        return new SendResult(true,out);
    }
    private byte[] encrypt(Connection c,byte[] plaintext) {
        long number=c.transport.nextSendingCounter();
        byte[] header=SessionPacket.header(SessionPacket.DATA,c.id,c.version,number);
        return new SessionPacket(SessionPacket.DATA,c.id,c.version,number,c.transport.sendDatagram(plaintext,header)).encode();
    }
    public synchronized Received receive(byte[] wire) {
        return receive(wire,certificate->{});
    }
    /**
     * UDPのpinを、証明書の検査後・時刻と相手の採用前に確かめる。
     * <p>
     * Checks the UDP pin after certificate validation and before adopting the peer and timestamp.
     */
    synchronized Received receive(byte[] wire,java.util.function.Consumer<AdminRecords.Record> firstPeerCheck) {
        open();refresh();open();SessionPacket packet=SessionPacket.decode(wire);
        boolean persisting=coordinator!=null&&coordinator.acceptsPersistingData();
        if(!persisting||packet.kind()!=SessionPacket.DATA)requireHandshake();
        if(packet.kind()==SessionPacket.FIRST) return first(packet,wire,firstPeerCheck);
        Peer p=routes.get(key(packet.id()));
        if(p==null && packet.kind()==SessionPacket.SECOND) {
            Unconfirmed u=unconfirmedRoutes.get(key(packet.id()));
            if(u!=null) return unconfirmedSecond(u,packet);
        }
        if(persisting&&(p==null||p.invalid||!matching(p.active,packet)))throw new IllegalStateException("Existing session required during persistence");
        if(p==null || p.invalid) throw new SecurityException("受け手のセッションがありません");
        if(packet.kind()==SessionPacket.SECOND) return second(p,packet,wire);
        Connection c=matching(p.active,packet) ? p.active : matching(p.candidate,packet) ? p.candidate : null;
        if(c==null||persisting&&c!=p.active) throw new SecurityException("受け手の鍵がありません");
        requirePeer(identity(p.certificate));
        byte[] plain=c.transport.receiveDatagram(packet.counter(),packet.body(),packet.header());
        if(coordinator!=null&&(persisting||plain.length!=0)){
            try{coordinator.requireReceivedData(plain);}catch(RuntimeException rejected){Crypto.wipe(plain);throw rejected;}
        }
        try{
            if(!persisting){authenticated(p);if(c==p.candidate)promote(p,c);}
            return new Received(identity(p.certificate),plain,List.of(),packet.id());
        }finally{Crypto.wipe(plain);}
    }
    private static boolean matching(Connection c,SessionPacket packet) {
        return c!=null && c.version==packet.version() && Crypto.equal(c.id,packet.id());
    }
    private boolean newerKeyVersionSeen;
    /** 認証前の表示の目安。権限や停止の判断には使わない。 */
    public synchronized boolean sawNewerKeyVersion() { return newerKeyVersionSeen; }
    private Received first(SessionPacket packet,byte[] wire,java.util.function.Consumer<AdminRecords.Record> firstPeerCheck) {
        // 古いグループの鍵で新しい握手を始めない。既存 DATA だけを猶予中に受ける。
        if(packet.version()>version)newerKeyVersionSeen=true;
        if(packet.version()!=version) throw new SecurityException("握手のグループの鍵の版が違います");
        Peer routed=routes.get(key(packet.id()));
        if(routed!=null) {
            Connection c=matching(routed.candidate,packet) ? routed.candidate : matching(routed.active,packet) ? routed.active : null;
            if(c!=null && !c.initiator && c.first!=null && Arrays.equals(c.first,wire))
                return new Received(identity(routed.certificate),null,response(routed,c,ticker.getAsLong()));
            throw new SecurityException("セッションの番号が使用済みです");
        }
        firstCalculations++;
        try(var noise=new NoiseHandshake(false,localSecret,null,psk,prologue(packet.id(),version));
            var handshake=new TimedHandshake(noise,false,clock,replay,this::verify)) {
            boolean[] accepted={false};
            var received=handshake.readMessage(packet.body(),message->{
                var cert=AdminRecords.decode(message.certificate());Peer known=peers.get(key(identity(cert)));
                Unconfirmed mine=unconfirmed.get(key(identity(cert)));
                firstPeerCheck.accept(cert);
                boolean ownWins=AdminRecords.compareBytes(localPublic,cert.field(1))<0;
                // 自分が候補を送っている相手と同時に始めたとき：公開鍵の小さい側を残す。
                if(mine!=null && mine.pending!=null && ownWins) return false;
                // 無視する同時開始は、時刻の記録を確定する前に除く。
                accepted[0]=known!=null && !Crypto.equal(known.certificate.field(1),cert.field(1))
                        || !ownWins || known==null || known.pending==null;
                return accepted[0];
            });
            var certificate=AdminRecords.decode(received.certificate());byte[] id=identity(certificate);
            if(!accepted[0]) return new Received(id,null,List.of());
            // 負けた候補は消す。番地の失敗には数えない（呼び出し元が hasUnconfirmed で見る）。
            Unconfirmed lost=unconfirmed.get(key(id));if(lost!=null) dropUnconfirmed(lost);
            Peer p=peers.get(key(id));
            if(p==null) { p=new Peer(certificate);p.stored=storedMatcher.test(certificate);peers.put(key(id),p); }
            long now=ticker.getAsLong();p.lastAuthenticated=now;
            // 新しい認証済みの開始なら、確認の来なかった候補を捨てて回復する。
            dropCandidate(p);
            dropPending(p);p.attempt=null;p.restartScheduled=false;
            adopt(p,certificate);p.authenticatedFirst=certificate;
            byte[] second=new SessionPacket(SessionPacket.SECOND,packet.id(),version,0,handshake.writeMessage(localCertificate.encode(),nextTimestamp())).encode();
            Connection c=new Connection(packet.id(),version,now,handshake.transport(ticker),false,received.peerClockOffset());
            c.first=wire.clone();c.second=second;p.candidate=c;routes.put(key(c.id),p);
            return new Received(id,null,List.of(outbound(p,second)));
        }
    }
    private Received second(Peer p,SessionPacket packet,byte[] wire) {
        if(p.pending==null || !Crypto.equal(p.pending.id,packet.id())) {
            if(matching(p.active,packet) && p.active.initiator && Arrays.equals(p.active.second,wire))
                return new Received(identity(p.certificate),null,List.of(outbound(p,encrypt(p.active,new byte[0]))));
            throw new SecurityException("2通目を待っていません");
        }
        Pending pending=p.pending;
        try {
            if(packet.version()!=pending.version || packet.version()!=version) throw new SecurityException("握手の版が違います");
            var received=pending.handshake.readMessage(packet.body());
            Connection c=new Connection(packet.id(),version,ticker.getAsLong(),pending.handshake.transport(ticker),true,received.peerClockOffset());
            c.second=wire.clone();
            adopt(p,AdminRecords.decode(received.certificate()));
            authenticated(p);
            dropPending(p);promote(p,c);routes.put(key(c.id),p);
            return new Received(identity(p.certificate),null,List.of(outbound(p,encrypt(c,new byte[0]))));
        } catch(RuntimeException e) { dropPending(p);p.restartScheduled=true;throw e; }
    }
    private void promote(Peer p,Connection c) {
        newerKeyVersionSeen=false;
        dropActive(p);if(p.candidate==c) p.candidate=null;
        p.active=c;p.rotating=false;p.exhausted=false;p.restartScheduled=false;p.attempt=null;
    }
    private void dropActive(Peer p) { if(p.active!=null) { if(coordinator!=null)coordinator.forgetManagementPages(identity(p.certificate));routes.remove(key(p.active.id));p.active.close();p.active=null; } }
    private void dropCandidate(Peer p) { if(p.candidate!=null) { routes.remove(key(p.candidate.id));p.candidate.close();p.candidate=null; } }
    private void dropPending(Peer p) { if(p.pending!=null) { routes.remove(key(p.pending.id));p.pending.close();p.pending=null; } }
    private void destroy(Peer p) { dropActive(p);dropCandidate(p);dropPending(p);p.attempt=null;p.rotating=false;p.restartScheduled=false; }
    /** 一覧の採用直後に呼ぶ。期限の判定にも使い、パケットは作らない。 */
    public synchronized void refresh() {
        if(closed) return;
        var reason=admin.localCertificateReason(localCertificate,localPublic,localChecks);
        if(reason!=UdpEndpoint.CloseReason.RUNNING) { closeReason=reason;close();return; }
        long now=ticker.getAsLong();
        for(var it=unconfirmed.values().iterator();it.hasNext();) {
            Unconfirmed u=it.next();
            if(u.attempt==null || now-u.attempt.started>=ATTEMPT_NANOS) {
                it.remove();
                if(u.pending!=null) { unconfirmedRoutes.remove(key(u.pending.id));u.pending.close();u.pending=null; }
                u.attempt=null;
            }
        }
        for(var it=peers.values().iterator();it.hasNext();) {
            Peer p=it.next();
            try { admin.verifyCertificateCached(p.certificate,p.certificate.field(1),p.checks); }
            catch(RuntimeException e) {
                destroy(p);
                // 揮発の相手は項目ごと消して枠を空ける。保存した相手は invalid のまま残す。
                if(p.stored) p.invalid=true; else it.remove();
                continue;
            }
            if(p.attempt!=null && now-p.attempt.started>=ATTEMPT_NANOS) {
                dropPending(p);p.attempt=null;p.exhausted=true;p.restartScheduled=false;
            }
            if(p.candidate!=null) {
                p.candidate.transport.expire();
                // 返事の候補の期限切れで、成立済みセッションの通常の作り直しを止めない。
                if(p.candidate.transport.isClosed() || now-p.candidate.created>=ATTEMPT_NANOS) { dropCandidate(p);p.restartScheduled=false; }
            }
            if(p.active!=null) {
                p.active.transport.expire();
                if(p.active.transport.isClosed() || p.rotating && now-p.rotationAt>=ROTATION_NANOS) dropActive(p);
                else if(now-p.active.created>=ATTEMPT_NANOS) { p.active.first=null;p.active.second=null; }
            }
            // 揮発の相手で、使えるセッションが無く握手も進んでいなければ項目ごと消す。
            if(!p.stored && p.active==null && p.pending==null && p.candidate==null && !p.restartScheduled) it.remove();
        }
    }
    private List<Outbound> response(Peer p,Connection c,long now) {
        if(now-c.lastSent<RETRY_NANOS) return List.of();
        c.lastSent=now;return List.of(outbound(p,c.second));
    }
    /**
     * タイマーの代わりの口。1通目は失敗後の作り直しも含め、最初の試みから90秒未満・5秒ごと。
     * 0・5・…・85秒の最大18通。時計を進めず繰り返し呼んでも追加しない。
     * 1つの1通目への2通目も、重複への返事と共通の間隔で最大18通。未確認の候補は90秒で消す。
     */
    public synchronized List<Outbound> poll() {
        if(closed) return List.of();refresh();if(closed) return List.of();
        if(coordinator!=null&&!coordinator.acceptsPackets())return List.of();
        long now=ticker.getAsLong();List<Outbound> out=new ArrayList<>();
        for(Peer p:peers.values()) {
            if(p.invalid) continue;
            if(p.pending!=null) {
                if(firstDue(p,now)) out.add(begin(p));
            } else if(p.candidate!=null) {
                out.addAll(response(p,p.candidate,now));
            } else if(firstDue(p,now) && (p.restartScheduled || !p.exhausted && p.active!=null
                    && (p.active.version!=version || p.active.transport.needsRehandshake()))) out.add(begin(p));
        }
        return List.copyOf(out);
    }
    /**
     * 受け取って確かめた新しいグループの鍵を渡す。引数の秘密の配列は呼び出し元が消す。
     * 成立済みか、試みが続いている相手だけを予定する。覚えただけ・期限切れ・あきらめた相手は予定しない。
     * あきらめた相手は古い成立済みの鍵が残っていても予定せず、次のsendかstartを待つ。
     * ただし新しい確認待ちの候補があれば、過去にあきらめた印より候補を優先して予定する。
     * 候補を捨てて自分の試みにする90秒は、この更新の時点から数える。
     * pollが遅れても、続けて鍵を更新しても、この開始時刻と5秒の間隔は延ばさない。
     * 途中の試みの90秒と1通目の5秒間隔、古い転送鍵の期限は引き継ぐ。
     */
    public synchronized void rotateGroupKey(byte[] key,long nextVersion) {
        if(coordinator!=null)coordinator.require(CorePersistenceCoordinator.Operation.KEY_APPLY);
        open();Crypto.length(key,32);if(nextVersion<=version) throw new IllegalArgumentException("グループの鍵の版が増えていません");
        refresh();open();byte[] next=key.clone();Crypto.wipe(psk);psk=next;version=nextVersion;long now=ticker.getAsLong();
        for(Peer p:peers.values()) {
            boolean candidate=p.candidate!=null;
            boolean resume=!p.invalid && (candidate || !p.exhausted
                && (p.active!=null || p.pending!=null || p.attempt!=null && p.restartScheduled));
            if(resume && candidate && p.attempt==null) p.attempt=new Attempt(now);
            dropPending(p);dropCandidate(p);p.restartScheduled=resume;
            if(resume) p.exhausted=false;
            // 連続して鍵を替えても、残っている古いセッションの猶予を延ばさない。
            if(p.active!=null && !p.rotating) { p.rotationAt=now;p.rotating=true; }
        }
    }
    /**
     * 旧セッションの猶予中だけ管理ページの送信を抑える。既存の起点は変えない。
     * <p>
     * Pauses management pages only while old sessions are in their grace period, without changing its existing start.
     */
    public synchronized boolean hasRotatingSessions(){
        refresh();for(var peer:peers.values())if(peer.active!=null&&peer.rotating)return true;return false;
    }
    /** refresh を行うため、照会だけでも期限・失効で相手または全体が閉じることがある。 */
    public synchronized boolean isEstablished(byte[] id) { refresh();Peer p=peers.get(key(id));return p!=null && p.active!=null; }
    /** 握手の全検査を通した確立済みの相手だけを表す。SessionManager だけが作る（DHT の相手の入口。核 C1）。 */
    public static final class VerifiedSession {
        private final byte[] peerId,sessionId;
        private final long generation;
        private VerifiedSession(byte[] peerId,byte[] sessionId,long generation){this.peerId=peerId.clone();this.sessionId=sessionId.clone();this.generation=generation;}
        /** SessionManager が作ったときの世代。呼ぶ側は決められない。 */
        public long generation() { return generation; }
        public byte[] peerId() { return peerId.clone(); }
        public byte[] sessionId() { return sessionId.clone(); }
        @Override public String toString() { return "Verified session"; }
    }
    /** 確立済みの相手の確認済みセッション。まだ確立していない・知らない相手は null。 */
    public synchronized VerifiedSession verifiedSession(byte[] id) {
        Crypto.length(id,32);refresh();Peer p=peers.get(key(id));
        return p!=null&&p.active!=null?new VerifiedSession(id,p.active.id,generation):null;
    }
    /** 認証済みFIRSTで示された証明書だけを返す。保存済み相手やSECONDでは更新しない。 */
    public synchronized AdminRecords.Record authenticatedFirstCertificate(byte[] peerId){
        open();Peer peer=peers.get(key(peerId));return peer==null?null:peer.authenticatedFirst;
    }
    /** 今の世代。ネットワークが変わるたびに 1 増える（DhtNode.networkChanged(世代, LocalNetwork) へ渡す）。 */
    public synchronized long generation() { return generation; }
    /** 成立したセッションの公開の識別子。DATAを受けたときの値はReceivedのものを使う。 */
    public synchronized byte[] sessionId(byte[] id) {
        Crypto.length(id,32);refresh();Peer p=peers.get(key(id));return p!=null&&p.active!=null?p.active.id.clone():null;
    }
    /** 指定した確立済みセッションを相手が始めたか。世代が変わったらfalse。 */
    public synchronized boolean isPeerInitiatedSession(byte[] peerId,byte[] sessionId) {
        Crypto.length(peerId,32);Crypto.length(sessionId,16);refresh();Peer peer=peers.get(key(peerId));
        return peer!=null&&peer.active!=null&&Crypto.equal(peer.active.id,sessionId)&&!peer.active.initiator;
    }
    /** refresh を行い、転送鍵・握手中の鍵を消すことがある。 */
    public synchronized boolean isHandshaking(byte[] id) { refresh();Peer p=peers.get(key(id));return p!=null && (p.pending!=null || p.candidate!=null); }
    /** refresh で相手や全体を閉じることがある。時計を戻した直後の差は答え157の目安。 */
    public synchronized Duration peerClockOffset(byte[] id) { refresh();Peer p=peer(id);return p.active==null ? null : p.active.offset; }
    /** UDPのクッキーは、今も待っている1通目にだけ答える。状態と期限は核で判定する。 */
    synchronized boolean awaitsFirst(byte[] first) {
        refresh();if(closed)return false;
        for(Peer p:peers.values())if(!p.invalid&&p.pending!=null&&Arrays.equals(first,p.pending.first))return true;
        for(Unconfirmed u:unconfirmed.values())if(u.pending!=null&&Arrays.equals(first,u.pending.first))return true;
        return false;
    }
    int maximumPeers() { return maxPeers; }
    /** 閉じた状態の照会だけを行う。refresh は呼ばず、状態を変えない。 */
    public synchronized boolean isClosed() { return closed; }
    public synchronized UdpEndpoint.CloseReason closeReason() { return closeReason; }
    /** 新しく採用した公開証明書を保存するための照会。保留中の発行証明書は返さない。 */
    public synchronized AdminRecords.Record peerCertificate(byte[] id) { return knownCertificate(id); }
    /** UDPの口が認証済みの公開記録を読み出すためだけに使う。 */
    synchronized AdminRecords.Record knownCertificate(byte[] id) {
        refresh();
        Peer p=peers.get(key(id));
        return closed || p==null || p.invalid ? null : p.certificate;
    }
    @Override public synchronized void close() {
        if(closed) return;closed=true;
        if(closeReason==UdpEndpoint.CloseReason.RUNNING)closeReason=UdpEndpoint.CloseReason.CLOSED_BY_CALLER;
        for(Peer p:peers.values()) { destroy(p);replay.remove(p.certificate.field(1)); }
        for(Unconfirmed u:new ArrayList<>(unconfirmed.values())) dropUnconfirmed(u);
        peers.clear();routes.clear();Crypto.wipe(localSecret);Crypto.wipe(psk);
    }
}
