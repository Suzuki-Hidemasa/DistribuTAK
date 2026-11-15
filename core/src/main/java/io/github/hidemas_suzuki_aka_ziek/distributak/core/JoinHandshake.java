// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.LongSupplier;
import java.util.function.Consumer;

/**
 * 通信しない入るためだけの握手。HPKE base の求めと返事を1つずつ扱う。
 * 引数の秘密配列は呼び出し側が所有する。操作中の一時的な写しは成功・失敗とも消す。
 * 招待の秘密は有効な間だけ保持し、消費・期限・取り消し・closeで消す。
 */
public final class JoinHandshake {
    public static final int MAX_REQUEST_BYTES=JoinMessages.MAX_REQUEST, MAX_RESPONSE_BYTES=JoinMessages.MAX_REPLY_PACKET;
    public static final int MAX_CHAIN_RECORDS=JoinMessages.MAX_CHAIN, RETRY_INTERVAL_MILLIS=1000, MAX_RETRIES=5;
    private JoinHandshake() {}
    private static byte[] ascii(String value) { return value.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] requestInfo(byte[] id) { return Crypto.concat(ascii("DistribuTAK/join/request/v1"),id); }
    private static byte[] replyInfo(byte[] id,byte[] fingerprint) { return Crypto.concat(ascii("DistribuTAK/join/response/v1"),id,fingerprint); }
    private static byte[] signedReply(byte[] info,byte[] prefix) {
        return Crypto.concat(ascii("DistribuTAK/join/response-signature/v1"),info,prefix);
    }
    private static byte[] proof(byte[] key,JoinMessages.Request request) {
        byte[] unsigned=request.unsigned(), input=null;
        try { input=Crypto.concat(ascii("DistribuTAK/join/request-proof/v1"),unsigned);return Crypto.hmacSha256(key,input); }
        finally { Crypto.wipe(unsigned);Crypto.wipe(input); }
    }
    private static byte[] signedRequest(JoinMessages.Request request) {
        byte[] raw=request.signedBytes();
        try { return Crypto.concat(ascii("DistribuTAK/join/request-signature/v1"),raw); } finally { Crypto.wipe(raw); }
    }
    /** URL の秘密から招待の識別子と証明用の鍵を作る。識別子自体は秘密として扱わない。 */
    private static final class Context implements AutoCloseable {
        final byte[] id,proofKey,administrator,handshake,group;
        Context(Invitation invitation) {
            byte[] secret=invitation.totpSecret(), extracted=null;
            try {
                byte[] address=invitation.adminAddress();
                byte[] publicFields=Crypto.concat(ascii("DistribuTAK/join/invitation/v1"),new byte[]{(byte)address.length},address,
                        ByteBuffer.allocate(4).putInt(invitation.udpPort()).array(),invitation.handshakePublicKey(),invitation.adminPublicKey());
                id=Crypto.hmacSha256(secret,publicFields);extracted=Crypto.extract(id,secret);
                proofKey=Crypto.expand(extracted,ascii("DistribuTAK/join/proof-key/v1"),32);
                administrator=invitation.adminPublicKey();handshake=invitation.handshakePublicKey();group=invitation.groupId();
            } finally { Crypto.wipe(secret);Crypto.wipe(extracted); }
        }
        @Override public void close() { Crypto.wipe(proofKey); }
    }
    /**
     * 発行の直前の最新の鎖・失効・鍵の一貫した写し。呼び出し元が最新であることを保証する。
     * 鎖はURLを作ったときの起点から。使い終わったら呼び出し元も close する。
     */
    public static final class Materials implements AutoCloseable {
        private List<AdminRecords.Record> chain;
        private AdminRecords.Record revocations;
        private final long keyVersion;
        private final byte[] groupKey;
        private byte[] expectedIdentity;
        private boolean closed;
        public Materials(List<AdminRecords.Record> chain,AdminRecords.Record revocations,long keyVersion,byte[] groupKey) {
            Crypto.length(groupKey,32);
            if(chain==null || chain.isEmpty() || chain.size()>MAX_CHAIN_RECORDS || keyVersion<0) throw new IllegalArgumentException("発行の材料が範囲外です");
            int total=Objects.requireNonNull(revocations).encode().length;
            for(var record:chain) {
                total=Math.addExact(total,record.encode().length);
                if(total>JoinMessages.MAX_RESPONSE) throw new IllegalArgumentException("発行の材料が大きすぎます");
            }
            this.chain=List.copyOf(chain);this.revocations=Objects.requireNonNull(revocations);this.keyVersion=keyVersion;this.groupKey=groupKey.clone();
        }
        /** 入り直す身元を必須にした発行材料。新規加入の材料とは区別する。 */
        public static Materials rejoin(List<AdminRecords.Record> chain,AdminRecords.Record revocations,long keyVersion,byte[] groupKey,byte[] expectedIdentity) {
            if(expectedIdentity==null) throw new IllegalArgumentException("入り直す身元がありません");
            Crypto.length(expectedIdentity,32);
            var result=new Materials(chain,revocations,keyVersion,groupKey);result.expectedIdentity=expectedIdentity.clone();return result;
        }
        private synchronized byte[] key() { if(closed) throw new IllegalStateException("発行の材料は消去済みです");return groupKey.clone(); }
        private synchronized Materials snapshot() {
            if(closed) throw new IllegalStateException("発行の材料は消去済みです");return expectedIdentity==null ? new Materials(chain,revocations,keyVersion,groupKey) : rejoin(chain,revocations,keyVersion,groupKey,expectedIdentity);
        }
        @Override public synchronized void close() { closed=true;Crypto.wipe(groupKey);chain=List.of();revocations=null; }
    }
    /** 招待1つにつき1つ作る。中にタイマーを持たず、上位から expire/revoke/close を呼ぶ。 */
    public static final class Admin implements AutoCloseable {
        private final Context context;
        private final TotpVerifier verifier;
        private final Clock clock;
        private byte[] anchor,anchorSignature,cachedReply,cachedFingerprint;
        private AdminRecords.Record issuedCertificate;
        private boolean consumed,closed;
        private final Consumer<byte[]> beforeCommit;
        public Admin(Invitation invitation,AdminRecords.Record anchor,byte[] anchorSignature,Clock clock,LongSupplier monotonicNanos) {
            this(invitation,anchor,anchorSignature,clock,monotonicNanos,key->{});
        }
        // 発行前の失敗の試験だけに使う。通常の道では外の処理を呼ばない。
        Admin(Invitation invitation,AdminRecords.Record anchor,byte[] anchorSignature,Clock clock,LongSupplier monotonicNanos,Consumer<byte[]> beforeCommit) {
            this.clock=Objects.requireNonNull(clock);this.beforeCommit=Objects.requireNonNull(beforeCommit);
            if(!Crypto.equal(anchor.group(),invitation.groupId()))throw new SecurityException("招待のグループが違います");
            var checked=new AdminState(anchor.group(),invitation.adminPublicKey(),clock,new InMemoryAdminRecordStore());
            try { checked.bootstrap(anchor,anchorSignature); } finally { checked.clear(); }
            byte[] pinnedAnchor=anchor.encode(), pinnedSignature=anchorSignature.clone();
            Context created=new Context(invitation);byte[] secret=null;
            try {
                secret=invitation.totpSecret();verifier=new TotpVerifier(secret,clock,monotonicNanos);context=created;
                this.anchor=pinnedAnchor;this.anchorSignature=pinnedSignature;
            } catch(RuntimeException e) { created.close();Crypto.wipe(pinnedAnchor);Crypto.wipe(pinnedSignature);throw e; }
            finally { Crypto.wipe(secret); }
        }
        /**
         * 最新の材料と機器の鍵は呼び出し元が所有する。発行・consume・返事の確定を直列に行う。
         * 送り直しでは材料と署名の秘密鍵を使わず、最初に確定した暗号文だけを返す。
         * @throws IllegalArgumentException 包みの形・大きさや、引数の鍵の長さが違うとき。
         * @throws SecurityException 暗号・署名・TOTP・期限・権限などの検査に通らないとき。
         * @throws IllegalStateException 消去済みの材料を使うなど、操作の順が違うとき。
         */
        public synchronized byte[] respond(byte[] packet,byte[] handshakeSecret,byte[] administratorSecret,Materials latest) {
            expire();if(closed) throw new SecurityException("招待は使えません");
            if(!Crypto.equal(Crypto.x25519Public(handshakeSecret),context.handshake)) throw new SecurityException("招待の管理者の握手の鍵が違います");
            byte[] plaintext=null, digest=null, key=null, ready=null, outgoing=null;
            AdminState checked=null;Materials material=null;
            try {
                var envelope=JoinMessages.packet(packet,false);
                if(!Crypto.equal(envelope.invitation,context.id)) throw new SecurityException("招待が違います");
                byte[] info=requestInfo(context.id);
                try(var hpke=Hpke.recipient(handshakeSecret,envelope.enc,info)) { plaintext=hpke.open(info,envelope.ciphertext); }
                try(var request=JoinMessages.request(plaintext)) {
                    if(!Crypto.equal(request.invitation,context.id) || !SignaturePurpose.verifyIdentity(context.group,request.identity,request.handshake,request.binding))
                        throw new SecurityException("入る側の身元の署名が違います");
                    byte[] signed=signedRequest(request);
                    try { if(!Crypto.verify(request.identity,signed,request.signature)) throw new SecurityException("求め全体の身元の署名が違います"); }
                    finally { Crypto.wipe(signed); }
                    digest=Crypto.blake2s(plaintext);
                    String code=new String(request.code,StandardCharsets.US_ASCII);
                    if(consumed) {
                        if(verifier.verify(request.handshake,code)!=TotpVerifier.Result.RETRANSMISSION || !Crypto.equal(digest,cachedFingerprint))
                            throw new SecurityException("同じ求めの送り直しではありません");
                        return cachedReply.clone();
                    }
                    byte[] expected=proof(context.proofKey,request);
                    try { if(!Crypto.equal(expected,request.proof)) throw new SecurityException("招待の秘密の証明が違います"); }
                    finally { Crypto.wipe(expected); }
                    if(verifier.verify(request.handshake,code)!=TotpVerifier.Result.VALID) throw new SecurityException("TOTPを確認できません");
                    if(!Crypto.equal(Crypto.ed25519Public(administratorSecret),context.administrator)) throw new SecurityException("招待した管理者の署名の鍵が違います");
                    material=Objects.requireNonNull(latest,"latest").snapshot();
                    if(material.expectedIdentity!=null && !Crypto.equal(material.expectedIdentity,request.identity))
                        throw new SecurityException("入り直す身元が違います");
                    if(!Crypto.equal(material.chain.get(0).encode(),anchor)) throw new SecurityException("保存した起点と違います");
                    checked=new AdminState(material.chain.get(0).group(),context.administrator,clock,new InMemoryAdminRecordStore());
                    checked.join(material.chain,anchorSignature,material.revocations);
                    if(!checked.administrators().hasEntry(context.administrator)) throw new SecurityException("招待した管理者は外されています");
                    var certificate=AdminRecords.certificate(material.chain.get(0).group(),request.identity,request.handshake,request.binding,clock.millis(),administratorSecret);
                    checked.verifyCertificate(certificate,request.handshake);
                    key=material.key();
                    var wrapped=GroupKeyEnvelope.wrap(certificate.group(),Crypto.blake2s(request.identity),request.handshake,material.keyVersion,clock.millis(),key,administratorSecret);
                    List<byte[]> chain=new ArrayList<>();for(var record:material.chain) chain.add(record.encode());
                    var response=new JoinMessages.Response(certificate.group(),chain,anchorSignature,material.revocations.encode(),certificate.encode(),wrapped.encode());
                    ready=sealReply(response,context.id,digest,request.handshake,administratorSecret);outgoing=ready.clone();
                    beforeCommit.accept(key);
                    if(!verifier.consume(request.handshake,code)) throw new SecurityException("招待を使ったことにできません");
                    // ここからは失敗する外の処理や暗号の処理を行わず、準備した結果を確定する。
                    cachedReply=ready;ready=null;cachedFingerprint=digest;digest=null;issuedCertificate=certificate;consumed=true;
                    Crypto.wipe(context.proofKey);Crypto.wipe(anchor);anchor=null;Crypto.wipe(anchorSignature);anchorSignature=null;
                    byte[] result=outgoing;outgoing=null;return result;
                }
            } finally {
                Crypto.wipe(plaintext);Crypto.wipe(digest);Crypto.wipe(key);Crypto.wipe(ready);Crypto.wipe(outgoing);
                if(checked!=null) checked.clear();if(material!=null) material.close();synchronizeLifecycle();
            }
        }
        public synchronized boolean isConsumed() { return consumed; }
        /** expireは呼ばず、現在の閉じた印だけを返す。 */
        public synchronized boolean isClosed() { return closed; }
        /** 登録に使う公開の識別子の写し。秘密の証明にはならない。 */
        public synchronized byte[] invitationId() { return context.id.clone(); }
        /** 確定済みの公開の証明書の写し。未発行・消去後はnull。 */
        public synchronized AdminRecords.Record issuedCertificate() {
            return issuedCertificate==null ? null : AdminRecords.decode(issuedCertificate.encode());
        }
        public synchronized void expire() {
            if(closed) return;
            verifier.expire();synchronizeLifecycle();
        }
        // consume のあとに時計などの外部の処理を呼ばず、既に判定した状態だけを見る。
        private void synchronizeLifecycle() { if(verifier.isClosed() || consumed && !verifier.hasRetransmission()) close(); }
        public synchronized void revoke() { close(); }
        @Override public synchronized void close() {
            closed=true;verifier.close();context.close();Crypto.wipe(anchor);Crypto.wipe(anchorSignature);Crypto.wipe(cachedReply);Crypto.wipe(cachedFingerprint);
            anchor=null;anchorSignature=null;cachedReply=null;cachedFingerprint=null;issuedCertificate=null;
        }
    }
    static byte[] sealReply(JoinMessages.Response response,byte[] invitation,byte[] digest,byte[] recipient,byte[] signingSecret) {
        byte[] info=replyInfo(invitation,digest), plain=response.encode();
        try(var hpke=Hpke.sender(recipient,info)) {
            byte[] ciphertext=hpke.seal(info,plain), enc=hpke.encapsulation();
            var unsigned=new JoinMessages.Packet(true,invitation,enc,ciphertext,new byte[64]);
            byte[] signature=Crypto.sign(signingSecret,signedReply(info,unsigned.signedBytes()));
            return new JoinMessages.Packet(true,invitation,enc,ciphertext,signature).encode();
        } finally { Crypto.wipe(plain); }
    }
    /** 求めは一度だけ作る。送り直す時刻は上位が管理し、retry に同じ求めを最大5回返させる。 */
    public static final class Joiner implements AutoCloseable {
        private final byte[] identity,handshake,handshakeSecret,invitation,administrator,digest;
        private final Clock clock;
        private final byte[] invitationGroup;
        private byte[] requestPacket;
        private boolean started,closed;
        private int retries;
        private byte[] savedGroup;
        private long savedAdministrators,savedRevocations,savedKeyVersion;
        public Joiner(Invitation invitation,byte[] identitySecret,byte[] handshakeSecret,Clock clock) {
            this.clock=Objects.requireNonNull(clock);this.invitationGroup=invitation.groupId();Crypto.length(handshakeSecret,32);Crypto.length(identitySecret,32);
            identity=Crypto.ed25519Public(identitySecret);handshake=Crypto.x25519Public(handshakeSecret);this.handshakeSecret=handshakeSecret.clone();
            byte[] code=null, secret=null, encoded=null;
            try(var context=new Context(invitation)) {
                this.invitation=context.id.clone();administrator=context.administrator.clone();
                secret=invitation.totpSecret();code=Totp.generate(secret,clock.instant()).getBytes(StandardCharsets.US_ASCII);
                byte[] binding=SignaturePurpose.identityProof(identitySecret,invitationGroup,handshake);
                try(var unsigned=new JoinMessages.Request(context.id,identity,handshake,binding,code,new byte[32])) {
                    byte[] proof=proof(context.proofKey,unsigned);
                    byte[] signature=null, signed=null;
                    try {
                        try(var withProof=new JoinMessages.Request(context.id,identity,handshake,binding,code,proof)) {
                            signed=signedRequest(withProof);signature=Crypto.sign(identitySecret,signed);
                        }
                        try(var request=new JoinMessages.Request(context.id,identity,handshake,binding,code,proof,signature)) {
                            encoded=request.encode();digest=Crypto.blake2s(encoded);
                            byte[] info=requestInfo(context.id);
                            try(var hpke=Hpke.sender(context.handshake,info)) {
                                requestPacket=new JoinMessages.Packet(false,context.id,hpke.encapsulation(),hpke.seal(info,encoded),new byte[0]).encode();
                            }
                        }
                    } finally { Crypto.wipe(proof);Crypto.wipe(signature);Crypto.wipe(signed); }
                }
            } catch(RuntimeException e) { Crypto.wipe(this.handshakeSecret);Crypto.wipe(requestPacket);throw e; }
            finally { Crypto.wipe(code);Crypto.wipe(secret);Crypto.wipe(encoded); }
        }
        /** 新しい握手の秘密鍵は呼び出し元が作り、保存が終わるまで保持する。保存した状態は変更しない。 */
        public static Joiner rejoin(Invitation invitation,byte[] identitySecret,byte[] newHandshakeSecret,Clock clock,
                                    AdminState saved,AdminRecords.Record previousCertificate,long keyVersion) {
            if(keyVersion<0) throw new IllegalArgumentException("保存した鍵の版が負です");
            var administrators=saved.administrators();var revoked=saved.revocations();
            if(!administrators.hasEntry(invitation.adminPublicKey())) throw new SecurityException("招待した管理者が保存した一覧にありません");
            saved.verifyCertificate(previousCertificate,previousCertificate.field(1),true);
            if(!Crypto.equal(Crypto.ed25519Public(identitySecret),previousCertificate.field(0))
                    || Crypto.equal(Crypto.x25519Public(newHandshakeSecret),previousCertificate.field(1)))
                throw new SecurityException("入り直す身元か新しい握手の鍵が違います");
            var result=new Joiner(invitation,identitySecret,newHandshakeSecret,clock);
            if(!Crypto.equal(invitation.groupId(),administrators.group())){result.close();throw new SecurityException("招待のグループが違います");}
            result.savedGroup=administrators.group();result.savedAdministrators=administrators.version();
            result.savedRevocations=revoked.version();result.savedKeyVersion=keyVersion;return result;
        }
        public synchronized byte[] request() {
            if(closed || started) throw new IllegalStateException("求めは作成済みか消去済みです");started=true;return requestPacket.clone();
        }
        public synchronized byte[] retry() {
            if(closed || !started || retries>=MAX_RETRIES) throw new IllegalStateException("求めを送り直せません");retries++;return requestPacket.clone();
        }
        /**
         * 検査が全部通ったときだけ状態と鍵を返す。
         * 外側の大きさ・構文・種類・招待ID・署名に通らない入力では状態を変えず、retry と本物の返事を引き続き受けられる。
         * URLの管理者の外側の署名が通った後は、成功でも内側の検査の失敗でも、このJoinerを閉じ秘密の写しを消す。
         * 各試みで作った一時の写しは、外側の検査に通らないときも消す。
         * @throws IllegalArgumentException 外側または内側の形・大きさが違うとき。外側の署名の検査が通る前なら閉じず、通った後なら閉じる。
         * @throws SecurityException 招待ID・署名・暗号・管理記録などの検査に通らないとき。外側の署名の検査が通る前なら閉じず、通った後なら閉じる。
         * @throws IllegalStateException 求めを出す前や、既に閉じた後に呼んだとき。
         */
        public synchronized Joined receive(byte[] reply) {
            if(closed || !started) throw new IllegalStateException("求めを出していません");
            byte[] plain=null,info=null,prefix=null,signed=null;AdminState checked=null;GroupKeyEnvelope.OpenedKey opened=null;
            boolean authenticated=false;
            try(var envelope=JoinMessages.packet(reply,true)) {
                if(!Crypto.equal(envelope.invitation,invitation)) throw new SecurityException("招待した管理者の返事ではありません");
                info=replyInfo(invitation,digest);prefix=envelope.signedBytes();signed=signedReply(info,prefix);
                if(!Crypto.verify(administrator,signed,envelope.signature)) throw new SecurityException("招待した管理者の返事ではありません");
                authenticated=true;
                try(var hpke=Hpke.recipient(handshakeSecret,envelope.enc,info)) { plain=hpke.open(info,envelope.ciphertext); }
                var response=JoinMessages.response(plain);List<AdminRecords.Record> chain=new ArrayList<>();
                for(byte[] record:response.chain) chain.add(AdminRecords.decode(record));
                checked=new AdminState(response.group,administrator,clock,new InMemoryAdminRecordStore());
                checked.join(chain,response.anchor,AdminRecords.decode(response.revocations));
                if(!Crypto.equal(invitationGroup,response.group))throw new SecurityException("招待と返事のグループが違います");
                if(savedGroup!=null && (!Crypto.equal(savedGroup,response.group)
                        || checked.administrators().version()<savedAdministrators || checked.revocations().version()<savedRevocations))
                    throw new SecurityException("入り直しの返事が保存したグループと合いません");
                var certificate=AdminRecords.decode(response.certificate);
                checked.verifyCertificate(certificate,handshake);
                if(!Crypto.equal(certificate.field(0),identity) || !Crypto.equal(certificate.field(1),handshake)) throw new SecurityException("自分あての証明書ではありません");
                var wrapped=AdminRecords.decode(response.wrapped);
                if(savedGroup!=null) {
                    if(wrapped.version()<savedKeyVersion) throw new SecurityException("入り直しの鍵の版が古すぎます");
                    opened=checked.openRejoinedGroupKey(wrapped,Crypto.blake2s(identity),handshakeSecret,savedKeyVersion);
                } else opened=checked.openGroupKey(wrapped,Crypto.blake2s(identity),handshakeSecret,-1);
                var joined=new Joined(checked,certificate,opened,wrapped.version());checked=null;opened=null;return joined;
            } finally {
                Crypto.wipe(plain);Crypto.wipe(info);Crypto.wipe(prefix);Crypto.wipe(signed);
                if(opened!=null) opened.close();if(checked!=null) checked.clear();if(authenticated) close();
            }
        }
        public synchronized boolean isClosed() { return closed; }
        @Override public synchronized void close() { closed=true;Crypto.wipe(handshakeSecret);Crypto.wipe(requestPacket);requestPacket=null; }
    }
    /** 完全に検査した加入結果。groupKey の写しは呼び出し元が消す。 */
    public static final class Joined implements AutoCloseable {
        private final AdminState state;
        private final AdminRecords.Record certificate;
        private final GroupKeyEnvelope.OpenedKey key;
        private final long keyVersion;
        private boolean closed;
        private Joined(AdminState state,AdminRecords.Record certificate,GroupKeyEnvelope.OpenedKey key,long keyVersion) {
            this.state=state;this.certificate=certificate;this.key=key;this.keyVersion=keyVersion;
        }
        private void usable() { if(closed) throw new IllegalStateException("加入の結果は消去済みです"); }
        /** 写しではなく所有する同じ状態を返す。Joined.close()すると、既に返した参照の中身も空になる。 */
        public synchronized AdminState state() { usable();return state; }
        public synchronized AdminRecords.Record certificate() { usable();return certificate; }
        public synchronized byte[] groupKey() { usable();return key.copy(); }
        /** 検査を通った包んだグループの鍵の版。次の鍵を開くときの現在版として使う。 */
        public synchronized long groupKeyVersion() { usable();return keyVersion; }
        /** 鍵を0にし、state()で返した同じ状態の中身も空にする。 */
        @Override public synchronized void close() { closed=true;key.close();state.clear(); }
    }
}
