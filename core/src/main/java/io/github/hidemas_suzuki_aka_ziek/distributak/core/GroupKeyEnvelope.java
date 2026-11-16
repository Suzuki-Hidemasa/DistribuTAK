// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/** 管理者が署名する HPKE の包み。info/aad の並べ方は第3段の案。 */
public final class GroupKeyEnvelope {
    private static final byte[] DOMAIN="DistribuTAK/group-key/v1".getBytes(StandardCharsets.US_ASCII);
    private GroupKeyEnvelope() {}
    private static byte[] info(byte[] group) { return Crypto.concat(DOMAIN,group); }
    private static byte[] aad(byte[] group, byte[] recipient, byte[] handshake, long version, byte[] signer) {
        return Crypto.concat(info(group),recipient,handshake,ByteBuffer.allocate(8).putLong(version).array(),signer);
    }
    /** 引数の秘密配列は呼び出し元が所有する。内部の写しは成功・失敗とも消す。 */
    public static AdminRecords.Record wrap(byte[] group, byte[] recipient, byte[] handshake, long version,
                                            long signedAt, byte[] groupKey, byte[] adminSecret) {
        return wrap(group,recipient,handshake,version,signedAt,groupKey,adminSecret,null);
    }
    /** 告知の digest を署名に含めた形式 2 を作る。HPKE の入力は変えない。
     * <p>
     * Creates format 2 with the announcement digest in the signature. HPKE inputs are unchanged.
     */
    public static AdminRecords.Record wrap(byte[] group,byte[] recipient,byte[] handshake,long version,
                                            long signedAt,byte[] groupKey,byte[] adminSecret,byte[] announcementDigest) {
        Crypto.length(group,32);Crypto.length(recipient,32);Crypto.length(handshake,32);Crypto.length(groupKey,32);
        if(version<0 || signedAt<0) throw new IllegalArgumentException("版か時刻が負です");
        byte[] key=groupKey.clone();
        try(var sender=Hpke.sender(handshake,info(group))) {
            byte[] cipher=sender.seal(aad(group,recipient,handshake,version,Crypto.ed25519Public(adminSecret)),key);
            return announcementDigest==null
                    ?AdminRecords.wrapped(group,version,signedAt,recipient,handshake,sender.encapsulation(),cipher,adminSecret)
                    :AdminRecords.wrapped(group,version,signedAt,recipient,handshake,sender.encapsulation(),cipher,adminSecret,announcementDigest);
        } finally { Crypto.wipe(key); }
    }
    /** currentVersion は信頼できる手元の現在版。-1 は鍵を1度も持っていないときだけ渡す。 */
    static OpenedKey open(AdminRecords.Record record, byte[] recipient, byte[] handshakeSecret, long currentVersion) {
        return open(record,recipient,handshakeSecret,currentVersion,false);
    }
    static OpenedKey open(AdminRecords.Record record,byte[] recipient,byte[] handshakeSecret,long currentVersion,boolean rejoining) {
        if(record.kind()!=AdminRecords.Kind.WRAPPED_KEY || !Crypto.equal(record.field(0),recipient)
                || !Crypto.equal(record.field(1),Crypto.x25519Public(handshakeSecret)) || currentVersion< -1
                || (rejoining ? currentVersion<0 || record.version()<currentVersion : record.version()<=currentVersion)) throw new SecurityException("包んだ鍵の受け手か版が違います");
        byte[] plain=null;
        try(var context=Hpke.recipient(handshakeSecret,record.field(2),info(record.group()))) {
            plain=context.open(aad(record.group(),recipient,record.field(1),record.version(),record.signer()),record.field(3));
            Crypto.length(plain,32);return new OpenedKey(plain);
        } finally { Crypto.wipe(plain); }
    }
    /** copy の写しは呼び出し元が消す。保持する鍵は close で消す。 */
    public static final class OpenedKey implements AutoCloseable {
        private final byte[] value;
        private boolean closed;
        private OpenedKey(byte[] value) { this.value=value.clone(); }
        public synchronized byte[] copy() { if(closed) throw new IllegalStateException("鍵は消去済みです");return value.clone(); }
        @Override public synchronized void close() { closed=true;Crypto.wipe(value); }
    }
}
