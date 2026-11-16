// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import java.nio.charset.StandardCharsets;

/**
 * DHT の記録鍵。種類 1 は発見、種類 2〜6 は管理用（04 §4.5）。
 * <p>
 * DHT record keys. Kind 1 is discovery; kinds 2-6 are management records (04 §4.5).
 */
public final class DhtKeys {
    /** 発見の記録。宛先は端末番号。 / Discovery record; the subject is the node identifier. */
    public static final int MEMBER_DISCOVERY=1;
    /** 最新の管理者の一覧。宛先は 32 バイトの 0。 / Latest administrator list; the subject is 32 zero bytes. */
    public static final int LATEST_ADMINS=2;
    /** 最新の失効の一覧。宛先は 32 バイトの 0。 / Latest revocation list; the subject is 32 zero bytes. */
    public static final int LATEST_REVOCATIONS=3;
    /** 受け手あての、包まれた鍵。宛先は受け手の識別子。 / Wrapped key for a recipient; the subject is the recipient identifier. */
    public static final int WRAPPED_KEY=4;
    /** 指定した版の管理者の一覧。宛先は版から決める。 / Administrator list at a given version; the subject comes from the version. */
    public static final int ADMIN_HISTORY=5;
    /** 最新の鍵の告知。宛先は 32 バイトの 0。 / Latest key announcement; the subject is 32 zero bytes. */
    public static final int KEY_ANNOUNCEMENT=6;
    private static final byte[] DOMAIN="DistribuTAK/dht-key/v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] HISTORY_DOMAIN="DistribuTAK/admin-history/v1".getBytes(StandardCharsets.US_ASCII);
    private DhtKeys(){}
    /**
     * 記録鍵を求める。種類 2・3・6 の宛先は 32 バイトの 0 だけを受け付ける。
     * <p>
     * Derives a record key. Kinds 2, 3 and 6 accept only the 32-zero-byte subject.
     */
    public static DhtId derive(byte[] groupId,int kind,byte[] subject) {
        if(groupId==null||groupId.length!=32||kind<MEMBER_DISCOVERY||kind>KEY_ANNOUNCEMENT||subject==null||subject.length!=32)
            throw new IllegalArgumentException("DHTの記録鍵の項目が違います");
        if(kind==LATEST_ADMINS||kind==LATEST_REVOCATIONS||kind==KEY_ANNOUNCEMENT)
            for(byte value:subject)if(value!=0)throw new IllegalArgumentException("DHTの記録鍵の宛先が違います");
        return hash(groupId,(byte)kind,subject);
    }
    /**
     * 種類 5 の宛先。固定の前置きと、版を 8 バイトの大きい順で並べた値の BLAKE2s。
     * <p>
     * Subject for kind 5: BLAKE2s of the fixed prefix and the version as 8 big-endian bytes.
     */
    public static byte[] adminHistorySubject(long version) {
        if(version<0)throw new IllegalArgumentException("版が負です");
        byte[] number=new byte[8];
        for(int i=0;i<8;i++)number[i]=(byte)(version>>>(56-8*i));
        return Crypto.blake2s(Crypto.concat(HISTORY_DOMAIN,number));
    }
    static DhtId hash(byte[] groupId,byte kind,byte[] subject) {
        return new DhtId(Crypto.blake2s(Crypto.concat(DOMAIN,groupId,new byte[]{kind},subject)));
    }
}
