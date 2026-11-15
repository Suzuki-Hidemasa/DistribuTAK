// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import java.nio.charset.StandardCharsets;

/** 第12段で公開する記録の種類は発見だけ。管理の種類は第13段で決める。 */
public final class DhtKeys {
    public static final int MEMBER_DISCOVERY=1;
    private static final byte[] DOMAIN="DistribuTAK/dht-key/v1".getBytes(StandardCharsets.US_ASCII);
    private DhtKeys(){}
    public static DhtId derive(byte[] groupId,int kind,byte[] subject) {
        if(groupId==null||groupId.length!=32||kind!=MEMBER_DISCOVERY||subject==null||subject.length!=32)
            throw new IllegalArgumentException("DHTの記録鍵の項目が違います");
        return hash(groupId,(byte)kind,subject);
    }
    static DhtId hash(byte[] groupId,byte kind,byte[] subject) {
        return new DhtId(Crypto.blake2s(Crypto.concat(DOMAIN,groupId,new byte[]{kind},subject)));
    }
}
