// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.charset.StandardCharsets;

/** 期待する用途は呼び出し元が選ぶ。入力の purpose から署名方式を選ばない。 */
public enum SignaturePurpose {
    IDENTITY_BINDING("identity-binding/v2"), CERTIFICATE("certificate/v2"),
    ADMINISTRATORS("administrators/v2"), REVOCATIONS("revocations/v2"), WRAPPED_KEY("wrapped-key/v2"),
    MEMBER_DISCOVERY("member-discovery/v2"), DHT_MANAGEMENT("dht-management/v1"),
    ADMIN_REQUEST("admin-request/v1"), ADMIN_KEY_PROOF("admin-key-proof/v1"), KEY_ROTATION("key-rotation/v1");
    private final byte[] purpose,domain;
    SignaturePurpose(String name) {
        purpose=("DistribuTAK/"+name).getBytes(StandardCharsets.US_ASCII);
        domain=Crypto.concat(purpose,new byte[]{0});
    }
    public byte[] purpose(){return purpose.clone();}
    public byte[] sign(byte[] secret,byte[] payload){return Crypto.sign(secret,Crypto.concat(domain,payload));}
    public boolean verify(byte[] key,byte[] payload,byte[] signature){return Crypto.verify(key,Crypto.concat(domain,payload),signature);}
    public static byte[] identityProof(byte[] secret,byte[] group,byte[] handshake) {
        Crypto.length(group,32);Crypto.length(handshake,32);
        return IDENTITY_BINDING.sign(secret,Crypto.concat(group,Crypto.ed25519Public(secret),handshake));
    }
    public static boolean verifyIdentity(byte[] group,byte[] identity,byte[] handshake,byte[] proof) {
        Crypto.length(group,32);Crypto.length(identity,32);Crypto.length(handshake,32);Crypto.length(proof,64);
        return IDENTITY_BINDING.verify(identity,Crypto.concat(group,identity,handshake),proof);
    }
}
