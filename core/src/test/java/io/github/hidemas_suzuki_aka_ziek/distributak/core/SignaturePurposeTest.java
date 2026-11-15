// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SignaturePurposeTest {
    private final byte[] secret=new byte[32],payload=new byte[]{1,2,3};
    @Test void everyDomainHasExactPrefixAndTrailingNul() {
        String[] names={"identity-binding/v2","certificate/v2","administrators/v2","revocations/v2","wrapped-key/v2",
            "member-discovery/v2","dht-management/v1","admin-request/v1","admin-key-proof/v1","key-rotation/v1"};
        var purposes=SignaturePurpose.values();assertEquals(names.length,purposes.length);
        for(int i=0;i<names.length;i++) {
            byte[] expected=Crypto.concat(("DistribuTAK/"+names[i]+"\0").getBytes(StandardCharsets.US_ASCII),payload);
            assertTrue(Crypto.equal(Crypto.sign(secret,expected),purposes[i].sign(secret,payload)));
            assertTrue(purposes[i].verify(Crypto.ed25519Public(secret),payload,purposes[i].sign(secret,payload)));
        }
    }
    @Test void signatureCannotCrossAnyPurposeOrFallBackToRaw() {
        for(var purpose:SignaturePurpose.values()) {
            byte[] signature=purpose.sign(secret,payload);
            assertFalse(Crypto.verify(Crypto.ed25519Public(secret),payload,signature));
            assertFalse(purpose.verify(Crypto.ed25519Public(secret),payload,Crypto.sign(secret,payload)));
            for(var other:SignaturePurpose.values())if(other!=purpose)
                assertFalse(other.verify(Crypto.ed25519Public(secret),payload,signature));
        }
    }
    @Test void identityProofBindsGroupIdentityAndHandshake() {
        byte[] group=new byte[32],handshake=new byte[32],identity=Crypto.ed25519Public(secret);
        byte[] proof=SignaturePurpose.identityProof(secret,group,handshake);
        assertTrue(SignaturePurpose.verifyIdentity(group,identity,handshake,proof));
        group[0]=1;assertFalse(SignaturePurpose.verifyIdentity(group,identity,handshake,proof));group[0]=0;
        handshake[0]=1;assertFalse(SignaturePurpose.verifyIdentity(group,identity,handshake,proof));
    }
    @Test void rawCryptoStillSignsExactInput() {
        byte[] signature=Crypto.sign(secret,payload);
        assertTrue(Crypto.verify(Crypto.ed25519Public(secret),payload,signature));
        assertFalse(Crypto.verify(Crypto.ed25519Public(secret),Crypto.concat(payload,new byte[]{0}),signature));
    }
}
