// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class RenewalMessageTest {
    final byte[] group=new byte[32],secret=new byte[32],handshake=Crypto.x25519Public(secret),id=new byte[16];
    AdminRecords.Record base(){return AdminRecords.certificate(group,Crypto.ed25519Public(secret),handshake,
        SignaturePurpose.identityProof(secret,group,handshake),100,secret);}
    RenewalMessage request(){return RenewalMessage.request(base(),id,Crypto.ed25519Public(secret),RenewalMessage.Reason.AUTO_RENEWAL,null);}
    @Test void threeOperationsRoundTripInsideTheFinalEnvelope() {
        var request=request();var reply=RenewalMessage.reply(request,secret);var delivery=RenewalMessage.delivery(request,base().encode());
        for(var message:new RenewalMessage[]{request,reply,delivery}) {
            byte[] wire=message.encode();assertTrue(wire.length<=1176);
            assertTrue(RenewalMessage.isManagement(wire));assertTrue(java.util.Arrays.equals(wire,RenewalMessage.decode(wire).encode()));
        }
        assertTrue(request.sameRequest(reply));assertTrue(request.sameRequest(delivery));
    }
    @Test void schemaOneTwoAndReservedBodyAreNeverAccepted() {
        byte[] wire=request().encode();wire[1]=1;assertThrows(IllegalArgumentException.class,()->RenewalMessage.decode(wire));
        wire[1]=2;assertThrows(IllegalArgumentException.class,()->RenewalMessage.decode(wire));
        assertThrows(IllegalArgumentException.class,()->RenewalMessage.decode(new byte[]{8,3,82,4,8,1,50,0}));
    }
    @Test void unknownAndDuplicateFieldsAreRejected() {
        byte[] wire=request().encode();
        assertThrows(IllegalArgumentException.class,()->RenewalMessage.decode(Crypto.concat(wire,new byte[]{8,3})));
        assertThrows(IllegalArgumentException.class,()->RenewalMessage.decode(Crypto.concat(wire,new byte[]{88,1})));
    }
    @Test void finalEnvelopeLimitAndCertificateLimitAreEnforced() {
        assertThrows(IllegalArgumentException.class,()->RenewalMessage.delivery(request(),new byte[1025]));
        assertThrows(IllegalArgumentException.class,()->RenewalMessage.decode(new byte[1177]));
    }
    @Test void removalNeedsOperationIdAndAutoForbidsIt() {
        assertThrows(IllegalArgumentException.class,()->RenewalMessage.request(base(),id,Crypto.ed25519Public(secret),RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,null));
        assertThrows(IllegalArgumentException.class,()->RenewalMessage.request(base(),id,Crypto.ed25519Public(secret),RenewalMessage.Reason.AUTO_RENEWAL,id));
        assertNotNull(RenewalMessage.request(base(),id,Crypto.ed25519Public(secret),RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,id));
    }
}
