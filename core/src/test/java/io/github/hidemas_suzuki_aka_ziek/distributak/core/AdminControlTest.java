// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class AdminControlTest {
    final byte[] group=new byte[32],id=new byte[16],identity=AdminRecordsTest.key(1),admin=AdminRecordsTest.key(2);
    AdminControl request(){return AdminControl.request(group,id,0,identity,admin);}
    @Test void requestAndKeyProofUseBothDomainsAndBindIdentity() {
        for(var c:new AdminControl[]{request(),AdminControl.keyProof(group,id,0,identity,admin)}) {
            assertTrue(c.verifyPossessionProof());assertFalse(Crypto.verify(c.identityKey(),c.unsignedBytes(),c.identitySignature()));
            assertFalse(Crypto.verify(c.administratorKey(),c.unsignedBytes(),c.possessionSignature()));
            assertTrue(Crypto.equal(c.memberId(),Crypto.blake2s(Crypto.ed25519Public(identity))));
        }
    }
    @Test void offerIsSignedOnlyByCurrentAdministratorKey() {
        var offer=AdminControl.offer(group,id,new byte[32],0,admin);
        assertTrue(offer.verifyOffer());assertFalse(offer.verifyPossessionProof());assertNull(offer.identityKey());assertNull(offer.identitySignature());
    }
    @Test void noticesHaveNoSignaturesAndCannotBeBindingProofs() {
        for(var c:new AdminControl[]{AdminControl.approved(request(),1),AdminControl.rejected(request())}) {
            assertNull(c.identityKey());assertNull(c.identitySignature());assertNull(c.possessionSignature());assertFalse(c.verifyPossessionProof());
            assertTrue(java.util.Arrays.equals(c.encode(),AdminControl.decode(c.encode()).encode()));
        }
    }
    @Test void allOperationsRoundTripInsideSchemaThreeBodyEight() {
        for(var c:new AdminControl[]{request(),AdminControl.offer(group,id,new byte[32],0,admin),
                AdminControl.keyProof(group,id,0,identity,admin),AdminControl.approved(request(),1),AdminControl.rejected(request())}) {
            byte[] wire=c.envelope();assertTrue(wire.length<=1176);assertTrue(AdminControl.isEnvelope(wire));
            assertTrue(java.util.Arrays.equals(c.encode(),AdminControl.fromEnvelope(wire).encode()));
            assertThrows(IllegalArgumentException.class,()->RenewalMessage.decode(wire));
        }
    }
    @Test void noticesAndOfferRejectPresenceOfProhibitedIdentityFields() {
        var notice=AdminControl.approved(request(),1);
        assertThrows(IllegalArgumentException.class,()->AdminControl.decode(Crypto.concat(notice.encode(),new byte[]{66,0})));
        var offer=AdminControl.offer(group,id,new byte[32],0,admin);
        assertThrows(IllegalArgumentException.class,()->AdminControl.decode(Crypto.concat(offer.encode(),new byte[]{82,0})));
    }
    @Test void wrongIdentityAndSignatureDoNotBecomePossessionProof() {
        byte[] bytes=request().encode();bytes[bytes.length-1]^=1;assertFalse(AdminControl.decode(bytes).verifyPossessionProof());
        bytes=request().encode();bytes[bytes.length-40]^=1;assertFalse(AdminControl.decode(bytes).verifyPossessionProof());
    }
    @Test void unknownOperationSchemaDuplicateAndNoncanonicalAreRejected() {
        byte[] wire=request().encode(),schema=wire.clone();schema[1]=2;
        assertThrows(IllegalArgumentException.class,()->AdminControl.decode(schema));
        int at=2+34+18;byte[] operation=wire.clone();operation[at+1]=0;
        assertThrows(IllegalArgumentException.class,()->AdminControl.decode(operation));
        assertThrows(IllegalArgumentException.class,()->AdminControl.decode(Crypto.concat(wire,new byte[]{88,0})));
        assertThrows(IllegalArgumentException.class,()->AdminControl.decode(Crypto.concat(wire,new byte[]{8,1})));
        assertThrows(IllegalArgumentException.class,()->AdminControl.decode(Crypto.concat(new byte[]{8,(byte)129,0},java.util.Arrays.copyOfRange(wire,2,wire.length))));
    }
    @Test void envelopeLimitAndVersionOverflowAreRejected() {
        assertThrows(IllegalArgumentException.class,()->AdminControl.fromEnvelope(new byte[1177]));
        assertThrows(IllegalArgumentException.class,()->AdminControl.request(group,id,-1,identity,admin));
        assertThrows(IllegalArgumentException.class,()->AdminControl.approved(request(),0));
    }
}
