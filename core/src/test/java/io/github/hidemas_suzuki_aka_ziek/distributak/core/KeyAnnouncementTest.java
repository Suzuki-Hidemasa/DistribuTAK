// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class KeyAnnouncementTest {
    static byte[] value(int n){byte[] b=new byte[32];Arrays.fill(b,(byte)n);return b;}
    static KeyAnnouncement announcement(long version,long time) {
        return KeyAnnouncement.issue(value(1),value(2),version,time,3,value(4),value(5),6,value(7));
    }
    @Test void signedAnnouncementRoundTripsAndChecksAuthority() {
        var record=announcement(8,100);
        var decoded=KeyAnnouncement.decode(record.encode());
        decoded.verify(value(1),List.of(Crypto.ed25519Public(value(2))));
        assertEquals(8,decoded.keyVersion());assertEquals(100,decoded.signedAt());
        assertEquals(3,decoded.revocationVersion());assertEquals(6,decoded.adminVersion());
        assertArrayEquals(value(4),decoded.revocationDigest());assertArrayEquals(value(5),decoded.keyCommitment());
        assertArrayEquals(record.encode(),decoded.encode());
        assertThrows(SecurityException.class,()->decoded.verify(value(9),List.of(decoded.signer())));
        assertThrows(SecurityException.class,()->decoded.verify(value(1),List.of(value(9))));
    }
    @Test void commitmentBindsTheDomainGroupVersionAndKey() {
        byte[] expected=Crypto.blake2s(Crypto.concat("DistribuTAK/key-commitment/v1\0".getBytes(StandardCharsets.US_ASCII),
                value(1),ByteBuffer.allocate(8).putLong(8).array(),value(3)));
        assertTrue(Crypto.equal(expected,KeyAnnouncement.commitment(value(1),8,value(3))));
        assertFalse(Crypto.equal(expected,KeyAnnouncement.commitment(value(2),8,value(3))));
        assertFalse(Crypto.equal(expected,KeyAnnouncement.commitment(value(1),9,value(3))));
        assertFalse(Crypto.equal(expected,KeyAnnouncement.commitment(value(1),8,value(4))));
    }
    @Test void rankUsesVersionThenTimeThenPayload() {
        assertTrue(KeyAnnouncement.compare(announcement(9,1),announcement(8,100))>0);
        assertTrue(KeyAnnouncement.compare(announcement(8,101),announcement(8,100))>0);
        var other=KeyAnnouncement.issue(value(1),value(2),8,100,3,value(4),value(8),6,value(7));
        assertEquals(Integer.signum(AdminRecords.compareBytes(other.signedBytes(),announcement(8,100).signedBytes())),
                Integer.signum(KeyAnnouncement.compare(other,announcement(8,100))));
    }
    @Test void malformedOrNoncanonicalAnnouncementsAreRefused() {
        byte[] wire=announcement(8,100).encode();
        assertThrows(IllegalArgumentException.class,()->KeyAnnouncement.decode(Arrays.copyOf(wire,wire.length-1)));
        assertThrows(IllegalArgumentException.class,()->KeyAnnouncement.decode(Crypto.concat(wire,new byte[]{24,0})));
        assertThrows(IllegalArgumentException.class,()->KeyAnnouncement.issue(value(1),value(2),-1,100,3,value(4),value(5),6,value(7)));
        assertThrows(IllegalArgumentException.class,()->KeyAnnouncement.commitment(value(1),8,new byte[31]));
    }
    @Test void signatureAndPurposeAreChecked() {
        var record=announcement(8,100);
        byte[] wire=record.encode();wire[wire.length-1]^=1;
        var decoded=KeyAnnouncement.decode(wire);
        assertThrows(SecurityException.class,()->decoded.verify(value(1),List.of(decoded.signer())));
        assertFalse(SignaturePurpose.WRAPPED_KEY.verify(record.signer(),record.signedBytes(),record.signature()));
    }
    @Test void returnedArraysCannotChangeTheRecord() {
        var record=announcement(8,100);byte[] before=record.encode();
        record.group()[0]^=1;record.keyCommitment()[0]^=1;record.revocationDigest()[0]^=1;
        record.adminDigest()[0]^=1;record.signer()[0]^=1;record.signedBytes()[0]^=1;
        assertArrayEquals(before,record.encode());
    }
    @Test void formatTwoWrappedKeyBindsAnnouncementAndPreservesHpke() {
        byte[] identity=value(8),handshake=value(9),key=value(10),recipient=Crypto.blake2s(Crypto.ed25519Public(identity));
        var wrapped=GroupKeyEnvelope.wrap(value(1),recipient,Crypto.x25519Public(handshake),8,100,key,value(2),value(4));
        var decoded=AdminRecords.decode(wrapped.encode());
        assertEquals(2,decoded.format());assertTrue(decoded.hasValidSignature());
        assertArrayEquals(value(4),decoded.field(4));
        assertTrue(SignaturePurpose.WRAPPED_KEY.verify(decoded.signer(),decoded.signedBytes(),decoded.signature()));
        try(var opened=GroupKeyEnvelope.open(decoded,recipient,handshake,7)){
            assertTrue(Crypto.equal(key,opened.copy()));
        }
        var legacy=GroupKeyEnvelope.wrap(value(1),recipient,Crypto.x25519Public(handshake),8,100,key,value(2));
        assertEquals(1,AdminRecords.decode(legacy.encode()).format());
        assertTrue(legacy.hasValidSignature());
    }
    @Test void offlineMemberFetchesAndOpensTheKeyHeldByAnOrdinaryThirdParty() {
        long now=1_000_000;byte[] group=value(1),administrator=value(2),identity=value(3),handshake=value(4),key=value(5);
        var clock=Clock.fixed(Instant.ofEpochMilli(now),ZoneOffset.UTC);
        var state=new AdminState(group,Crypto.ed25519Public(administrator),clock,new InMemoryAdminRecordStore());
        var admins=AdminProofFixtures.list(group,0,now,List.of(Crypto.ed25519Public(administrator)),administrator,administrator);
        state.bootstrap(admins,AdminRecords.signAnchor(admins,administrator));
        byte[] adminDigest=Crypto.blake2s(admins.signedBytes()),recipient=Crypto.blake2s(Crypto.ed25519Public(identity));
        var rev=AdminRecords.initialRevocations(group,now,administrator);
        var announcement=KeyAnnouncement.issue(group,administrator,1,now,0,Crypto.blake2s(rev.signedBytes()),
                KeyAnnouncement.commitment(group,1,key),0,adminDigest);
        var certificate=AdminRecords.certificate(group,Crypto.ed25519Public(identity),Crypto.x25519Public(handshake),
                SignaturePurpose.identityProof(identity,group,Crypto.x25519Public(handshake)),now,administrator);
        var wrapped=GroupKeyEnvelope.wrap(group,recipient,certificate.field(1),1,now,key,administrator,Crypto.blake2s(announcement.signedBytes()));
        var outer=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,group,administrator,wrapped,1,0,adminDigest,now,certificate.encode());
        var trust=new AdminStateTrust(state);var union=new RevocationUnion(group,trust);
        var verifier=new ManagedVerifier(trust,clock,union,new ManagedDependencies(){
            public KeyAnnouncement announcement(byte[] digest){return announcement;}
            public AdminRecords.Record revocations(long version,byte[] digest){return rev;}
        });
        var atC=ManagedDhtRecord.verifyStructure(outer.encode(),group);
        assertEquals(ManagedVerdict.Status.ACCEPTED,verifier.judge(atC,null).status());
        var storageAtC=new java.util.HashMap<DhtId,byte[]>();storageAtC.put(atC.key(),atC.encode());
        var fetchedByM=ManagedDhtRecord.verifyStructure(storageAtC.get(DhtKeys.derive(group,DhtKeys.WRAPPED_KEY,recipient)),group);
        assertEquals(ManagedVerdict.Status.ACCEPTED,verifier.judge(fetchedByM,null).status());
        try(var opened=GroupKeyEnvelope.open(fetchedByM.inner(),recipient,handshake,0)){
            byte[] received=opened.copy();
            try{assertTrue(Crypto.equal(key,received));assertTrue(Crypto.equal(announcement.keyCommitment(),KeyAnnouncement.commitment(group,1,received)));}
            finally{Crypto.wipe(received);}
        }
        assertEquals(1,state.snapshot().records().size());
    }
}
