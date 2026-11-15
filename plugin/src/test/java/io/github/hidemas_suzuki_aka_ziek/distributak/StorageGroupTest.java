// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.time.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;
public class StorageGroupTest {
    static final long NOW=10_000_000_000L;
    static final Clock CLOCK=Clock.fixed(Instant.ofEpochMilli(NOW),ZoneOffset.UTC);
    static byte[] fixture(int version,String state)throws Exception {
        try(var in=StorageGroupTest.class.getResourceAsStream("/legacy-state/v"+version+"-"+state+".base64")){return Base64.getMimeDecoder().decode(in.readAllBytes());}
    }
    @Test public void legacyVersionsValidAndExpiredMigrateWithoutChangingIdentityOrCertificate()throws Exception {
        for(int version:new int[]{2,3})for(String status:List.of("valid","expired")) {
            byte[] wire=fixture(version,status);assertEquals(version,ByteBuffer.wrap(wire).getInt());
            try(var group=LanGroup.decode(wire,CLOCK,true)) {
                assertEquals(0,group.saveSeq);assertEquals(0,group.renewalCount);
                byte[] current=group.encode();assertEquals(5,ByteBuffer.wrap(current).getInt());
                try(var restored=LanGroup.decode(current,CLOCK,true)) {
                    assertArrayEquals(group.groupId,restored.groupId);assertArrayEquals(group.identitySecret,restored.identitySecret);
                    assertArrayEquals(group.certificate.encode(),restored.certificate.encode());
                }
                if(status.equals("expired")) {
                    assertEquals(UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED,group.localCertificateReason());
                    assertThrows(SecurityException.class,()->LanGroup.decode(wire,CLOCK,false));
                    assertThrows(SecurityException.class,()->group.sessions(CLOCK,()->0));
                }
            }
        }
    }
    @Test public void versionFourPreservesCountersAndRejectsNegativeValues()throws Exception {
        try(var group=LanGroup.create(54321,CLOCK,new SecureRandom())) {
            group.saveSeq=7;group.renewalCount=3;
            try(var restored=LanGroup.decode(group.encode(),CLOCK,false)){assertEquals(7,restored.saveSeq);assertEquals(3,restored.renewalCount);}
            group.saveSeq=-1;assertThrows(Exception.class,group::encode);group.saveSeq=7;
            group.renewalCount=-1;assertThrows(Exception.class,group::encode);
        }
    }
    @Test public void expiredReadingNeverAllowsRevocationBadSignatureOrClockFailure()throws Exception {
        byte[] wire=fixture(3,"expired");
        try(var group=LanGroup.decode(wire,CLOCK,true)) {
            group.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group.groupId,1,NOW,List.of(group.id()),group.administratorSecret));
            assertThrows(SecurityException.class,group::encode);
        }
        assertThrows(Exception.class,()->LanGroup.decode(wire,Clock.fixed(Instant.ofEpochMilli(-1),ZoneOffset.UTC),true));
        var before=Clock.fixed(Instant.ofEpochMilli(NOW-AdminRecords.CERTIFICATE_LIFETIME_MILLIS-300_001),ZoneOffset.UTC);
        assertThrows(Exception.class,()->LanGroup.decode(wire,before,true));
        try(var group=LanGroup.create(54321,CLOCK,new SecureRandom())) {
            byte[] bad=group.certificate.encode();bad[bad.length-1]^=1;group.certificate=AdminRecords.decode(bad);
            assertThrows(SecurityException.class,group::encode);
        }
    }
    @Test public void revokedOwnIdentityIsRejectedWhenReadingAuthenticatedRecords()throws Exception {
        byte[] wire=fixture(3,"valid");
        try(var group=LanGroup.decode(wire,CLOCK,true)) {
            group.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group.groupId,1,NOW,List.of(group.id()),group.administratorSecret));
            var input=new java.io.DataInputStream(new java.io.ByteArrayInputStream(wire));input.readInt();input.readInt();
            for(int n=0;n<4;n++)input.skipBytes(input.readInt());input.readLong();
            for(int n=0;n<3;n++)input.skipBytes(input.readInt());
            var buffer=new java.io.ByteArrayOutputStream();var output=new java.io.DataOutputStream(buffer);
            output.write(wire,0,wire.length-input.available());var snapshot=group.state.snapshot();output.writeInt(snapshot.records().size());
            for(byte[] record:snapshot.records()){output.writeInt(record.length);output.write(record);}
            for(byte[] bytes:List.of(snapshot.anchorSignature(),snapshot.revocations())){output.writeInt(bytes.length);output.write(bytes);}
            output.writeLong(snapshot.administratorVersion());output.writeLong(snapshot.revocationVersion());
            output.writeBoolean(false);output.writeBoolean(false);output.writeBoolean(false);output.flush();
            assertThrows(SecurityException.class,()->LanGroup.decode(buffer.toByteArray(),CLOCK,true));
        }
    }
    @Test public void expiredPeerKeepsItsSlotButIsNotRememberedBySessions()throws Exception {
        try(var group=LanGroup.create(54321,CLOCK,new SecureRandom())) {
            byte[] identity=new byte[32],handshake=new byte[32];Arrays.fill(identity,(byte)71);Arrays.fill(handshake,(byte)72);
            byte[] pub=Crypto.x25519Public(handshake);
            group.peerCertificate=AdminRecords.certificate(group.groupId,Crypto.ed25519Public(identity),pub,SignaturePurpose.identityProof(identity,group.groupId,pub),NOW-AdminRecords.CERTIFICATE_LIFETIME_MILLIS,group.administratorSecret);
            group.peerAddress=new java.net.InetSocketAddress("192.168.1.10",54322);
            try(var restored=LanGroup.decode(group.encode(),CLOCK,true);var sessions=restored.sessions(CLOCK,()->0)) {
                assertNotNull(restored.peerCertificate);assertNull(sessions.peerCertificate(Crypto.blake2s(restored.peerCertificate.field(0))));
            }
        }
    }
}
