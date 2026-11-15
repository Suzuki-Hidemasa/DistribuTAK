// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;
public class StoredUpdatesTest {
    final GroupStateStorageTest f=new GroupStateStorageTest();
    static byte[] key(int n){byte[] b=new byte[32];Arrays.fill(b,(byte)n);return b;}
    static AdminRecords.Record peer(LanGroup group,int identity,int handshake,long issued) {
        byte[] pub=Crypto.x25519Public(key(handshake));return AdminRecords.certificate(group.groupId,Crypto.ed25519Public(key(identity)),pub,SignaturePurpose.identityProof(key(identity),group.groupId,pub),issued,group.administratorSecret);
    }
    @Test public void separateAdministratorSelfRenewalPersistsCountOnlyAfterSuccessfulSave()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            f.storage().save(group);byte[] old=f.state.value.clone();
            Clock later=Clock.offset(StorageGroupTest.CLOCK,Duration.ofDays(20));
            var state=LanGroup.restore(group.groupId,group.urlAdmin,group.state.snapshot(),later);
            var renewed=state.renewOwnCertificate(group.certificate,group.handshakeSecret,group.identitySecret,group.administratorSecret);
            group.state=state;f.state.fail=true;
            assertThrows(Exception.class,()->f.storage().saveLocalRenewal(group,renewed));assertEquals(0,group.renewalCount);assertEquals(1,group.saveSeq);assertArrayEquals(old,f.state.value);
            f.state.fail=false;assertTrue(f.storage().saveLocalRenewal(group,renewed));assertEquals(1,group.renewalCount);assertEquals(2,group.saveSeq);
            assertFalse(f.storage().saveLocalRenewal(group,renewed));assertEquals(1,group.renewalCount);
            try(var loaded=f.storage().load(later)){assertEquals(1,loaded.renewalCount);assertArrayEquals(renewed.encode(),loaded.certificate.encode());}
        }
    }
    @Test public void pendingRenewalRoundTripsAndNewPeerSaveClearsOnlyAfterCommit()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            group.peerCertificate=peer(group,71,72,StorageGroupTest.NOW-1);group.peerAddress=new InetSocketAddress("192.168.1.10",54322);
            var renewal=peer(group,71,72,StorageGroupTest.NOW);byte[] id=Crypto.blake2s(renewal.field(0));
            group.rememberRenewal(id,renewal.encode());f.storage().save(group);
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){assertArrayEquals(renewal.encode(),loaded.pendingRenewal(id));}
            byte[] old=f.state.value.clone();f.state.fail=true;
            assertThrows(Exception.class,()->f.storage().savePeer(group,renewal,group.peerAddress));
            assertNotNull(group.pendingRenewal(id));assertArrayEquals(old,f.state.value);
            f.state.fail=false;assertTrue(f.storage().savePeer(group,renewal,group.peerAddress));assertNull(group.pendingRenewal(id));
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){assertNull(loaded.pendingRenewal(id));assertArrayEquals(renewal.encode(),loaded.peerCertificate.encode());}
        }
    }
    @Test public void staleOrOtherIdentityCannotReplaceSavedPeer()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            group.peerCertificate=peer(group,71,72,StorageGroupTest.NOW);group.peerAddress=new InetSocketAddress("192.168.1.10",54322);f.storage().save(group);
            byte[] old=f.state.value.clone();
            assertThrows(SecurityException.class,()->f.storage().savePeer(group,peer(group,71,72,StorageGroupTest.NOW-1),group.peerAddress));
            assertThrows(SecurityException.class,()->f.storage().savePeer(group,peer(group,73,74,StorageGroupTest.NOW+1),group.peerAddress));
            assertArrayEquals(old,f.state.value);assertEquals(1,group.saveSeq);
        }
    }
    @Test public void issuingPersistenceFailureRestoresPendingBytesAndSequence()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            group.peerCertificate=peer(group,71,72,StorageGroupTest.NOW-1);group.peerAddress=new InetSocketAddress("192.168.1.10",54322);f.storage().save(group);
            byte[] id=Crypto.blake2s(group.peerCertificate.field(0)),renewal=peer(group,71,72,StorageGroupTest.NOW).encode(),old=f.state.value.clone();
            f.state.fail=true;assertThrows(Exception.class,()->f.storage().saveIssuedRenewal(group,id,renewal));
            assertNull(group.pendingRenewal(id));assertEquals(1,group.saveSeq);assertArrayEquals(old,f.state.value);
            f.state.fail=false;assertTrue(f.storage().saveIssuedRenewal(group,id,renewal));
            try(var restored=f.storage().load(StorageGroupTest.CLOCK);var sessions=restored.sessions(StorageGroupTest.CLOCK,()->0)) {
                assertArrayEquals(renewal,restored.pendingRenewal(id));var peers=(java.util.Map<?,?>)LanControllerHarness.field(sessions,"peers");
                Object peer=peers.get(org.bouncycastle.util.encoders.Hex.toHexString(id));
                assertTrue(java.util.Arrays.equals(renewal,(byte[])LanControllerHarness.field(peer,"renewal")));
            }
        }
    }
    @Test public void pendingRenewalWithOtherPeerIdIsDiscarded()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            group.peerCertificate=peer(group,71,72,StorageGroupTest.NOW-1);group.peerAddress=new InetSocketAddress("192.168.1.10",54322);
            byte[] id=Crypto.blake2s(group.peerCertificate.field(0)),renewal=peer(group,71,72,StorageGroupTest.NOW).encode();group.rememberRenewal(id,renewal);
            byte[] wire=group.encode();wire[wire.length-8-renewal.length-4-32]^=1;
            try(var restored=LanGroup.decode(wire,StorageGroupTest.CLOCK,true)) {
                assertNull(restored.pendingRenewal(id));assertEquals(UdpEndpoint.CloseReason.INTERNAL_FAILURE,restored.pendingRenewalReason());
            }
        }
    }
    @Test public void malformedPendingRenewalIsDiscardedWithoutRejectingMembership()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            group.peerCertificate=peer(group,71,72,StorageGroupTest.NOW-1);group.peerAddress=new InetSocketAddress("192.168.1.10",54322);
            var renewal=peer(group,71,72,StorageGroupTest.NOW);byte[] id=Crypto.blake2s(renewal.field(0));group.rememberRenewal(id,renewal.encode());
            byte[] wire=group.encode();wire[wire.length-9]^=1;
            try(var loaded=LanGroup.decode(wire,StorageGroupTest.CLOCK,true)) {
                assertNull(loaded.pendingRenewal(id));assertEquals(UdpEndpoint.CloseReason.INTERNAL_FAILURE,loaded.pendingRenewalReason());
                assertEquals(UdpEndpoint.CloseReason.RUNNING,loaded.localCertificateReason());
            }
        }
    }
}
