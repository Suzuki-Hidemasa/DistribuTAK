// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.time.*;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import org.junit.Test;
import static org.junit.Assert.*;

public class RenewalReviewFixTest {
    @Test public void receiveThreadMayRefreshBetweenPersistAndApplyWithoutInvalidatingSelf() throws Exception {
        try(var pair=new RejoinedStorageTest.Fixture()) {
            var oldSelf=LegacyRecords.record(pair.member.certificate,pair.member.identitySecret,pair.admin.administratorSecret);
            var oldPeer=LegacyRecords.record(pair.admin.certificate,pair.admin.identitySecret,pair.admin.administratorSecret);
            LegacyRecords.install(pair.member,oldSelf,oldPeer,pair.admin.administratorSecret,StorageGroupTest.CLOCK);
            try(var sessions=pair.member.sessions(StorageGroupTest.CLOCK,()->0)) {
                var renewed=AdminRecords.certificate(pair.member.groupId,pair.member.certificate.field(0),pair.member.certificate.field(1),
                    SignaturePurpose.identityProof(pair.member.identitySecret,pair.member.groupId,pair.member.certificate.field(1)),
                    StorageGroupTest.NOW+1,pair.admin.administratorSecret);
                assertTrue(sessions.validateLocalCertificateRenewal(renewed));
                var storage=new GroupStateStorageTest().storage();
                storage.saveLocalRenewal(pair.member,renewed);
                // 保存の直後、核への適用の前にUDPタイマーのrefreshが入る順を固定する。
                sessions.refresh();
                assertEquals(UdpEndpoint.CloseReason.RUNNING,sessions.closeReason());
                sessions.updateLocalCertificate(renewed);sessions.refresh();
                assertEquals(UdpEndpoint.CloseReason.RUNNING,sessions.closeReason());
                assertThrows(SecurityException.class,()->pair.member.state.verifyCertificate(oldSelf,oldSelf.field(1)));
            }
        }
    }

    @Test public void rejoinPreservesStoredLegacyPeerPermission() throws Exception {
        try(var pair=new RejoinedStorageTest.Fixture()) {
            var oldSelf=LegacyRecords.record(pair.member.certificate,pair.member.identitySecret,pair.admin.administratorSecret);
            var oldPeer=LegacyRecords.record(pair.admin.certificate,pair.admin.identitySecret,pair.admin.administratorSecret);
            LegacyRecords.install(pair.member,oldSelf,oldPeer,pair.admin.administratorSecret,StorageGroupTest.CLOCK);
            // 前の保存では、この正確な形式1の証明書が許可されている。
            pair.member.state.verifyCertificate(oldPeer,oldPeer.field(1));
            try(var previous=LanGroup.decode(pair.member.encode(),StorageGroupTest.CLOCK,true);
                var rejoined=rejoin(pair,previous,Clock.offset(StorageGroupTest.CLOCK,Duration.ofSeconds(1)))) {
                assertEquals(2,rejoined.certificate.format());
                assertTrue(java.util.Arrays.equals(oldPeer.encode(),rejoined.peerCertificate.encode()));
                rejoined.state.verifyCertificate(oldPeer,oldPeer.field(1));
            }
        }
    }

    static LanGroup rejoin(RejoinedStorageTest.Fixture pair,LanGroup previous,Clock clock)throws Exception {
        byte[] handshake=StoredUpdatesTest.key(74);
        try(var invite=pair.invitation();var issuer=pair.issuer(invite,clock);
            var joiner=JoinHandshake.Joiner.rejoin(invite,previous.identitySecret,handshake,clock,previous.state,previous.certificate,previous.keyVersion,previous.groupKey,previous.state.announcement(),previous.state.revokedSubjects());
            var material=pair.materials(Crypto.ed25519Public(previous.identitySecret));
            var joined=joiner.receive(issuer.respond(joiner.request(),pair.admin.handshakeSecret,pair.admin.administratorSecret,material))) {
            return LanGroup.rejoined(previous,handshake,pair.admin.urlAdmin,joined,clock);
        }
    }
    @Test public void expiredWellFormedPendingDoesNotInvalidateSavedGroup() throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            group.peerCertificate=StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW-1);
            group.peerAddress=new InetSocketAddress("192.0.2.10",54322);
            var later=Clock.offset(StorageGroupTest.CLOCK,Duration.ofDays(31));
            // 対照: 自分と相手の期限切れだけでは保存の復旧を止めない。
            try(var control=LanGroup.decode(group.encode(),later,true)) { assertNotNull(control); }
            var certificate=StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW);
            var request=RenewalMessage.request(group.peerCertificate,new byte[16],group.urlAdmin,RenewalMessage.Reason.AUTO_RENEWAL,null);
            group.rememberRenewal(Crypto.blake2s(group.peerCertificate.field(0)),RenewalMessage.delivery(request,certificate.encode()).pendingValue());
            try(var loaded=LanGroup.decode(group.encode(),later,true)) { assertNotNull(loaded); }
        }
    }
    @Test public void administratorSelfRenewalKeepsOldPermissionUntilCoreApplies()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            var old=LegacyRecords.record(group.certificate,group.identitySecret,group.administratorSecret);
            group.certificate=old;group.state.trustStoredLegacyCertificate(old);
            var later=Clock.offset(StorageGroupTest.CLOCK,Duration.ofDays(20));
            // 保存と適用の間にUDPタイマーと同じrefreshを入れる。
            var storage=new GroupStateStorageTest().storage();
            try(var loaded=LanGroup.decode(group.encode(),later,true);var sessions=loaded.sessions(later,()->0)) {
                var renewed=loaded.state.renewOwnCertificate(loaded.certificate,loaded.handshakeSecret,loaded.identitySecret,loaded.administratorSecret);
                assertNotNull(renewed);storage.saveLocalRenewal(loaded,renewed);sessions.refresh();
                assertEquals(UdpEndpoint.CloseReason.RUNNING,sessions.closeReason());
                sessions.updateLocalCertificate(renewed);sessions.refresh();assertEquals(UdpEndpoint.CloseReason.RUNNING,sessions.closeReason());
                assertThrows(SecurityException.class,()->loaded.state.verifyCertificate(old,old.field(1)));assertEquals(1,loaded.renewalCount);
            }
        }
    }
    @Test public void rejoinCannotInheritUnknownLegacyPeer()throws Exception {
        try(var pair=new RejoinedStorageTest.Fixture()) {
            pair.member.peerCertificate=LegacyRecords.record(pair.admin.certificate,pair.admin.identitySecret,pair.admin.administratorSecret);
            assertThrows(SecurityException.class,()->pair.rejoin(Clock.offset(StorageGroupTest.CLOCK,Duration.ofSeconds(1))));
        }
    }
    static LanGroup pendingGroup()throws Exception {
        var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom());
        group.peerCertificate=StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW-1);
        group.peerAddress=new InetSocketAddress("192.0.2.10",54322);return group;
    }
    static void pending(LanGroup group,AdminRecords.Record certificate)throws Exception {
        var request=RenewalMessage.request(group.peerCertificate,new byte[16],group.urlAdmin,RenewalMessage.Reason.AUTO_RENEWAL,null);
        group.restoreRenewal(Crypto.blake2s(group.peerCertificate.field(0)),RenewalMessage.delivery(request,certificate.encode()).pendingValue());
    }
    @Test public void revokedPendingPeerIsForgottenAndOwnGroupRemainsReadable()throws Exception {
        try(var group=pendingGroup()) {
            pending(group,StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW));
            byte[] saved=group.encode(),peer=Crypto.blake2s(group.peerCertificate.field(0));
            group.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group.groupId,1,StorageGroupTest.NOW,
                    java.util.List.of(Crypto.blake2s(group.peerCertificate.field(0))),group.administratorSecret));
            byte[] revokedSaved=replaceManagementSnapshot(saved,group.state.snapshot());
            try(var loaded=LanGroup.decode(revokedSaved,StorageGroupTest.CLOCK,true)) {
                assertNull(loaded.peerCertificate);assertTrue(loaded.revokedPeerForgotten);
                assertNull(loaded.pendingRenewal(peer));assertNotNull(loaded.certificate);
            }
        }
    }
    static byte[] replaceManagementSnapshot(byte[] saved,AdminRecordStore.Snapshot snapshot)throws Exception {
        var in=new java.io.DataInputStream(new java.io.ByteArrayInputStream(saved));
        in.readInt();in.readInt();for(int i=0;i<4;i++)in.skipNBytes(in.readInt());in.readLong();
        for(int i=0;i<3;i++)in.skipNBytes(in.readInt());int prefix=saved.length-in.available();
        int count=in.readInt();for(int i=0;i<count;i++)in.skipNBytes(in.readInt());
        in.skipNBytes(in.readInt());in.skipNBytes(in.readInt());in.readLong();in.readLong();int suffix=saved.length-in.available();
        var buffer=new java.io.ByteArrayOutputStream();var out=new java.io.DataOutputStream(buffer);out.write(saved,0,prefix);
        out.writeInt(snapshot.records().size());for(byte[] value:snapshot.records()){out.writeInt(value.length);out.write(value);}
        for(byte[] value:new byte[][]{snapshot.anchorSignature(),snapshot.revocations()}){out.writeInt(value.length);out.write(value);}
        out.writeLong(snapshot.administratorVersion());out.writeLong(snapshot.revocationVersion());out.write(saved,suffix,saved.length-suffix);out.flush();return buffer.toByteArray();
    }
    @Test public void pendingClockFailureHasTypedReasonAndDoesNotEraseState()throws Exception {
        try(var group=pendingGroup()) {
            pending(group,StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW+360_000));
            var failure=assertThrows(StoredCertificateFailure.class,()->LanGroup.decode(group.encode(),StorageGroupTest.CLOCK,true));
            assertEquals(UdpEndpoint.CloseReason.CLOCK_FAILURE,failure.reason);
        }
    }
    @Test public void malformedPendingIsRejectedEvenAfterItsExpiry()throws Exception {
        try(var group=pendingGroup()) {
            var cert=StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW);byte[] broken=cert.encode();broken[broken.length-1]^=1;
            var request=RenewalMessage.request(group.peerCertificate,new byte[16],group.urlAdmin,RenewalMessage.Reason.AUTO_RENEWAL,null);
            group.restoreRenewal(Crypto.blake2s(group.peerCertificate.field(0)),RenewalMessage.delivery(request,broken).pendingValue());
            var later=Clock.offset(StorageGroupTest.CLOCK,Duration.ofDays(31));byte[] saved=group.encode();
            assertThrows(SecurityException.class,()->LanGroup.decode(saved,later,true));
        }
    }
    @Test public void expiredPendingAllowsAdministratorSelfRenewalAtStartup()throws Exception {
        try(var group=pendingGroup()) {
            pending(group,StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW));
            var disk=new LanControllerHarness.Disk(group.port);disk.save(group);
            var later=Clock.offset(StorageGroupTest.CLOCK,Duration.ofDays(31));
            try(var admin=new LanControllerHarness(disk,CotPort.NONE,later)) {
                assertTrue(admin.ui.last.running);assertFalse(disk.erased);
                assertEquals(1,LanBehaviourWiringTest.group(admin).renewalCount);
                assertEquals(2,LanBehaviourWiringTest.group(admin).certificate.format());
            }
        }
    }
    @Test public void pendingClockFailureStopsStartupWithoutErasing()throws Exception {
        try(var group=pendingGroup()) {
            pending(group,StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW+360_000));
            var disk=new LanControllerHarness.Disk(group.port);disk.save(group);byte[] saved=disk.state.value.clone();
            try(var node=LanControllerHarness.unreadable(disk,StorageGroupTest.CLOCK)) {
                assertFalse(node.ui.last.running);assertFalse(disk.erased);assertTrue(java.util.Arrays.equals(saved,disk.state.value));
                assertTrue(node.ui.last.text.contains("端末の時計がずれています"));
            }
        }
    }
    @Test public void pendingWrongBaseAndIssuerAreRejectedAsBroken()throws Exception {
        for(boolean issuer:new boolean[]{false,true})try(var group=pendingGroup()) {
            var certificate=issuer?AdminRecords.certificate(group.groupId,group.peerCertificate.field(0),group.peerCertificate.field(1),
                    group.peerCertificate.field(2),StorageGroupTest.NOW,StoredUpdatesTest.key(79)):StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW);
            var base=issuer?group.peerCertificate:StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW-2);
            var request=RenewalMessage.request(base,new byte[16],group.urlAdmin,RenewalMessage.Reason.AUTO_RENEWAL,null);
            group.restoreRenewal(Crypto.blake2s(group.peerCertificate.field(0)),RenewalMessage.delivery(request,certificate.encode()).pendingValue());
            byte[] saved=group.encode();assertThrows(SecurityException.class,()->LanGroup.decode(saved,StorageGroupTest.CLOCK,true));
        }
    }
    @Test public void legacyPeerPermissionIsPrunedOnlyAfterSuccessfulSaveAndKeepsCoreValid()throws Exception {
        for(boolean fail:new boolean[]{false,true})try(var group=pendingGroup()) {
            var old=LegacyRecords.record(group.peerCertificate,StoredUpdatesTest.key(71),group.administratorSecret);
            group.peerCertificate=old;group.state.trustStoredLegacyCertificate(old);
            var next=LegacyRecords.record(StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW),StoredUpdatesTest.key(71),group.administratorSecret);
            group.state.trustStoredLegacyCertificate(next);var fixture=new GroupStateStorageTest();
            try(var sessions=group.sessions(StorageGroupTest.CLOCK,()->0)) {
                sessions.rememberPeer(next);fixture.state.fail=fail;
                if(fail)assertThrows(Exception.class,()->fixture.storage().savePeer(group,next,group.peerAddress));
                else fixture.storage().savePeer(group,next,group.peerAddress);
                sessions.refresh();assertEquals(UdpEndpoint.CloseReason.RUNNING,sessions.closeReason());
                group.state.verifyCertificate(next,next.field(1));
                if(fail)group.state.verifyCertificate(old,old.field(1));
                else assertThrows(SecurityException.class,()->group.state.verifyCertificate(old,old.field(1)));
            }
        }
    }
}
