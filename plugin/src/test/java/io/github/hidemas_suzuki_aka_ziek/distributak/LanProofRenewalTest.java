// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;
import java.time.*;

public class LanProofRenewalTest {
    static final class Tap {
        final java.util.List<RenewalMessage.Operation> received=new java.util.concurrent.CopyOnWriteArrayList<>();
        volatile boolean dropReplies,dropDeliveries;
        volatile RenewalMessage delivery;
        void install(LanControllerHarness harness)throws Exception {
            var field=UdpEndpoint.class.getDeclaredField("receiver");field.setAccessible(true);
            UdpEndpoint.Receiver original=(UdpEndpoint.Receiver)field.get(harness.endpoint());
            field.set(harness.endpoint(),new UdpEndpoint.Receiver(){
                public void receive(byte[] peer,byte[] plain){original.receive(peer,plain);}
                public void receive(byte[] peer,byte[] session,byte[] plain){
                    if(RenewalMessage.isManagement(plain)) {
                        var decoded=RenewalMessage.decode(plain);var operation=decoded.operation();received.add(operation);
                        if(operation==RenewalMessage.Operation.CERTIFICATE_DELIVERY)delivery=decoded;
                        if(dropReplies&&operation==RenewalMessage.Operation.PROOF_REPLY||dropDeliveries&&operation==RenewalMessage.Operation.CERTIFICATE_DELIVERY)return;
                    }
                    original.receive(peer,session,plain);
                }
            });
        }
    }
    static void until(LanControllerHarness.Check check,LanControllerHarness... nodes)throws Exception {
        long end=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(8);
        while(!check.ok()) {
            for(var node:nodes){node.offset.addAndGet(100_000_000L);node.tick();}
            if(System.nanoTime()>end)throw new AssertionError("renewal condition timed out");
            Thread.sleep(5);
        }
        for(var node:nodes)node.drain();
    }
    static LanControllerHarness.Disk[] legacyPair()throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.create();member.beginJoin(admin);
            until(()->member.ui.last.member&&admin.logs.contains("LAN_MEMBER_ISSUED"),admin,member);
            admin.controller.connect();admin.drain();
            until(()->LanBehaviourWiringTest.group(member).peerCertificate!=null,admin,member);
            var a=LanBehaviourWiringTest.group(admin);var m=LanBehaviourWiringTest.group(member);
            var ca=LegacyRecords.record(a.certificate,a.identitySecret,a.administratorSecret);
            var cm=LegacyRecords.record(m.certificate,m.identitySecret,a.administratorSecret);
            LegacyRecords.install(a,ca,cm,a.administratorSecret,LanControllerHarness.CLOCK);
            LegacyRecords.install(m,cm,ca,a.administratorSecret,LanControllerHarness.CLOCK);
            admin.disk.save(a);member.disk.save(m);
            long later=LanControllerHarness.CLOCK.millis()+20L*86_400_000;
            String time=Instant.ofEpochMilli(later).toString(),stale=Instant.ofEpochMilli(later+3_600_000).toString();
            for(var harness:new LanControllerHarness[]{admin,member}) {
                var group=LanBehaviourWiringTest.group(harness);var snapshot=new SyncState(group.groupId,group.id());
                byte[] xml=("<event version=\"2.0\" uid=\"migration-fixture\" type=\"a-f-G\" time=\""+time+"\" start=\""+time+"\" stale=\""+stale+"\"><point lat=\"0\" lon=\"0\" hae=\"0\" ce=\"1\" le=\"1\"/><detail/></event>").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                snapshot.put(CotRecord.record("migration-fixture",later,group.id(),later+3_600_000,xml,0),later);
                harness.disk.saveSync(group,snapshot);
            }
            return new LanControllerHarness.Disk[]{admin.disk,member.disk};
        }
    }
    @Test public void versionFivePairMigratesOnlyAfterAdministratorRequestAndKeepsIdentityGroupAndCot()throws Exception {
        var disks=legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.addAndGet(20L*86_400_000);
        byte[] identity,group;
        try(var old=disks[1].load(wall)){identity=old.id();group=old.groupId.clone();assertEquals(1,old.certificate.format());}
        try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall);var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            var toAdmin=new Tap();var toMember=new Tap();toAdmin.install(admin);toMember.install(member);
            assertTrue(toAdmin.received.isEmpty());assertEquals(0,LanBehaviourWiringTest.group(member).renewalCount);
            admin.drain();
            until(()->LanBehaviourWiringTest.group(member).renewalCount==1,admin,member);
            assertEquals(java.util.List.of(RenewalMessage.Operation.PROOF_REPLY),toAdmin.received);
            assertEquals(java.util.List.of(RenewalMessage.Operation.PROOF_REQUEST,RenewalMessage.Operation.CERTIFICATE_DELIVERY),toMember.received);
            try(var migrated=member.disk.load(wall)) {
                assertEquals(2,migrated.certificate.format());assertEquals(2,migrated.certificate.identityProofFormat());
                assertTrue(Crypto.equal(identity,migrated.id()));assertTrue(Crypto.equal(group,migrated.groupId));assertFalse(member.disk.erased);
                assertNotNull(member.disk.loadSync(migrated).get("migration-fixture"));
            }
            assertEquals(2,LanBehaviourWiringTest.group(admin).certificate.format());assertEquals(1,LanBehaviourWiringTest.group(admin).renewalCount);
        }
    }
    @Test public void duplicateDeliveryRetriesFirstWithoutAnotherSaveOrRenewalCount()throws Exception {
        var disks=legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.addAndGet(20L*86_400_000);
        try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall);var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            var tap=new Tap();tap.install(member);
            byte[] administrator=LanBehaviourWiringTest.group(admin).id(),memberId=LanBehaviourWiringTest.group(member).id();
            until(()->LanBehaviourWiringTest.group(member).renewalCount==1,admin,member);
            until(()->LanBehaviourWiringTest.group(admin).pendingRenewal(memberId)==null,admin,member);
            until(()->!((SessionManager)LanControllerHarness.field(admin.endpoint(),"sessions")).isHandshaking(memberId)
                    &&!((SessionManager)LanControllerHarness.field(member.endpoint(),"sessions")).isHandshaking(administrator)
                    &&java.util.Arrays.equals(admin.endpoint().sessionId(memberId),member.endpoint().sessionId(administrator)),admin,member);
            byte[] session=member.endpoint().sessionId(administrator);long saved=LanBehaviourWiringTest.group(member).saveSeq;
            wall.now.addAndGet(1000);member.offset.addAndGet(5_000_000_000L);
            var method=LanController.class.getDeclaredMethod("receiveProofRenewal",byte[].class,byte[].class,byte[].class);method.setAccessible(true);
            method.invoke(member.controller,administrator,session,tap.delivery.encode());
            assertTrue(((SessionManager)LanControllerHarness.field(member.endpoint(),"sessions")).isHandshaking(administrator));
            until(()->!java.util.Arrays.equals(session,member.endpoint().sessionId(administrator)),admin,member);
            assertEquals(1,LanBehaviourWiringTest.group(member).renewalCount);assertEquals(saved,LanBehaviourWiringTest.group(member).saveSeq);
        }
    }
    @Test public void noProofReplyCannotIssueNewCertificate()throws Exception {
        var disks=legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.addAndGet(20L*86_400_000);
        try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall);var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            var tap=new Tap();tap.dropReplies=true;tap.install(admin);admin.drain();
            until(()->tap.received.contains(RenewalMessage.Operation.PROOF_REPLY),admin,member);
            assertNull(LanBehaviourWiringTest.group(admin).pendingRenewal(LanBehaviourWiringTest.group(member).id()));
            assertEquals(0,LanBehaviourWiringTest.group(member).renewalCount);
        }
    }
    @Test public void memberSaveFailureRetriesSameDeliveryAndCountsOnlyOnce()throws Exception{saveFailure(false);}
    @Test public void administratorSaveFailureDoesNotPublishAndCanRetry()throws Exception{saveFailure(true);}
    private void saveFailure(boolean issuer)throws Exception {
        var disks=legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.addAndGet(20L*86_400_000);
        try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall);var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            var toAdmin=new Tap();var toMember=new Tap();toAdmin.install(admin);toMember.install(member);
            if(issuer)admin.disk.failIssuedRenewal=true;else member.disk.failLocalRenewal=true;
            admin.drain();
            var failed=issuer?admin:member;
            until(()->failed.logs.contains("LAN_RENEWAL_REJECTED"),admin,member);
            assertEquals(0,LanBehaviourWiringTest.group(member).renewalCount);
            if(issuer)assertFalse(toMember.received.contains(RenewalMessage.Operation.CERTIFICATE_DELIVERY));
            admin.disk.failIssuedRenewal=false;member.disk.failLocalRenewal=false;
            admin.offset.addAndGet(5_000_000_000L);member.offset.addAndGet(5_000_000_000L);
            until(()->LanBehaviourWiringTest.group(member).renewalCount==1,admin,member);
            assertEquals(2,LanBehaviourWiringTest.group(member).certificate.format());
        }
    }
    @Test public void administratorRestartAfterSavingKeepsIssuedCertificateAndUsesFreshRequest()throws Exception {
        var disks=legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.addAndGet(20L*86_400_000);
        try(var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            var toMember=new Tap();toMember.dropDeliveries=true;toMember.install(member);byte[] certificate,request;
            try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall)) {
                admin.drain();
                until(()->toMember.received.contains(RenewalMessage.Operation.CERTIFICATE_DELIVERY),admin,member);
                var saved=RenewalMessage.pendingValue(LanBehaviourWiringTest.group(admin).pendingRenewal(LanBehaviourWiringTest.group(member).id()));
                certificate=saved.certificate();request=saved.requestId();assertEquals(0,LanBehaviourWiringTest.group(member).renewalCount);
            }
            wall.now.addAndGet(1000);toMember.dropDeliveries=false;
            try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall)) {
                admin.drain();
                until(()->LanBehaviourWiringTest.group(member).renewalCount==1,admin,member);
                assertTrue(java.util.Arrays.equals(certificate,LanBehaviourWiringTest.group(member).certificate.encode()));
                var rebound=RenewalMessage.pendingValue(LanBehaviourWiringTest.group(admin).pendingRenewal(LanBehaviourWiringTest.group(member).id()));
                assertFalse(java.util.Arrays.equals(request,rebound.requestId()));
            }
        }
    }
    @Test public void memberRestartAfterReplyNeedsNewRequestBeforeDelivery()throws Exception {
        var disks=legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.addAndGet(20L*86_400_000);
        try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall)) {
            var toAdmin=new Tap();toAdmin.dropReplies=true;toAdmin.install(admin);
            try(var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
                admin.drain();
                until(()->toAdmin.received.contains(RenewalMessage.Operation.PROOF_REPLY),admin,member);
                assertNull(LanBehaviourWiringTest.group(admin).pendingRenewal(LanBehaviourWiringTest.group(member).id()));
            }
            wall.now.addAndGet(1000);toAdmin.dropReplies=false;admin.offset.addAndGet(5_000_000_000L);
            try(var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
                member.drain();
                until(()->LanBehaviourWiringTest.group(member).renewalCount==1,admin,member);
                assertEquals(2,LanBehaviourWiringTest.group(member).certificate.format());
            }
        }
    }
    @Test public void oldPendingAdoptedByMemberIsConfirmedOnlyAfterFirstWithoutCountingAgain()throws Exception {oldPending(true);}
    @Test public void oldPendingNotAdoptedByMemberIsRemovedBeforeFreshProof2Renewal()throws Exception {oldPending(false);}
    private void oldPending(boolean adopted)throws Exception {
        var disks=legacyPair();long issued=LanControllerHarness.CLOCK.millis()+10L*86_400_000;
        byte[] pending;
        var issuedClock=Clock.fixed(Instant.ofEpochMilli(issued),ZoneOffset.UTC);
        try(var admin=disks[0].load(issuedClock);var member=disks[1].load(issuedClock)) {
            var fresh=AdminRecords.certificate(member.groupId,member.certificate.field(0),member.certificate.field(1),
                    SignaturePurpose.identityProof(member.identitySecret,member.groupId,member.certificate.field(1)),issued,admin.administratorSecret);
            var legacy=LegacyRecords.record(fresh,member.identitySecret,admin.administratorSecret);pending=legacy.encode();
            admin.state.trustStoredLegacyCertificate(legacy);admin.rememberRenewal(member.id(),pending);disks[0].save(admin);
            if(adopted){member.state.trustStoredLegacyCertificate(legacy);member.certificate=legacy;member.renewalCount=1;disks[1].save(member);}
        }
        var wall=new LanAutomaticRenewalTest.Wall();wall.now.addAndGet(20L*86_400_000);
        try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall);var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            var toMember=new Tap();toMember.install(member);
            byte[] administrator=LanBehaviourWiringTest.group(admin).id(),memberId=LanBehaviourWiringTest.group(member).id();
            until(()->admin.endpoint().isEstablished(memberId)&&member.endpoint().isEstablished(administrator),admin,member);
            // 旧 pending は SECOND だけでは確定しない。メンバーを FIRST の送り手にする。
            wall.now.addAndGet(1000);member.offset.addAndGet(5_000_000_000L);member.endpoint().start(administrator);
            if(adopted) {
                until(()->java.util.Arrays.equals(pending,LanBehaviourWiringTest.group(admin).peerCertificate.encode()),admin,member);
                assertEquals(1,LanBehaviourWiringTest.group(member).renewalCount);
                assertTrue(toMember.received.isEmpty());
            }else {
                until(()->LanBehaviourWiringTest.group(member).certificate.format()==2,admin,member);
                assertEquals(1,LanBehaviourWiringTest.group(member).renewalCount);
                assertTrue(toMember.received.contains(RenewalMessage.Operation.PROOF_REQUEST));
            }
            until(()->LanBehaviourWiringTest.group(admin).pendingRenewal(LanBehaviourWiringTest.group(member).id())==null,admin,member);
            try(var restored=disks[0].load(wall)) {
                assertNull(restored.pendingRenewal(LanBehaviourWiringTest.group(member).id()));
                assertEquals(adopted?1:2,restored.peerCertificate.format());
            }
        }
    }
    @Test public void savedDeliveryRetainsMetadataAndSameCertificateAcrossRestart()throws Exception {
        var f=new GroupStateStorageTest();
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())) {
            group.peerCertificate=StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW-1);
            group.peerAddress=new java.net.InetSocketAddress("192.0.2.10",54322);
            byte[] id=Crypto.blake2s(group.peerCertificate.field(0));
            var request=RenewalMessage.request(group.peerCertificate,new byte[16],group.urlAdmin,RenewalMessage.Reason.AUTO_RENEWAL,null);
            var certificate=StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW);
            byte[] pending=RenewalMessage.delivery(request,certificate.encode()).pendingValue();
            assertTrue(f.storage().saveIssuedRenewal(group,id,pending));
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)) {
                assertTrue(java.util.Arrays.equals(pending,loaded.pendingRenewal(id)));
                assertTrue(java.util.Arrays.equals(certificate.encode(),LanGroup.renewalCertificate(loaded.pendingRenewal(id))));
            }
        }
    }
    @Test public void corruptOldPendingIsDroppedWithoutErasingVersionFiveGroup()throws Exception {corruptPending(true);}
    @Test public void corruptNewPendingRejectsWholeSavedState()throws Exception {corruptPending(false);}
    private void corruptPending(boolean legacy)throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())) {
            group.peerCertificate=StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW-1);
            group.peerAddress=new java.net.InetSocketAddress("192.0.2.10",54322);
            byte[] peer=Crypto.blake2s(group.peerCertificate.field(0));
            group.restoreRenewal(peer,legacy?new byte[]{10,1}:new byte[]{0,2,8,1});byte[] saved=group.encode();
            if(legacy)try(var restored=LanGroup.decode(saved,StorageGroupTest.CLOCK)) {
                assertNull(restored.pendingRenewal(peer));assertNotNull(restored.certificate);
                assertEquals(UdpEndpoint.CloseReason.INTERNAL_FAILURE,restored.pendingRenewalReason());
            }else assertThrows(RuntimeException.class,()->LanGroup.decode(saved,StorageGroupTest.CLOCK));
        }
    }
    @Test public void metadataRebindFailureRestoresPreviousSavedDelivery()throws Exception {
        var f=new GroupStateStorageTest();
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())) {
            group.peerCertificate=StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW-1);
            group.peerAddress=new java.net.InetSocketAddress("192.0.2.10",54322);
            byte[] id=Crypto.blake2s(group.peerCertificate.field(0)),requestId=new byte[16];
            var certificate=StoredUpdatesTest.peer(group,71,72,StorageGroupTest.NOW);
            var first=RenewalMessage.delivery(RenewalMessage.request(group.peerCertificate,requestId,group.urlAdmin,RenewalMessage.Reason.AUTO_RENEWAL,null),certificate.encode());
            f.storage().saveIssuedRenewal(group,id,first.pendingValue());byte[] saved=f.state.value.clone();
            requestId[0]=1;var next=RenewalMessage.delivery(RenewalMessage.request(group.peerCertificate,requestId,group.urlAdmin,RenewalMessage.Reason.AUTO_RENEWAL,null),certificate.encode());
            f.state.fail=true;assertThrows(Exception.class,()->f.storage().saveIssuedRenewal(group,id,next.pendingValue()));
            assertTrue(java.util.Arrays.equals(first.pendingValue(),group.pendingRenewal(id)));assertTrue(java.util.Arrays.equals(saved,f.state.value));
        }
    }
}
