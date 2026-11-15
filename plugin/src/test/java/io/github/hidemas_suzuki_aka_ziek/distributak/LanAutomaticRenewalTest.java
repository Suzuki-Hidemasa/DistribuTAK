// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.time.*;
import java.util.concurrent.atomic.AtomicLong;
public class LanAutomaticRenewalTest {
    static final class Wall extends Clock {
        final AtomicLong now=new AtomicLong(LanControllerHarness.CLOCK.millis());
        public ZoneId getZone(){return ZoneOffset.UTC;}
        public Clock withZone(ZoneId zone){return this;}
        public Instant instant(){return Instant.ofEpochMilli(now.get());}
    }
    @Test public void issuedRenewalIsSavedAndReceivedAndDuplicateDoesNotCount()throws Exception{renew(false);}
    @Test public void issuedRenewalSaveFailureDoesNotSendOrReplacePeer()throws Exception{renew(true);}
    static void allowReview(LanControllerHarness node)throws Exception{
        // 既存の輸送を時刻飛躍で壊さず、1時間後の自己更新の見直しを試験する。
        var checked=LanController.class.getDeclaredField("ownRenewalChecked");checked.setAccessible(true);checked.setBoolean(node.controller,false);
    }
    @Test public void runningAdministratorRenewsAfterSavingAndDoesNotRenewTwice()throws Exception{own(false);}
    @Test public void runningAdministratorSaveFailureKeepsEndpointAndCertificate()throws Exception{own(true);}
    @Test public void startupRenewalIsNotCountedAgainAtNextReview()throws Exception{
        var wall=new Wall();LanControllerHarness.Disk disk;
        try(var first=new LanControllerHarness(null,CotPort.NONE,wall)){first.create();disk=first.disk;}
        wall.now.addAndGet(20L*86_400_000);
        try(var next=new LanControllerHarness(disk,CotPort.NONE,wall)){
            assertEquals(1,LanBehaviourWiringTest.group(next).renewalCount);allowReview(next);next.tick();
            assertEquals(1,LanBehaviourWiringTest.group(next).renewalCount);
        }
    }
    @Test public void revokedAdministratorCannotRenewItself()throws Exception{
        try(var f=new LanControllerHarness()){
            f.create();var group=LanBehaviourWiringTest.group(f);
            var revocations=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group.groupId,1,LanControllerHarness.CLOCK.millis(),java.util.List.of(group.id()),group.administratorSecret);
            group.state.acceptRevocations(revocations);allowReview(f);f.tick();
            assertEquals(0,group.renewalCount);
        }
    }
    void own(boolean fail)throws Exception{
        var wall=new Wall();
        try(var admin=new LanControllerHarness(null,CotPort.NONE,wall)){
            admin.create();var endpoint=admin.endpoint();var previous=LanBehaviourWiringTest.group(admin).certificate;
            wall.now.addAndGet(20L*86_400_000);admin.disk.failSave=fail;allowReview(admin);admin.tick();
            assertSame(endpoint,admin.endpoint());assertEquals(UdpEndpoint.CloseReason.RUNNING,endpoint.closeReason());
            try(var saved=admin.disk.load(wall)){
                assertEquals(fail?0:1,saved.renewalCount);
                assertEquals(fail?previous.issuedAt():wall.millis(),saved.certificate.issuedAt());
                var sessions=(SessionManager)LanControllerHarness.field(endpoint,"sessions");
                assertArrayEquals(saved.certificate.encode(),((AdminRecords.Record)LanControllerHarness.field(sessions,"localCertificate")).encode());
            }
            allowReview(admin);admin.tick();assertEquals(fail?0:1,LanBehaviourWiringTest.group(admin).renewalCount);
        }
    }
    void renew(boolean failSave)throws Exception{
        var wall=new Wall();
        try(var admin=new LanControllerHarness(null,CotPort.NONE,wall);var member=new LanControllerHarness(null,CotPort.NONE,wall)){
            admin.create();member.beginJoin(admin);LanControllerHarness.until(()->member.ui.last.member&&admin.logs.contains("LAN_MEMBER_ISSUED"),admin,member);
            admin.controller.connect();admin.drain();byte[] memberId;
            try(var saved=member.disk.load(wall)){memberId=saved.id();}
            LanControllerHarness.until(()->admin.endpoint().isEstablished(memberId)&&LanBehaviourWiringTest.group(member).peerCertificate!=null,admin,member);
            long issued=LanBehaviourWiringTest.group(member).certificate.issuedAt();
            wall.now.addAndGet(20L*86_400_000);allowReview(admin);
            admin.offset.addAndGet(5_000_000_000L);member.offset.addAndGet(5_000_000_000L);
            admin.disk.failSave=failSave;admin.tick();
            if(failSave){
                LanControllerHarness.until(()->admin.logs.contains("LAN_RENEWAL_REJECTED"),admin,member);
                assertEquals(issued,LanBehaviourWiringTest.group(member).certificate.issuedAt());assertEquals(0,LanBehaviourWiringTest.group(member).renewalCount);
                assertNull(LanBehaviourWiringTest.group(admin).pendingRenewal(memberId));
            }else{
                LanControllerHarness.until(()->LanBehaviourWiringTest.group(member).renewalCount==1,admin,member);
                try(var saved=member.disk.load(wall);var issuer=admin.disk.load(wall)){
                    assertEquals(1,saved.renewalCount);assertTrue(saved.certificate.issuedAt()>issued);
                    assertArrayEquals(saved.certificate.encode(),LanGroup.renewalCertificate(issuer.pendingRenewal(memberId)));
                    assertEquals(issued,issuer.peerCertificate.issuedAt());
                }
                LanBehaviourWiringTest.renewal(member,LanBehaviourWiringTest.group(member).certificate);assertEquals(1,LanBehaviourWiringTest.group(member).renewalCount);
            }
        }
    }
}
