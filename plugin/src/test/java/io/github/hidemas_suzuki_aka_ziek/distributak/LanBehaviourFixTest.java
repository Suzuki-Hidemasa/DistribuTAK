// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class LanBehaviourFixTest {
    static final Clock CLOCK=LanControllerHarness.CLOCK;
    static final String JOIN_FAILED="加入できませんでした。管理者側の状態も確認してください。管理者が招待を出せる場合は、新しい招待でやり直してください";
    static final String CLOCK_FAILED="端末の時計がずれています。時計を合わせてからATAKを起動し直してください";
    static final String RENEW_FAILED="証明書の更新に失敗しました。接続するを押してください";
    static LanControllerHarness.Disk[] validPair()throws Exception{
        var pair=LanRejoinBehaviourTest.expiredPair();
        try(var a=pair[0].load(CLOCK);var b=pair[1].load(CLOCK)){
            b.certificate=AdminRecords.certificate(b.groupId,b.certificate.field(0),b.certificate.field(1),b.certificate.field(2),CLOCK.millis()-1,a.administratorSecret);
            a.peerCertificate=b.certificate;pair[0].save(a);pair[1].save(b);
        }
        return pair;
    }
    static LanControllerHarness stoppedAdmin(LanControllerHarness.Disk disk)throws Exception{
        var admin=new LanControllerHarness(disk);admin.controller.disconnect();admin.drain();return admin;
    }
    static void keyHint(LanControllerHarness member)throws Exception{
        var sessions=(SessionManager)LanControllerHarness.field(member.endpoint(),"sessions");
        assertThrows(RuntimeException.class,()->sessions.receive(new SessionPacket(SessionPacket.FIRST,new byte[16],1,0,new byte[108]).encode()));
        member.tick();assertTrue(member.ui.last.rejoin);
    }
    static AdminState.ClockFailure clockFailure(LanGroup group){
        var state=new AdminState(group.groupId,group.urlAdmin,Clock.offset(CLOCK,Duration.ofMinutes(-6)),new InMemoryAdminRecordStore());
        return assertThrows(AdminState.ClockFailure.class,()->state.bootstrap(group.state.administrators(),group.state.snapshot().anchorSignature()));
    }
    static void beginRejoin(LanControllerHarness member,LanControllerHarness admin)throws Exception{
        member.controller.join(admin.rejoinInvitation(),member.controller.ticket());member.drain();
    }
    @Test public void rejoinOpenFailureRestoresPreviousEndpointAndSupervisor()throws Exception{beforeJoinFailure(0);}
    @Test public void rejoinSecurityFailureRestoresPreviousEndpointAndSupervisor()throws Exception{beforeJoinFailure(1);}
    @Test public void rejoinClockFailureRestoresPreviousEndpointAndSupervisor()throws Exception{beforeJoinFailure(2);}
    void beforeJoinFailure(int kind)throws Exception{
        var pair=validPair();
        try(var admin=stoppedAdmin(pair[0]);var member=new LanControllerHarness(pair[1])){
            keyHint(member);byte[] old=member.disk.state.value.clone();var previous=member.endpoint();int opens=member.link.opens;
            var prior=((ReconnectSupervisor)LanControllerHarness.field(member.controller,"reconnect")).snapshot();
            var once=new AtomicBoolean();var group=LanBehaviourWiringTest.group(member);var certificate=group.certificate;
            member.link.beforeOpen=()->{
                if(!once.compareAndSet(false,true))return;
                if(kind==0){member.link.failOpens=1;return;}
                if(kind==2)throw clockFailure(group);
                group.certificate=group.peerCertificate;
                member.link.afterIoClose=()->{group.certificate=certificate;member.link.afterIoClose=()->{};};
            };
            beginRejoin(member,admin);
            assertTrue(member.ui.last.ready);assertTrue(member.ui.last.running);assertNotSame(previous,member.endpoint());assertTrue(member.link.opens>=opens+2);
            assertArrayEquals(old,member.disk.state.value);assertFalse(member.disk.erased);
            assertTrue(member.ui.last.text.contains(kind==2?CLOCK_FAILED:JOIN_FAILED));
            var restored=(ReconnectSupervisor)LanControllerHarness.field(member.controller,"reconnect");
            assertEquals(prior.active(),restored.active());
            for(String name:List.of("next","attempt","failures"))assertEquals(LanControllerHarness.field(prior,name),LanControllerHarness.field(restored,name));
        }
    }
    @Test public void failedReopenAfterRejoinFailureWaitsForConnectWithoutDisablingUi()throws Exception{
        var pair=validPair();try(var admin=stoppedAdmin(pair[0]);var member=new LanControllerHarness(pair[1])){
            keyHint(member);byte[] old=member.disk.state.value.clone();member.link.failOpens=2;beginRejoin(member,admin);
            assertTrue(member.ui.last.ready);assertFalse(member.ui.last.running);assertArrayEquals(old,member.disk.state.value);
            assertTrue(member.ui.last.text.contains(JOIN_FAILED));member.controller.connect();member.drain();assertTrue(member.ui.last.running);
        }
    }
    @Test public void expiredMemberOpenFailureKeepsRejoinScreenAndBytes()throws Exception{
        var pair=LanRejoinBehaviourTest.expiredPair();
        try(var admin=stoppedAdmin(pair[0]);var member=new LanControllerHarness(pair[1])){
            byte[] old=member.disk.state.value.clone();member.link.failOpens=1;beginRejoin(member,admin);
            assertTrue(member.ui.last.ready);assertTrue(member.ui.last.rejoin);assertFalse(member.ui.last.running);
            assertArrayEquals(old,member.disk.state.value);assertFalse(member.disk.erased);
            assertTrue(member.ui.last.text.contains("証明書の期限が切れました。管理者の新しい招待を読んでください"));
        }
    }
    @Test public void committedRejoinWithOpenFailureKeepsNewStateAndCanConnect()throws Exception{committedOpenFailure(false);}
    @Test public void committedRejoinWithNetworkSecurityFailureCanConnect()throws Exception{committedOpenFailure(true);}
    void committedOpenFailure(boolean security)throws Exception{
        var pair=LanRejoinBehaviourTest.expiredPair();byte[] previous=pair[1].state.value.clone();
        try(var admin=stoppedAdmin(pair[0]);var member=new LanControllerHarness(pair[1])){
            var once=new AtomicBoolean();
            member.disk.afterStage=()->{
                if(security)member.link.beforeOpen=()->{if(once.compareAndSet(false,true))throw new SecurityException("test socket permission failure");};
                else member.link.failOpens=1;
            };
            beginRejoin(member,admin);
            LanControllerHarness.until(()->!member.ui.last.busy,admin,member);
            assertTrue(member.ui.last.ready);assertFalse(member.ui.last.running);assertFalse(member.ui.last.rejoin);
            assertTrue(member.ui.last.text.contains("待ち受けを開けません。ポートを確かめてください"));assertFalse(Arrays.equals(previous,member.disk.state.value));
            try(var saved=member.disk.load(CLOCK)){assertEquals(CLOCK.millis(),saved.certificate.issuedAt());}
            member.controller.connect();member.drain();assertTrue(member.ui.last.running);
        }
    }
    @Test public void legacyValidControllerStartsAutomaticallyWithoutChangingIdentityOrCertificate()throws Exception{legacy("valid",false,false);}
    @Test public void legacyExpiredMemberKeepsMigratedBytesAndOffersRejoin()throws Exception{legacy("member-expired",true,false);}
    @Test public void legacyExpiredAdministratorRenewsAndStartsWithoutRejoin()throws Exception{legacy("expired",false,true);}
    void legacy(String name,boolean rejoin,boolean renewed)throws Exception{
        byte[] bytes=StorageGroupTest.fixture(3,name),id,certificate;int port;
        try(var original=LanGroup.decode(bytes,CLOCK,true)){id=original.id();certificate=original.certificate.encode();port=original.port;}
        var disk=new LanControllerHarness.Disk(port);disk.state.value=disk.envelope.seal(bytes);
        try(var node=new LanControllerHarness(disk)){
            assertTrue(node.ui.last.ready);assertEquals(!rejoin,node.ui.last.running);assertEquals(rejoin,node.ui.last.rejoin);assertFalse(disk.erased);
            assertFalse(node.ui.last.text.contains("保存が古い状態に戻っています"));assertEquals(rejoin?0:1,node.link.opens);
            try(var saved=disk.load(CLOCK)){
                assertArrayEquals(id,saved.id());assertEquals(renewed?1:0,saved.renewalCount);
                if(!renewed)assertArrayEquals(certificate,saved.certificate.encode());else assertTrue(saved.certificate.issuedAt()>AdminRecords.decode(certificate).issuedAt());
            }
            byte[] migrated=disk.state.value.clone();node.tick();assertArrayEquals(migrated,disk.state.value);
        }
        byte[] migrated=disk.state.value.clone();try(var next=new LanControllerHarness(disk)){assertTrue(next.ui.last.ready);assertArrayEquals(migrated,disk.state.value);}
    }
    @Test public void expiredRunningAdministratorRenewsOnceAndReopens()throws Exception{administratorExpiry(false);}
    @Test public void expiredRunningAdministratorSaveFailureWaitsForConnectAndRetries()throws Exception{administratorExpiry(true);}
    void administratorExpiry(boolean fail)throws Exception{
        var wall=new LanAutomaticRenewalTest.Wall();
        try(var admin=new LanControllerHarness(null,CotPort.NONE,wall)){
            admin.create();var endpoint=admin.endpoint();byte[] old=admin.disk.state.value.clone();admin.disk.failSave=fail;
            wall.now.addAndGet(AdminRecords.CERTIFICATE_LIFETIME_MILLIS+1);
            LanControllerHarness.until(()->endpoint.closeReason()==UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED);
            admin.drain();
            LanControllerHarness.until(()->fail?admin.ui.last.text.contains(RENEW_FAILED):admin.ui.last.running&&admin.endpoint()!=endpoint,admin);
            assertTrue(admin.ui.last.ready);assertFalse(admin.ui.last.rejoin);assertFalse(admin.disk.erased);
            if(fail){assertFalse(admin.ui.last.text.contains("証明書 期限切れ（入り直しが必要）"));assertFalse(admin.ui.last.running);assertArrayEquals(old,admin.disk.state.value);admin.disk.failSave=false;admin.controller.connect();admin.drain();assertTrue(admin.ui.last.running);}
            try(var saved=admin.disk.load(wall)){assertEquals(1,saved.renewalCount);assertEquals(wall.millis(),saved.certificate.issuedAt());}
        }
    }
    @Test public void reconnectLoadRevocationErasesWhileClockAndInternalKeepBytes()throws Exception{
        for(int reason=0;reason<3;reason++){
            try(var node=new LanControllerHarness()){
                node.create();byte[] revoked=RevokedStoredPeerTest.replaceRevocations(LanBehaviourWiringTest.group(node),LanBehaviourWiringTest.group(node).id());
                node.link.lastIo.close();LanControllerHarness.until(()->!node.ui.last.running,node);
                if(reason==0)node.disk.state.value=node.disk.envelope.seal(revoked);
                else if(reason==1){
                    var earlier=Clock.offset(CLOCK,Duration.ofMinutes(-6));
                    // 保存は正しいまま、読み込みにだけ時計の異常を返す。
                    node.disk.loadClock=earlier;
                }else node.disk.loadFailure=new StoredCertificateFailure(UdpEndpoint.CloseReason.INTERNAL_FAILURE);
                byte[] old=node.disk.state.value.clone();node.offset.addAndGet(5_000_000_000L);node.tick();
                assertTrue(node.ui.last.ready);assertFalse(node.ui.last.running);
                if(reason==0){assertTrue(node.disk.erased);assertNull(node.disk.state.value);assertTrue(node.ui.last.text.contains("自分の証明書が無効です。消去しました"));}
                else{assertFalse(node.disk.erased);assertArrayEquals(old,node.disk.state.value);assertTrue(node.ui.last.text.contains(reason==1?CLOCK_FAILED:"内部の異常で通信を止めました。記録は消していません"));}
            }
        }
    }
    @Test public void peerWithoutSessionDoesNotAdvanceReviewAndRenewsAfterConnecting()throws Exception{
        var pair=validPair();try(var a=pair[0].load(CLOCK);var b=pair[1].load(CLOCK)){
            b.certificate=AdminRecords.certificate(b.groupId,b.certificate.field(0),b.certificate.field(1),b.certificate.field(2),CLOCK.millis()-20L*86_400_000,a.administratorSecret);
            a.peerCertificate=b.certificate;pair[0].save(a);pair[1].save(b);
        }
        try(var admin=new LanControllerHarness(pair[0])){
            admin.tick();assertEquals(false,LanControllerHarness.field(admin.controller,"renewalAttempted"));
            try(var member=new LanControllerHarness(pair[1])){
                LanControllerHarness.until(()->admin.endpoint().isEstablished(LanBehaviourWiringTest.group(member).id()),admin,member);
                admin.offset.addAndGet(5_000_000_000L);member.offset.addAndGet(5_000_000_000L);
                LanControllerHarness.until(()->LanBehaviourWiringTest.group(member).renewalCount==1,admin,member);
                assertEquals(true,LanControllerHarness.field(admin.controller,"renewalAttempted"));
            }
        }
    }
}
