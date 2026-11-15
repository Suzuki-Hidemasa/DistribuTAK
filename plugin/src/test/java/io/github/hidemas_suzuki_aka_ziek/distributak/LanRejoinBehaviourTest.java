// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.time.Clock;
import java.util.*;
public class LanRejoinBehaviourTest {
    static final Clock CLOCK=LanControllerHarness.CLOCK;
    static LanControllerHarness.Disk[] expiredPair()throws Exception{
        try(var a=new LanControllerHarness();var b=new LanControllerHarness()){
            a.create();b.beginJoin(a);LanControllerHarness.until(()->b.ui.last.member&&a.logs.contains("LAN_MEMBER_ISSUED"),a,b);
            a.controller.connect();a.drain();
            LanControllerHarness.until(()->LanBehaviourWiringTest.group(b).peerCertificate!=null,a,b);
            a.controller.disconnect();b.controller.disconnect();a.drain();b.drain();
            try(var admin=a.disk.load(CLOCK);var member=b.disk.load(CLOCK)){
                var expired=AdminRecords.certificate(member.groupId,member.certificate.field(0),member.certificate.field(1),member.certificate.field(2),CLOCK.millis()-AdminRecords.CERTIFICATE_LIFETIME_MILLIS,admin.administratorSecret);
                member.certificate=expired;admin.peerCertificate=expired;
                a.disk.save(admin);b.disk.save(member);
            }
            return new LanControllerHarness.Disk[]{a.disk,b.disk};
        }
    }
    @Test public void expiredMemberCanRejoinWithIdentityAndRecordsAndStartsFirst()throws Exception{
        var pair=expiredPair();byte[] id,sync=pair[1].sync.value.clone(),external=pair[1].external.value.clone();
        try(var old=pair[1].load(CLOCK)){id=old.id();}
        try(var admin=new LanControllerHarness(pair[0]);var member=new LanControllerHarness(pair[1])){
            assertTrue(member.ui.last.rejoin);assertFalse(member.ui.last.running);assertNotNull(admin.endpoint());
            member.beginJoin(admin);
            LanControllerHarness.until(()->!member.ui.last.busy&&member.ui.last.running,admin,member);
            LanControllerHarness.until(()->admin.endpoint().isEstablished(id),admin,member);
            LanControllerHarness.until(()->{try(var saved=pair[0].load(CLOCK)){return saved.peerCertificate.issuedAt()==CLOCK.millis();}},admin,member);
            try(var current=pair[1].load(CLOCK);var savedAdmin=pair[0].load(CLOCK)){
                assertArrayEquals(id,current.id());assertEquals(0,current.renewalCount);
                assertArrayEquals(current.certificate.encode(),savedAdmin.peerCertificate.encode());
                assertTrue(current.certificate.issuedAt()>CLOCK.millis()-AdminRecords.CERTIFICATE_LIFETIME_MILLIS);
            }
            assertArrayEquals(sync,pair[1].sync.value);assertArrayEquals(external,pair[1].external.value);
        }
    }
    @Test public void rejoinStageFailureKeepsPreviousBytesAndExpiredScreen()throws Exception{
        var pair=expiredPair();byte[] old=pair[1].state.value.clone();
        try(var admin=new LanControllerHarness(pair[0]);var member=new LanControllerHarness(pair[1])){
            member.disk.failStage=true;member.beginJoin(admin);
            LanControllerHarness.until(()->!member.ui.last.busy,admin,member);
            assertArrayEquals(old,pair[1].state.value);assertTrue(member.ui.last.rejoin);assertFalse(member.ui.last.running);
            try(var saved=pair[0].load(CLOCK)){assertTrue(saved.peerCertificate.expiresAt()<=CLOCK.millis());}
        }
    }
    @Test public void unrelatedInvitationDoesNotStopKeyMissedEndpointOrWriteState()throws Exception{
        try(var member=new LanControllerHarness()){
            member.create();var field=LanController.class.getDeclaredField("keyMissed");field.setAccessible(true);field.setBoolean(member.controller,true);
            byte[] old=member.disk.state.value.clone();var endpoint=member.endpoint();int opens=member.link.opens;
            member.controller.join(member.unreachable(),member.controller.ticket());member.drain();
            assertSame(endpoint,member.endpoint());assertEquals(opens,member.link.opens);assertArrayEquals(old,member.disk.state.value);
        }
    }
    @Test public void staleReplyKeepsKeyMissedBytesAndRestoresPreviousEndpoint()throws Exception{
        var pair=expiredPair();
        try(var admin=pair[0].load(CLOCK);var member=pair[1].load(CLOCK)){
            member.certificate=AdminRecords.certificate(member.groupId,member.certificate.field(0),member.certificate.field(1),member.certificate.field(2),CLOCK.millis(),admin.administratorSecret);
            member.keyVersion=1;pair[1].save(member);
        }
        byte[] old=pair[1].state.value.clone();
        try(var admin=new LanControllerHarness(pair[0]);var member=new LanControllerHarness(pair[1])){
            var marker=LanController.class.getDeclaredField("keyMissed");marker.setAccessible(true);marker.setBoolean(member.controller,true);
            int opens=member.link.opens;member.beginJoin(admin);
            LanControllerHarness.until(()->!member.ui.last.busy,admin,member);
            assertArrayEquals(old,pair[1].state.value);assertTrue(member.ui.last.running);assertTrue(member.link.opens>opens);
            assertEquals(1,LanBehaviourWiringTest.group(member).keyVersion);
        }
    }
    @Test public void firstWithDifferentIdentityOlderIssueOrSameIssueDifferentKeyDoesNotChangeAdmin()throws Exception{
        for(int scenario=0;scenario<3;scenario++){
            var pair=expiredPair();byte[] expected;
            try(var admin=pair[0].load(CLOCK);var member=pair[1].load(CLOCK)){
                var previous=AdminRecords.certificate(member.groupId,member.certificate.field(0),member.certificate.field(1),member.certificate.field(2),CLOCK.millis()-1,admin.administratorSecret);
                admin.peerCertificate=previous;pair[0].save(admin);expected=previous.encode();
                Crypto.wipe(member.handshakeSecret);member.handshakeSecret=StoredUpdatesTest.key(91);
                if(scenario==0){Crypto.wipe(member.identitySecret);member.identitySecret=StoredUpdatesTest.key(92);member.syncInitialized=false;pair[1].sync.value=null;pair[1].external.value=null;}
                byte[] handshake=Crypto.x25519Public(member.handshakeSecret);
                member.certificate=AdminRecords.certificate(member.groupId,Crypto.ed25519Public(member.identitySecret),handshake,SignaturePurpose.identityProof(member.identitySecret,member.groupId,handshake),CLOCK.millis()-(scenario==0?0:scenario==1?2:1),admin.administratorSecret);
                pair[1].save(member);
            }
            byte[] old=pair[0].state.value.clone();
            try(var admin=new LanControllerHarness(pair[0]);var member=new LanControllerHarness(pair[1])){
                LanControllerHarness.until(()->admin.endpoint().rejectedPackets()>0,admin,member);
                assertArrayEquals(old,pair[0].state.value);assertArrayEquals(expected,admin.endpoint().knownPeers().get(0).certificate().encode());
                try(var saved=pair[0].load(CLOCK)){assertArrayEquals(expected,saved.peerCertificate.encode());}
            }
        }
    }
}
