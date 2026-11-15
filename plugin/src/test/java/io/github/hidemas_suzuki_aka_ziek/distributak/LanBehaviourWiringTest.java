// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.net.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
public class LanBehaviourWiringTest {
    static final Clock CLOCK=LanControllerHarness.CLOCK;
    static LanGroup group(LanControllerHarness f)throws Exception{return (LanGroup)LanControllerHarness.field(f.controller,"group");}
    static void closed(LanControllerHarness f,UdpEndpoint.CloseReason reason)throws Exception{
        var method=LanController.class.getDeclaredMethod("closed",long.class,UdpEndpoint.CloseReason.class);method.setAccessible(true);
        method.invoke(f.controller,((AtomicLong)LanControllerHarness.field(f.controller,"generation")).get(),reason);f.drain();
    }
    static void renewal(LanControllerHarness f,AdminRecords.Record certificate)throws Exception{
        var method=LanController.class.getDeclaredMethod("applyRenewal",AdminRecords.Record.class);method.setAccessible(true);
        method.invoke(f.controller,certificate);
    }
    static AdminRecords.Record renewed(LanGroup g){return AdminRecords.certificate(g.groupId,g.certificate.field(0),g.certificate.field(1),g.certificate.field(2),CLOCK.millis()+1,g.administratorSecret);}
    @Test public void renewalSaveFailureDoesNotUpdateCore()throws Exception{
        try(var f=new LanControllerHarness()){f.create();var cert=renewed(group(f));byte[] old=f.disk.state.value.clone();f.disk.failSave=true;
            renewal(f,cert);assertTrue(f.endpoint().validateLocalCertificateRenewal(cert));assertEquals(0,group(f).renewalCount);assertArrayEquals(old,f.disk.state.value);assertTrue(f.logs.contains("LAN_RENEWAL_REJECTED"));}
    }
    @Test public void renewalSuccessUpdatesCoreAfterSaveAndDuplicateDoesNotCount()throws Exception{
        try(var f=new LanControllerHarness()){f.create();var cert=renewed(group(f));renewal(f,cert);assertFalse(f.endpoint().validateLocalCertificateRenewal(cert));
            try(var saved=f.disk.load(CLOCK)){assertArrayEquals(cert.encode(),saved.certificate.encode());assertEquals(1,saved.renewalCount);}
            renewal(f,cert);assertEquals(1,group(f).renewalCount);}
    }
    @Test public void newerPeerCertificateWithoutAuthenticatedFirstDoesNotConfirmPendingRenewal()throws Exception{
        try(var f=new LanControllerHarness()){f.create();var g=group(f);var old=StoredUpdatesTest.peer(g,71,72,CLOCK.millis()-1);var next=StoredUpdatesTest.peer(g,71,72,CLOCK.millis());
            var address=new InetSocketAddress("192.0.2.200",54321);f.disk.savePeer(g,old,address);byte[] id=Crypto.blake2s(old.field(0));f.disk.saveIssuedRenewal(g,id,next.encode());
            f.endpoint().rememberPeer(next);f.endpoint().setPeerAddress(id,address);f.tick();
            try(var loaded=f.disk.load(CLOCK)){assertTrue(java.util.Arrays.equals(old.encode(),loaded.peerCertificate.encode()));assertNotNull(loaded.pendingRenewal(id));}}
    }
    @Test public void internalClosedListenerKeepsStateAndDoesNotReconnect()throws Exception{
        try(var f=new LanControllerHarness()){f.create();byte[] old=f.disk.state.value.clone();closed(f,UdpEndpoint.CloseReason.INTERNAL_FAILURE);f.offset.addAndGet(120_000_000_000L);f.tick();
            assertFalse(f.ui.last.running);assertArrayEquals(old,f.disk.state.value);assertTrue(f.ui.last.text.contains("内部の異常で通信を止めました。記録は消していません"));}
    }
    @Test public void expiryClosedListenerEnablesRejoinAndKeepsState()throws Exception{
        var pair=LanBehaviourFixTest.validPair();
        try(var f=new LanControllerHarness(pair[1])){byte[] old=f.disk.state.value.clone();closed(f,UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED);f.offset.addAndGet(120_000_000_000L);f.tick();assertFalse(f.ui.last.running);assertTrue(f.ui.last.rejoin);assertArrayEquals(old,f.disk.state.value);assertTrue(f.ui.last.text.contains("証明書の期限が切れました。管理者の新しい招待を読んでください"));}
    }
    @Test public void transientClosedListenerWaitsFiveSecondsAndReopensSameNetwork()throws Exception{
        for(var reason:List.of(UdpEndpoint.CloseReason.CLOCK_FAILURE,UdpEndpoint.CloseReason.RANDOM_FAILURE,UdpEndpoint.CloseReason.RECEIVE_FAILURE))try(var f=new LanControllerHarness()){
            f.create();closed(f,reason);f.tick();assertFalse(f.ui.last.running);f.offset.addAndGet(5_000_000_000L);f.tick();assertTrue(f.ui.last.running);}
    }
    @Test public void thirdConsecutiveEndpointFailureStopsReopening()throws Exception{
        try(var f=new LanControllerHarness()){f.create();for(int i=0;i<3;i++){closed(f,UdpEndpoint.CloseReason.RECEIVE_FAILURE);f.offset.addAndGet(60_000_000_000L);f.tick();}
            assertFalse(f.ui.last.running);assertTrue(f.ui.last.text.contains("続けて3回失敗したため"));}
    }
    @Test public void wifiLossAndReturnDoesNotAutomaticallyReopen()throws Exception{
        try(var f=new LanControllerHarness()){f.create();f.network.current=null;f.network.changed.run();f.drain();f.network.current=f.link;f.network.changed.run();f.drain();f.offset.addAndGet(120_000_000_000L);f.tick();assertFalse(f.ui.last.running);}
    }
    @Test public void rollbackUsesDedicatedScreenAndLeavesBytes()throws Exception{
        LanControllerHarness.Disk disk;byte[] old;
        try(var f=new LanControllerHarness()){f.create();disk=f.disk;old=disk.state.value.clone();disk.save(group(f));}
        disk.state.value=old;
        try(var f=LanControllerHarness.unreadable(disk,CLOCK)){assertTrue(f.ui.last.text.contains("保存が古い状態に戻っています"));assertArrayEquals(old,disk.state.value);assertFalse(disk.erased);}
    }
    @Test public void futureCertificateClockScreenLeavesBytes()throws Exception{
        LanControllerHarness.Disk disk;try(var f=new LanControllerHarness()){f.create();disk=f.disk;}
        byte[] old=disk.state.value.clone();
        try(var f=LanControllerHarness.unreadable(disk,Clock.offset(CLOCK,Duration.ofMinutes(-6)))){assertTrue(f.ui.last.text.contains("端末の時計がずれています"));assertArrayEquals(old,disk.state.value);assertFalse(disk.erased);}
    }
    @Test public void expiredPeerRetainsSlotButIsNotGivenToSessions()throws Exception{
        try(var g=LanGroup.create(54321,CLOCK,new java.security.SecureRandom())){
            g.peerCertificate=StoredUpdatesTest.peer(g,71,72,CLOCK.millis()-AdminRecords.CERTIFICATE_LIFETIME_MILLIS);g.peerAddress=new InetSocketAddress("192.0.2.1",54322);
            try(var loaded=LanGroup.decode(g.encode(),CLOCK,true);var sessions=loaded.sessions(CLOCK,()->0)){
                assertNotNull(loaded.peerCertificate);assertNull(sessions.peerCertificate(Crypto.blake2s(g.peerCertificate.field(0))));}
        }
    }

    @Test public void negativeClockUsesClockScreenWithoutChangingBytes()throws Exception{
        LanControllerHarness.Disk disk;try(var f=new LanControllerHarness()){f.create();disk=f.disk;}
        byte[] old=disk.state.value.clone();try(var f=LanControllerHarness.unreadable(disk,Clock.fixed(Instant.ofEpochMilli(-1),ZoneOffset.UTC))){
            assertTrue(f.ui.last.text.contains("端末の時計がずれています"));assertArrayEquals(old,disk.state.value);assertFalse(disk.erased);
        }
    }
    @Test public void eraseCreateReloadDoesNotTriggerRollback()throws Exception{
        LanControllerHarness.Disk disk;try(var f=new LanControllerHarness()){
            f.create();f.controller.erase();f.drain();f.create();disk=f.disk;
        }
        try(var f=new LanControllerHarness(disk)){assertTrue(f.ui.last.ready);assertTrue(f.ui.last.running);assertFalse(f.ui.last.text.contains("保存が古い状態に戻っています"));}
    }
    @Test public void largeStateUsesFixedWarning()throws Exception{
        LanControllerHarness.Disk disk;
        try(var f=new LanControllerHarness()){f.create();var g=group(f);var admins=AdministratorFixtures.bindings(g,12);
            for(int v=1;v<=130;v++)g.state.acceptAdministrators(AdminRecords.administrators(g.groupId,v,CLOCK.millis(),admins,g.administratorSecret),x->fail());
            f.disk.save(g);disk=f.disk;
        }
        try(var f=new LanControllerHarness(disk)){assertTrue(f.ui.last.text.contains("保存の大きさが512KiBを超えています"));assertTrue(f.ui.last.running);}
    }
    @Test public void malformedPendingRenewalWarnsWithoutStopping()throws Exception{
        LanControllerHarness.Disk disk;
        try(var f=new LanControllerHarness()){f.create();var g=group(f);var old=StoredUpdatesTest.peer(g,71,72,CLOCK.millis()-1);
            f.disk.savePeer(g,old,new InetSocketAddress("192.0.2.200",54321));
            f.disk.saveIssuedRenewal(g,Crypto.blake2s(old.field(0)),StoredUpdatesTest.peer(g,71,72,CLOCK.millis()).encode());
            byte[] plain=f.disk.envelope.open(f.disk.state.value);plain[plain.length-9]^=1;f.disk.state.value=f.disk.envelope.seal(plain);Crypto.wipe(plain);disk=f.disk;
        }
        try(var f=new LanControllerHarness(disk)){assertTrue(f.ui.last.text.contains("保存した証明書の更新を1件捨てました。次の更新で作り直します"));assertTrue(f.ui.last.running);}
    }
    @Test public void newerKeyHintDoesNotStopOrSaveOrDisableReconnect()throws Exception{
        try(var f=new LanControllerHarness()){f.create();byte[] old=f.disk.state.value.clone();var endpoint=f.endpoint();
            var sessions=(SessionManager)LanControllerHarness.field(endpoint,"sessions");
            assertThrows(RuntimeException.class,()->sessions.receive(new SessionPacket(SessionPacket.FIRST,new byte[16],1,0,new byte[108]).encode()));
            f.tick();assertTrue(f.ui.last.rejoin);assertSame(endpoint,f.endpoint());assertArrayEquals(old,f.disk.state.value);
            assertTrue(f.ui.last.text.contains("新しいグループの鍵があるようです。管理者の新しい招待を読んでください"));
            closed(f,UdpEndpoint.CloseReason.RECEIVE_FAILURE);f.offset.addAndGet(5_000_000_000L);f.tick();assertTrue(f.ui.last.running);
        }
    }
    @Test public void invitationSecretIsNotEncodedAndStopWipesDedicatedCopies()throws Exception{
        try(var f=new LanControllerHarness()){f.create();try(var invitation=f.invitation()){
            byte[] encoded=group(f).encode(),secret=invitation.totpSecret();
            try{assertFalse(contains(encoded,secret));assertFalse(contains(f.disk.envelope.open(f.disk.state.value),secret));}
            finally{Crypto.wipe(encoded);Crypto.wipe(secret);}
            byte[][] dedicated=(byte[][])LanControllerHarness.field(f.controller,"invitationSecrets");
            f.controller.disconnect();f.drain();for(byte[] bytes:dedicated)assertArrayEquals(new byte[bytes.length],bytes);
            assertNull(LanControllerHarness.field(f.controller,"invitationSecrets"));
        }}
    }
    static boolean contains(byte[] haystack,byte[] needle){for(int i=0;i<=haystack.length-needle.length;i++)if(Arrays.equals(Arrays.copyOfRange(haystack,i,i+needle.length),needle))return true;return false;}
    @Test public void administratorRenewalSaveFailureLeavesOriginalBytesAndDoesNotOpenSessions()throws Exception{
        LanControllerHarness.Disk disk;long expires;
        try(var f=new LanControllerHarness()){f.create();disk=f.disk;expires=group(f).certificate.expiresAt();}
        byte[] old=disk.state.value.clone();disk.failSave=true;
        try(var f=new LanControllerHarness(disk,CotPort.NONE,Clock.fixed(Instant.ofEpochMilli(expires+1),ZoneOffset.UTC))){assertTrue(f.ui.last.ready);assertTrue(f.ui.last.text.contains("証明書の更新に失敗しました。接続するを押してください"));assertFalse(f.ui.last.running);assertArrayEquals(old,disk.state.value);assertFalse(disk.erased);}
    }
}
