// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.time.*;
public class LanBehaviourTest {
    @Test public void certificateDisplayRoundsUp(){
        assertEquals("証明書 残り 30 日（自動更新 2 回）",CertificateStatus.text(30L*86400000,0,2));
        assertEquals("証明書 残り 30 日（自動更新 2 回）",CertificateStatus.text(30L*86400000,3600000,2));
        assertEquals("証明書 残り 1 日（自動更新 2 回）",CertificateStatus.text(100,99,2));
        assertEquals("証明書 期限切れ（入り直しが必要）",CertificateStatus.text(100,100,2));
        assertEquals("証明書 期限切れ（入り直しが必要）",CertificateStatus.text(100,101,2));
    }
    @Test public void startupReopensSavedGroupAutomatically()throws Exception{
        LanControllerHarness.Disk disk;try(var first=new LanControllerHarness()){first.create();disk=first.disk;}
        try(var next=new LanControllerHarness(disk)){assertTrue(next.ui.last.running);assertEquals(1,next.link.opens);}
    }
    @Test public void startupAdministratorRenewalIsSavedBeforeSessions()throws Exception{
        LanControllerHarness.Disk disk;long expires;
        try(var first=new LanControllerHarness()){first.create();disk=first.disk;try(var group=disk.load(LanControllerHarness.CLOCK)){expires=group.certificate.expiresAt();}}
        var later=Clock.fixed(Instant.ofEpochMilli(expires+1),ZoneOffset.UTC);
        try(var next=new LanControllerHarness(disk,CotPort.NONE,later);var loaded=disk.load(later)){
            assertTrue(next.ui.last.running);assertEquals(1,loaded.renewalCount);assertTrue(loaded.certificate.expiresAt()>expires);
        }
    }
    @Test public void startupDoesNotRestoreInvitation()throws Exception{
        LanControllerHarness.Disk disk;try(var first=new LanControllerHarness()){first.create();try(var invitation=first.invitation()){}disk=first.disk;}
        try(var next=new LanControllerHarness(disk)){assertNull(LanControllerHarness.field(next.controller,"invitation"));assertNull(LanControllerHarness.field(next.controller,"invitationSecrets"));assertNull(LanControllerHarness.field(next.controller,"joiningOperation"));assertNull(disk.temporary.value);}
    }
    @Test public void stopDoesNotReconnectOnPoll()throws Exception{
        try(var f=new LanControllerHarness()){f.create();f.controller.disconnect();f.drain();f.offset.addAndGet(120_000_000_000L);f.tick();assertFalse(f.ui.last.running);}
    }
    @Test public void sessionLossOnSameNetworkReconnectsWithoutButton()throws Exception{
        try(var a=new LanControllerHarness();var b=new LanControllerHarness()){
            a.create();b.beginJoin(a);LanControllerHarness.until(()->b.ui.last.member&&a.logs.contains("LAN_MEMBER_ISSUED"),a,b);
            a.controller.connect();a.drain();byte[] id;try(var saved=b.disk.load(LanControllerHarness.CLOCK)){id=saved.id();}
            LanControllerHarness.until(()->a.endpoint().isEstablished(id)&&a.ui.last.text.contains("セッション: 確立"),a,b);
            var endpoint=a.endpoint();var sessions=(SessionManager)LanControllerHarness.field(endpoint,"sessions");
            synchronized(sessions){
                var peers=(java.util.Map<?,?>)LanControllerHarness.field(sessions,"peers");
                for(Object peer:peers.values()){
                    var active=LanControllerHarness.field(peer,"active");
                    if(active!=null)((NoiseTransport)LanControllerHarness.field(active,"transport")).close();
                }
                sessions.refresh();
            }
            a.tick();assertFalse(endpoint.isEstablished(id));assertSame(endpoint,a.endpoint());
            a.offset.addAndGet(5_000_000_000L);b.offset.addAndGet(5_000_000_000L);
            LanControllerHarness.until(()->endpoint.isEstablished(id),a,b);assertSame(endpoint,a.endpoint());
        }
    }
}
