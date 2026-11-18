// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.time.*;
import java.util.concurrent.atomic.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class LanAdministratorCertificateTest {
    static final long NOW=LanControllerHarness.CLOCK.millis();
    static final class Time extends Clock {
        volatile long millis=NOW-1;
        public ZoneId getZone(){return ZoneOffset.UTC;}
        public Clock withZone(ZoneId zone){return this;}
        public Instant instant(){return Instant.ofEpochMilli(millis);}
        public long millis(){return millis;}
    }
    static LanControllerHarness.Disk[] pair()throws Exception {
        var pair=LanBehaviourFixTest.validPair();
        try(var admin=pair[0].load(LanControllerHarness.CLOCK);var member=pair[1].load(LanControllerHarness.CLOCK)){
            admin.certificate=AdminRecords.certificate(admin.groupId,admin.certificate.field(0),admin.certificate.field(1),
                    admin.certificate.field(2),NOW-AdminRecords.CERTIFICATE_LIFETIME_MILLIS,admin.administratorSecret);
            member.peerCertificate=admin.certificate;
            pair[0].save(admin);pair[1].save(member);
        }
        return pair;
    }
    static SessionManager sessions(LanControllerHarness member)throws Exception {
        return (SessionManager)LanControllerHarness.field(member.endpoint(),"sessions");
    }
    static LanGroup group(LanControllerHarness node)throws Exception{return LanBehaviourWiringTest.group(node);}
    static void conditions(LanControllerHarness member,LanGroup admin)throws Exception {
        var saved=group(member);
        assertEquals(NOW,saved.peerCertificate.expiresAt());
        assertTrue(saved.certificate.expiresAt()>NOW);
        assertTrue(admin.peerCertificate.expiresAt()>NOW);
        assertNotNull(admin.peerAddress);
        assertEquals(saved.keyVersion,admin.keyVersion);
        assertTrue(admin.certificate.issuedAt()>saved.peerCertificate.issuedAt());
        assertArrayEquals(saved.peerCertificate.field(0),admin.certificate.field(0));
        assertTrue(saved.state.administrators().hasEntry(admin.certificate.signer()));
        assertFalse(saved.state.revocations().hasEntry(admin.id()));
        saved.state.verifyCertificate(admin.certificate,admin.certificate.field(1));
    }
    @Test public void restartedMemberReceivesAndPersistsNewAdministratorFirst()throws Exception {accept(false);}
    @Test public void runningMemberReceivesAndPersistsNewAdministratorFirst()throws Exception {accept(true);}
    @Test public void expiredAdministratorSlotAloneDoesNotAllowRejoin()throws Exception {
        var disks=pair();
        try(var member=new LanControllerHarness(disks[1])){
            var endpoint=member.endpoint();byte[] oldBytes=member.disk.state.value.clone();
            assertEquals(NOW,group(member).peerCertificate.expiresAt());assertTrue(group(member).certificate.expiresAt()>NOW);
            assertFalse(member.ui.last.rejoin);
            try(var admin=new LanControllerHarness(disks[0])){
                member.controller.join(admin.rejoinInvitation(),member.controller.ticket());member.drain();
                assertTrue(member.ui.last.text.contains("所属済みです"));
                assertSame(endpoint,member.endpoint());assertArrayEquals(oldBytes,member.disk.state.value);
            }
        }
    }
    private void accept(boolean running)throws Exception {
        var disks=pair();var time=new Time();if(!running)time.millis=NOW;
        try(var member=new LanControllerHarness(disks[1],CotPort.NONE,time)){
            var endpoint=member.endpoint();byte[] adminId;
            try(var saved=disks[0].load(LanControllerHarness.CLOCK)){adminId=saved.id();}
            if(running){
                assertNotNull(sessions(member).peerCertificate(adminId));
                time.millis=NOW;sessions(member).refresh();
                assertNull(sessions(member).peerCertificate(adminId));
                var peers=(java.util.Map<?,?>)LanControllerHarness.field(sessions(member),"peers");
                assertEquals(1,peers.size());
                Object slot=peers.values().iterator().next();
                assertEquals(NOW,((AdminRecords.Record)LanControllerHarness.field(slot,"certificate")).expiresAt());
            }else assertTrue(((java.util.Map<?,?>)LanControllerHarness.field(sessions(member),"peers")).isEmpty());
            assertFalse(endpoint.isEstablished(adminId));
            try(var admin=new LanControllerHarness(disks[0])){
                conditions(member,group(admin));byte[] renewed=group(admin).certificate.encode();
                LanControllerHarness.until(()->endpoint.isEstablished(adminId),admin);
                assertSame(endpoint,member.endpoint());
                assertArrayEquals(renewed,endpoint.authenticatedFirstCertificate(adminId).encode());
                LanControllerHarness.until(()->{
                    try(var loaded=disks[1].load(LanControllerHarness.CLOCK)){
                        return java.util.Arrays.equals(renewed,loaded.peerCertificate.encode());
                    }
                },member,admin);
                try(var loaded=disks[1].load(LanControllerHarness.CLOCK)){
                    assertArrayEquals(renewed,loaded.peerCertificate.encode());
                    assertEquals(admin.link.address,loaded.peerAddress.getAddress());
                    assertEquals(admin.disk.port,loaded.peerAddress.getPort());
                }
                assertTrue(member.ui.last.running);assertSame(endpoint,member.endpoint());
            }
        }
    }
    @Test public void newAdministratorFirstSaveFailureRestoresStateAndStopsCommunication()throws Exception {
        var disks=pair();
        try(var member=new LanControllerHarness(disks[1])){
            var previous=group(member);var endpoint=member.endpoint();
            byte[] adminId=Crypto.blake2s(previous.peerCertificate.field(0));
            byte[] oldCertificate=previous.peerCertificate.encode();var oldAddress=previous.peerAddress;
            // 一般メンバーは更新待ちを持てないので null。相手の枠があるときは予約もない。
            // A general member cannot hold a pending renewal, so it is null; a stored peer also excludes a pin.
            assertNull(previous.pendingRenewal(adminId));assertNull(previous.pendingHandshake);assertNull(previous.pendingAddress);
            try(var admin=new LanControllerHarness(disks[0])){
                conditions(member,group(admin));
                byte[] renewed=group(admin).certificate.encode();
                byte[] oldBytes=member.disk.state.value.clone();long oldSequence=previous.saveSeq;
                LanControllerHarness.until(()->endpoint.authenticatedFirstCertificate(adminId)!=null,admin);
                assertArrayEquals(renewed,endpoint.authenticatedFirstCertificate(adminId).encode());
                assertArrayEquals(renewed,endpoint.knownPeers().get(0).certificate().encode());
                // 認証済み DATA で番地が先に変わった状態を再現する。FIRST 自身は保存した相手の番地を変えない（UdpEndpoint 561〜582 行）。
                // Reproduce an address already changed by authenticated DATA; FIRST itself does not change a stored peer's address (UdpEndpoint lines 561–582).
                var learnedAddress=new java.net.InetSocketAddress(oldAddress.getAddress(),LanControllerHarness.freePort());
                assertNotEquals(oldAddress,learnedAddress);endpoint.setPeerAddress(adminId,learnedAddress);
                assertEquals(learnedAddress,endpoint.knownPeers().get(0).address());
                assertArrayEquals(oldCertificate,previous.peerCertificate.encode());
                var closed=new AtomicBoolean();
                member.link.afterIoClose=()->{
                    assertArrayEquals(oldBytes,member.disk.state.value);
                    assertArrayEquals(oldCertificate,previous.peerCertificate.encode());
                    assertEquals(oldAddress,previous.peerAddress);
                    assertNull(previous.pendingHandshake);assertNull(previous.pendingAddress);
                    assertNull(previous.pendingRenewal(adminId));assertEquals(oldSequence,previous.saveSeq);
                    closed.set(true);
                };
                member.disk.failSave=true;
                member.tick();
                assertTrue(closed.get());assertNull(member.endpoint());assertNull(group(member));
                assertFalse(member.ui.last.running);assertFalse(member.ui.last.ready);
                assertTrue(member.logs.contains("LAN_STOPPED"));
                assertEquals(UdpEndpoint.CloseReason.CLOSED_BY_CALLER,endpoint.closeReason());
                assertFalse(((ReconnectSupervisor)LanControllerHarness.field(member.controller,"reconnect")).active());
                int opens=member.link.opens;member.offset.addAndGet(120_000_000_000L);member.tick();assertEquals(opens,member.link.opens);
                assertArrayEquals(oldBytes,member.disk.state.value);assertFalse(member.disk.erased);
                member.disk.failSave=false;
                try(var loaded=member.disk.load(LanControllerHarness.CLOCK)){
                    assertArrayEquals(oldCertificate,loaded.peerCertificate.encode());assertEquals(oldAddress,loaded.peerAddress);
                    assertNull(loaded.pendingHandshake);assertNull(loaded.pendingAddress);
                    assertNull(loaded.pendingRenewal(adminId));assertEquals(oldSequence,loaded.saveSeq);
                }
            }
        }
    }
}
