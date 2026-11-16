// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class AdministrationCertificateSwitchTest {
    final AdministrationPreparationTest p=new AdministrationPreparationTest();final GroupAdministrationTest t=p.t;final SessionManagerTest f=p.f;
    void copyGrant(SessionManagerTest.Node m,GroupAdministration ga,GroupAdministration.Candidate grant){
        var aKey=Crypto.ed25519Public(f.admin);
        m.state.acceptAdministrators(AdminRecords.administrators(f.group,1,f.time.millis(),ga.bindings().stream().filter(x->Crypto.equal(x.administratorKey(),aKey)).toList(),f.admin),v->fail());
        m.state.acceptAdministrators(grant.administrators(),v->fail());m.state.acceptRevocations(grant.revocations());
    }
    AdminState restore(AdminState state)throws Exception{
        var store=new InMemoryAdminRecordStore();store.save(state.snapshot());
        var restored=new AdminState(f.group,Crypto.ed25519Public(f.admin),f.time,store);restored.restore();return restored;
    }
    @Test void preSwitchedBAndOnlineMConnectAfterARemovalRestoreAndNewInvitation()throws Exception{
        try(var a=f.new Node(1);var b=f.new Node(2);var m=f.new Node(3);var ga=t.service(a,true);var gb=t.service(b,false);var gm=t.service(m,false)){
            var grant=p.grant(a,b,ga,gb);copyGrant(m,ga,grant);f.connect(b,m);
            gb.joined(new UdpEndpoint.AdminJoined(m.cert,new java.net.InetSocketAddress("192.0.2.1",54321)));
            f.time.advance(6);var preparation=gb.prepareRemoval(b.sessions,List.of(Crypto.ed25519Public(f.admin)),false);
            preparation.reissue(c->{});b.cert=gb.certificate();b.sessions.updateLocalCertificate(b.cert);
            var delivery=preparation.next(m.id,c->{});m.cert=gm.receiveCertificateDelivery(m.sessions,b.id,m.sessions.sessionId(b.id),delivery,c->{});m.sessions.updateLocalCertificate(m.cert);
            p.first(m,b);assertTrue(preparation.confirm(m.id));var removal=preparation.commit();preparation.publish(removal,s->{},c->{});
            gm.persist(gm.received(removal.administrators(),removal.revocations()),s->{},c->{});
            var restoredB=restore(b.state);var restoredM=restore(m.state);
            try(var bs=new SessionManager(restoredB,b.cert,b.secret,f.psk,0,f.time,()->f.time.nanos,256);
                var ms=new SessionManager(restoredM,m.cert,m.secret,f.psk,0,f.time,()->f.time.nanos,256)){
                bs.rememberPeer(m.cert);ms.rememberPeer(b.cert);var second=bs.receive(ms.start(b.id).packet());
                var confirm=ms.receive(second.outbound().get(0).packet());bs.receive(confirm.outbound().get(0).packet());
                assertTrue(bs.isEstablished(m.id));assertTrue(ms.isEstablished(b.id));
                assertFalse(restoredB.administrators().hasEntry(Crypto.ed25519Public(f.admin)));
            }
            try(var invite=gb.invitation(new byte[]{(byte)192,0,2,1},54321,key(92));var issuer=gb.invitationIssuer(invite);
                var joiner=new JoinHandshake.Joiner(invite,key(94),key(95),f.time);
                var joined=joiner.receive(gb.respondInvitation(issuer,joiner.request(),f.psk,0))){
                assertArrayEquals(f.psk,joined.groupKey());assertNotNull(joined.state().announcement());
                assertTrue(Crypto.equal(f.group,joined.certificate().group()));
            }
        }
    }
    static final class QuietIo implements UdpEndpoint.DatagramIo {
        private final CountDownLatch closed=new CountDownLatch(1);
        public UdpEndpoint.Datagram receive()throws java.io.IOException{
            try{closed.await();}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
            throw new java.io.IOException("closed");
        }
        public void send(byte[] wire,java.net.InetSocketAddress target){}
        public void close(){closed.countDown();}
    }
    @Test void offlineMAutomaticallyErasesOnIssuerRemovalThenJoinsWithNewIdentity()throws Exception{
        try(var a=f.new Node(1);var b=f.new Node(2);var m=f.new Node(3);var ga=t.service(a,true);var gb=t.service(b,false)){
            var grant=p.grant(a,b,ga,gb);copyGrant(m,ga,grant);f.time.advance(6);
            var preparation=gb.prepareRemoval(b.sessions,List.of(Crypto.ed25519Public(f.admin)),false);preparation.reissue(c->{});
            b.cert=gb.certificate();b.sessions.updateLocalCertificate(b.cert);
            var removal=preparation.commit();preparation.publish(removal,s->{},c->{});
            var erased=new CountDownLatch(1);var reason=new java.util.concurrent.atomic.AtomicReference<UdpEndpoint.CloseReason>();
            try(var endpoint=new UdpEndpoint(m.sessions,m.state,new QuietIo(),(peer,plain)->{},Duration.ofDays(1),()->f.time.nanos,value->{
                reason.set(value);if(value==UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_INVALID){m.state.clear();erased.countDown();}
            })){
                assertTrue(endpoint.acceptAdministrators(removal.administrators(),v->fail()));
                assertTrue(erased.await(2,TimeUnit.SECONDS));assertEquals(UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_INVALID,reason.get());
                assertThrows(IllegalStateException.class,m.state::administrators);assertTrue(m.sessions.isClosed());
            }
            try(var invite=gb.invitation(new byte[]{(byte)192,0,2,1},54321,key(96));var issuer=gb.invitationIssuer(invite);
                var joiner=new JoinHandshake.Joiner(invite,key(97),key(98),f.time);
                var joined=joiner.receive(gb.respondInvitation(issuer,joiner.request(),f.psk,0))){
                assertFalse(Crypto.equal(m.id,Crypto.blake2s(joined.certificate().field(0))));assertTrue(Crypto.equal(f.group,joined.certificate().group()));
            }
        }
    }
}
