// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class AdministrationPreparationTest {
    final GroupAdministrationTest t=new GroupAdministrationTest();final SessionManagerTest f=t.f;
    void first(SessionManagerTest.Node from,SessionManagerTest.Node to) {
        var reply=to.sessions.receive(from.sessions.start(to.id).packet());
        var confirmation=from.sessions.receive(reply.outbound().get(0).packet());to.sessions.receive(confirmation.outbound().get(0).packet());
    }
    GroupAdministration.Candidate grant(SessionManagerTest.Node a,SessionManagerTest.Node b,GroupAdministration ga,GroupAdministration gb) {
        t.connect(a,b,ga,gb);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),gb.request(b.sessions,a.id));var c=ga.approve(a.sessions,b.id);
        ga.persist(c,s->{},x->{});gb.persist(gb.received(c.administrators(),c.revocations()),s->{},x->{});return c;
    }
    @Test void retainedAdministratorReissuesSelfAndOnlineMemberBeforeRemovingIssuer() {
        try(var a=f.new Node(1);var b=f.new Node(2);var m=f.new Node(3);var ga=t.service(a,true);var gb=t.service(b,false);var gm=t.service(m,false)) {
            var grant=grant(a,b,ga,gb);var aKey=Crypto.ed25519Public(f.admin);
            var bound=AdminRecords.administrators(f.group,1,f.time.millis,ga.bindings().stream().filter(x->Crypto.equal(x.administratorKey(),aKey)).toList(),f.admin);
            m.state.acceptAdministrators(bound,v->fail());m.state.acceptAdministrators(grant.administrators(),v->fail());m.state.acceptRevocations(grant.revocations());
            f.connect(b,m);gb.joined(new UdpEndpoint.AdminJoined(m.cert,new java.net.InetSocketAddress("192.0.2.1",54321)));
            f.time.advance(6);var preparation=gb.prepareRemoval(b.sessions,List.of(aKey),false);assertEquals(GroupAdministration.Phase.PREPARE,preparation.phase());
            preparation.reissue(c->{});b.sessions.updateLocalCertificate(gb.certificate());b.cert=gb.certificate();
            var delivery=preparation.next(m.id,c->{});assertEquals(RenewalMessage.Operation.CERTIFICATE_DELIVERY,delivery.operation());
            var saved=new ArrayList<AdminRecords.Record>();
            var next=gm.receiveCertificateDelivery(m.sessions,b.id,m.sessions.sessionId(b.id),delivery,saved::add);
            assertEquals(1,saved.size());assertTrue(Arrays.equals(next.encode(),saved.get(0).encode()));m.sessions.updateLocalCertificate(next);m.cert=next;
            // Bが始めて受けたSECONDだけでは確定しない。
            first(b,m);assertFalse(preparation.confirm(m.id));assertThrows(SecurityException.class,preparation::commit);
            f.time.advance(6);first(m,b);assertTrue(preparation.confirm(m.id));
            var remove=preparation.commit();preparation.publish(remove,s->{},c->{});
            assertEquals(GroupAdministration.Phase.COMPLETE,preparation.phase());assertFalse(b.state.administrators().hasEntry(aKey));
            ga.persist(ga.received(remove.administrators(),remove.revocations()),s->{},c->{});assertFalse(ga.isAdministrator());
            gm.persist(gm.received(remove.administrators(),remove.revocations()),snapshot->{},candidate->{});
            assertDoesNotThrow(()->m.state.verifyCertificate(m.cert,m.cert.field(1)));
            var newIdentity=AdminRecordsTest.key(80);var handshake=Crypto.x25519Public(AdminRecordsTest.key(81));
            var joined=gb.issueCertificate(Crypto.ed25519Public(newIdentity),handshake,SignaturePurpose.identityProof(newIdentity,f.group,handshake));
            assertDoesNotThrow(()->b.state.verifyCertificate(joined,handshake));
        }
    }
    @Test void confirmationTimesOutAtSixtySecondsWithoutCommitting() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=t.service(a,true);var gb=t.service(b,false)) {
            grant(a,b,ga,gb);gb.joined(new UdpEndpoint.AdminJoined(a.cert,new java.net.InetSocketAddress("192.0.2.1",54321)));
            f.time.advance(6);var p=gb.prepareRemoval(b.sessions,List.of(Crypto.ed25519Public(f.admin)),false);p.reissue(c->{});
            assertEquals(1,p.incomplete());f.time.advance(60);assertTrue(p.expired());assertThrows(SecurityException.class,p::commit);
            assertEquals(2,b.state.administrators().version());
        }
    }
    @Test void selfRemovalRequiresRetainedAdministratorAndOfflineMemberIsNotWaitedFor() {
        try(var a=f.new Node(1);var b=f.new Node(2);var m=f.new Node(3);var ga=t.service(a,true);var gb=t.service(b,false)) {
            var c=grant(a,b,ga,gb);assertThrows(GroupAdministration.NeedsRetainedAdministrator.class,()->ga.prepareRemoval(a.sessions,List.of(Crypto.ed25519Public(f.admin)),false));
            gb.joined(new UdpEndpoint.AdminJoined(m.cert,new java.net.InetSocketAddress("192.0.2.1",54321)));
            f.time.advance(1);var p=gb.prepareRemoval(b.sessions,List.of(Crypto.ed25519Public(f.admin)),false);p.reissue(x->{});assertEquals(0,p.incomplete());
            var removal=p.commit();p.publish(removal,s->{},x->{});
            // オフラインのMは旧発行者を外す一覧を受けると無効になる。
            var first=AdminRecords.administrators(f.group,1,f.time.millis,ga.bindings().stream().filter(x->Crypto.equal(x.administratorKey(),Crypto.ed25519Public(f.admin))).toList(),f.admin);
            m.state.acceptAdministrators(first,v->fail());m.state.acceptAdministrators(c.administrators(),v->fail());m.state.acceptRevocations(c.revocations());
            m.state.acceptAdministrators(removal.administrators(),v->fail());m.state.acceptRevocations(removal.revocations());
            assertEquals(UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_INVALID,m.state.localCertificateReason(m.cert,m.cert.field(1)));
            var freshIdentity=AdminRecordsTest.key(90);var freshHandshake=Crypto.x25519Public(AdminRecordsTest.key(91));
            var rejoined=gb.issueCertificate(Crypto.ed25519Public(freshIdentity),freshHandshake,SignaturePurpose.identityProof(freshIdentity,f.group,freshHandshake));
            assertFalse(Crypto.equal(m.id,Crypto.blake2s(rejoined.field(0))));assertTrue(Crypto.equal(f.group,rejoined.group()));
            m.state.clear();assertDoesNotThrow(()->b.state.verifyCertificate(rejoined,freshHandshake));
            try(var invitation=gb.invitation(new byte[]{(byte)192,0,2,1},54321,AdminRecordsTest.key(92));
                var issuer=gb.invitationIssuer(invitation);
                var joiner=new JoinHandshake.Joiner(invitation,freshIdentity,AdminRecordsTest.key(91),f.time);
                var joined=joiner.receive(gb.respondInvitation(issuer,joiner.request(),f.psk,0));
                var fresh=new SessionManager(joined.state(),joined.certificate(),AdminRecordsTest.key(91),joined.groupKey(),0,f.time,()->f.time.nanos,256);
                var retained=new SessionManager(b.state,gb.certificate(),b.secret,f.psk,0,f.time,()->f.time.nanos,256)) {
                byte[] freshId=Crypto.blake2s(joined.certificate().field(0));fresh.rememberPeer(gb.certificate());retained.rememberPeer(joined.certificate());
                var reply=retained.receive(fresh.start(b.id).packet());var confirmation=fresh.receive(reply.outbound().get(0).packet());retained.receive(confirmation.outbound().get(0).packet());
                assertTrue(fresh.isEstablished(b.id));assertTrue(retained.isEstablished(freshId));
                assertTrue(Crypto.equal(f.group,joined.certificate().group()));assertFalse(Crypto.equal(m.id,freshId));
            }
        }
    }
    @Test void saveFailureDuringSelfReissueKeepsOriginalCertificateAndList() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=t.service(a,true);var gb=t.service(b,false)) {
            grant(a,b,ga,gb);f.time.advance(1);var p=gb.prepareRemoval(b.sessions,List.of(Crypto.ed25519Public(f.admin)),false);
            assertThrows(IllegalStateException.class,()->p.reissue(c->{throw new IllegalStateException();}));
            assertTrue(Arrays.equals(b.cert.encode(),gb.certificate().encode()));assertEquals(2,b.state.administrators().version());
        }
    }
}
