// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class InvitationPreparationTest {
    final SessionManagerTest f=new SessionManagerTest();
    final class Pair implements AutoCloseable {
        final SessionManagerTest.Node a=f.new Node(1),m=f.new Node(2);
        final AdminRecords.Record oldA,oldM;
        final SessionManager sa,sm;final GroupAdministration ga,gm;
        Pair()throws Exception {
            var proof=AdminControl.keyProof(f.group,new byte[16],0,a.identity,f.admin);
            var list=AdminRecords.administrators(f.group,1,f.time.millis,List.of(AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode())),f.admin);
            a.state.acceptAdministrators(list,v->fail());m.state.acceptAdministrators(list,v->fail());
            oldA=AdminFormatTest.legacy(a.cert,a.identity,f.admin);oldM=AdminFormatTest.legacy(m.cert,m.identity,f.admin);
            for(var state:List.of(a.state,m.state)){state.trustStoredLegacyCertificate(oldA);state.trustStoredLegacyCertificate(oldM);}
            ga=new GroupAdministration(a.state,oldA,a.identity,a.secret,f.admin,f.time,()->f.time.nanos,new java.security.SecureRandom());
            gm=new GroupAdministration(m.state,oldM,m.identity,m.secret,null,f.time,()->f.time.nanos,new java.security.SecureRandom());
            sa=new SessionManager(a.state,oldA,a.secret,f.psk,0,f.time,()->f.time.nanos,256);sm=new SessionManager(m.state,oldM,m.secret,f.psk,0,f.time,()->f.time.nanos,256);
            sa.rememberPeer(oldM);sm.rememberPeer(oldA);first(sm,sa,a.id);
            ga.joined(new UdpEndpoint.AdminJoined(oldM,new java.net.InetSocketAddress("192.0.2.1",54321)));
        }
        public void close(){ga.close();gm.close();sa.close();sm.close();a.close();m.close();}
    }
    void first(SessionManager from,SessionManager to,byte[] peer) {
        var reply=to.receive(from.start(peer).packet());var confirm=from.receive(reply.outbound().get(0).packet());to.receive(confirm.outbound().get(0).packet());
    }
    @Test void invitationWaitsAtSameMillisecondAndDoesNotChangeLegacyWithoutOperation()throws Exception {
        try(var p=new Pair()) {
            assertEquals(1,p.ga.certificate().format());assertNull(p.ga.invitationCertificateCandidate());
            var prep=p.ga.prepareInvitation(p.sa);assertThrows(IllegalStateException.class,()->prep.reissue(c->fail()));
            assertEquals(1,p.ga.certificate().format());f.time.millis++;
            prep.reissue(c->{});assertEquals(2,p.ga.certificate().format());assertEquals(1,p.gm.certificate().format());
        }
    }
    @Test void onlineLegacyMemberSuppliesProofSavesDeliveryAndConfirmsOnlyWithFirst()throws Exception {
        try(var p=new Pair()) {
            f.time.advance(6);var prep=p.ga.prepareInvitation(p.sa);prep.reissue(c->{});p.sa.updateLocalCertificate(p.ga.certificate());
            var request=prep.next(p.m.id,c->fail());assertEquals(RenewalMessage.Reason.INVITATION_PREPARE,request.reason());assertEquals(16,request.managementOperation().length);
            var response=p.gm.receiveProofRequest(p.sm,p.a.id,p.sm.sessionId(p.a.id),request);
            assertThrows(IllegalStateException.class,()->prep.reply(p.m.id,p.sa.sessionId(p.m.id),response,c->{throw new IllegalStateException();}));
            var delivery=prep.reply(p.m.id,p.sa.sessionId(p.m.id),response,c->{});
            assertThrows(IllegalStateException.class,()->p.gm.receiveCertificateDelivery(p.sm,p.a.id,p.sm.sessionId(p.a.id),delivery,c->{throw new IllegalStateException();}));
            assertEquals(1,p.gm.certificate().format());
            var renewed=p.gm.receiveCertificateDelivery(p.sm,p.a.id,p.sm.sessionId(p.a.id),delivery,c->{});p.sm.updateLocalCertificate(renewed);
            assertFalse(prep.confirm(p.m.id));first(p.sm,p.sa,p.a.id);assertTrue(prep.confirm(p.m.id));
            var result=prep.result();assertTrue(result.completed());assertEquals(0,result.incomplete());assertFalse(result.timedOut());
            assertTrue(Crypto.equal(p.oldM.field(0),renewed.field(0)));assertTrue(Crypto.equal(f.group,renewed.group()));
        }
    }
    @Test void invitationReportsIncompleteCountAfterSixtySecondsAndRejectsStaleSession()throws Exception {
        try(var p=new Pair()) {
            f.time.advance(1);var prep=p.ga.prepareInvitation(p.sa);prep.reissue(c->{});var request=prep.next(p.m.id,c->fail());
            assertThrows(SecurityException.class,()->p.gm.receiveProofRequest(p.sm,p.a.id,new byte[16],request));
            f.time.advance(60);var result=prep.result();assertFalse(result.completed());assertEquals(1,result.incomplete());assertTrue(result.timedOut());
            assertEquals(1,p.gm.certificate().format());assertThrows(SecurityException.class,()->prep.next(p.m.id,c->{}));
        }
    }
}
