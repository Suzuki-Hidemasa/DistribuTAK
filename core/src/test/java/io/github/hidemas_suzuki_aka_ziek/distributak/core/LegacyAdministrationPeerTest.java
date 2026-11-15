// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class LegacyAdministrationPeerTest {
    final SessionManagerTest f=new SessionManagerTest();
    final class Pair implements AutoCloseable {
        final SessionManagerTest.Node a=f.new Node(1),m=f.new Node(2),other=f.new Node(3);
        final AdminState as,ms;final AdminRecords.Record ca,cm,co;
        final SessionManager sa,sm,so;final GroupAdministration ga,gm;
        Pair()throws Exception {
            var list=AdminFormatTest.legacy(a.state.administrators(),null,f.admin);var rev=AdminFormatTest.legacy(a.state.revocations(),null,f.admin);
            as=state(list,rev);ms=state(list,rev);var os=state(list,rev);
            ca=AdminFormatTest.legacy(a.cert,a.identity,f.admin);cm=AdminFormatTest.legacy(m.cert,m.identity,f.admin);co=AdminFormatTest.legacy(other.cert,other.identity,f.admin);
            for(var state:List.of(as,ms,os))for(var cert:List.of(ca,cm,co))state.trustStoredLegacyCertificate(cert);
            sa=new SessionManager(as,ca,a.secret,f.psk,0,f.time,()->f.time.nanos,256);sm=new SessionManager(ms,cm,m.secret,f.psk,0,f.time,()->f.time.nanos,256);
            so=new SessionManager(os,co,other.secret,f.psk,0,f.time,()->f.time.nanos,256);
            sa.rememberPeer(cm);sm.rememberPeer(ca);connect(sm,sa,a.id);sm.rememberPeer(co);so.rememberPeer(cm);connect(so,sm,m.id);
            ga=new GroupAdministration(as,ca,a.identity,a.secret,f.admin,f.time,()->f.time.nanos,new java.security.SecureRandom());
            gm=GroupAdministration.fromSaved(ms,cm,m.identity,m.secret,null,f.time,()->f.time.nanos,new java.security.SecureRandom(),ca);
            ga.joined(new UdpEndpoint.AdminJoined(cm,new java.net.InetSocketAddress("192.0.2.1",54321)));
        }
        public void close(){ga.close();gm.close();sa.close();sm.close();so.close();a.close();m.close();other.close();}
    }
    AdminState state(AdminRecords.Record list,AdminRecords.Record rev) {
        var state=new AdminState(f.group,Crypto.ed25519Public(f.admin),f.time,new InMemoryAdminRecordStore());state.join(List.of(list),AdminRecords.signAnchor(list,f.admin),rev);return state;
    }
    void connect(SessionManager from,SessionManager to,byte[] peer){var r=to.receive(from.start(peer).packet());var c=from.receive(r.outbound().get(0).packet());to.receive(c.outbound().get(0).packet());}
    @Test void savedPeerAllowsCompleteReasonThreeMigrationWithoutRewritingLegacyList()throws Exception {
        try(var p=new Pair()) {
            byte[] original=p.ms.administrators().encode();assertFalse(p.ms.administrators().hasAdminBindings());f.time.advance(6);
            var preparation=p.ga.prepareInvitation(p.sa);preparation.reissue(c->{});p.sa.updateLocalCertificate(p.ga.certificate());
            var request=preparation.next(p.m.id,c->fail());var reply=p.gm.receiveProofRequest(p.sm,p.a.id,p.sm.sessionId(p.a.id),request);
            var delivery=preparation.reply(p.m.id,p.sa.sessionId(p.m.id),reply,c->{});
            var cert=p.gm.receiveCertificateDelivery(p.sm,p.a.id,p.sm.sessionId(p.a.id),delivery,c->{});p.sm.updateLocalCertificate(cert);
            connect(p.sm,p.sa,p.a.id);assertTrue(preparation.confirm(p.m.id));assertTrue(preparation.result().completed());
            assertEquals(2,p.gm.certificate().format());assertTrue(Arrays.equals(original,p.ms.administrators().encode()));
            assertNotNull(p.gm.request(p.sm,p.a.id));assertThrows(SecurityException.class,()->p.gm.request(p.sm,p.other.id));
        }
    }
    @Test void anotherAuthenticatedMemberCannotImpersonateSavedAdministrator()throws Exception {
        try(var p=new Pair()) {
            var request=RenewalMessage.request(p.cm,new byte[16],Crypto.ed25519Public(f.admin),RenewalMessage.Reason.INVITATION_PREPARE,new byte[16]);
            assertThrows(SecurityException.class,()->p.gm.receiveProofRequest(p.sm,p.other.id,p.sm.sessionId(p.other.id),request));
        }
    }
    @Test void boundListDisablesSavedMappingAndRequiresItsActualAdministratorIdentity()throws Exception {
        try(var p=new Pair()) {
            var proof=AdminControl.keyProof(f.group,new byte[16],0,p.other.identity,f.admin);
            var list=AdminRecords.administrators(f.group,1,f.time.millis,List.of(AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode())),f.admin);
            var rev=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,1,f.time.millis,List.of(),f.admin);
            p.gm.persist(p.gm.received(list,rev),s->{},c->{});
            var request=RenewalMessage.request(p.cm,new byte[16],Crypto.ed25519Public(f.admin),RenewalMessage.Reason.INVITATION_PREPARE,new byte[16]);
            assertThrows(SecurityException.class,()->p.gm.receiveProofRequest(p.sm,p.a.id,p.sm.sessionId(p.a.id),request));
            assertNotNull(p.gm.receiveProofRequest(p.sm,p.other.id,p.sm.sessionId(p.other.id),request));
        }
    }
    @Test void savedMappingIsRejectedForListsWithBindings()throws Exception {
        try(var a=f.new Node(1);var m=f.new Node(2)) {
            assertThrows(SecurityException.class,()->GroupAdministration.fromSaved(m.state,m.cert,m.identity,m.secret,null,f.time,()->f.time.nanos,new java.security.SecureRandom(),a.cert));
        }
    }
    @Test void multipleAdministratorsNeverEnableSavedSinglePeerFallback()throws Exception {
        try(var p=new Pair()) {
            var list=AdminFormatTest.legacy(AdminRecords.list(AdminRecords.Kind.ADMINS,f.group,0,f.time.millis,List.of(Crypto.ed25519Public(f.admin),Crypto.ed25519Public(AdminRecordsTest.key(70))),f.admin),null,f.admin);
            var state=state(list,p.as.revocations());state.trustStoredLegacyCertificate(p.cm);state.trustStoredLegacyCertificate(p.ca);
            assertThrows(SecurityException.class,()->GroupAdministration.fromSaved(state,p.cm,p.m.identity,p.m.secret,null,f.time,()->f.time.nanos,new java.security.SecureRandom(),p.ca));
        }
    }
    @Test void soleAdministratorCannotPinAnOrdinaryMemberAsAdministrator()throws Exception {
        try(var p=new Pair()) {
            assertThrows(SecurityException.class,()->GroupAdministration.fromSaved(p.as,p.ca,p.a.identity,p.a.secret,f.admin,f.time,()->f.time.nanos,new java.security.SecureRandom(),p.cm));
        }
    }
}
