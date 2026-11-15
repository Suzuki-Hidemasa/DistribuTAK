// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class GroupAdministrationTest {
    final SessionManagerTest f=new SessionManagerTest();
    GroupAdministration service(SessionManagerTest.Node n,boolean administrator) {
        return new GroupAdministration(n.state,n.cert,n.identity,n.secret,administrator?f.admin:null,f.time,()->f.time.nanos,new java.security.SecureRandom());
    }
    void connect(SessionManagerTest.Node a,SessionManagerTest.Node b,GroupAdministration ga,GroupAdministration gb) {
        var list=AdminRecords.administrators(f.group,1,f.time.millis,ga.bindings(),f.admin);
        a.state.acceptAdministrators(list,v->fail());b.state.acceptAdministrators(list,v->fail());f.connect(a,b);
    }
    @Test void requestApprovalRequiresSavedListAndAckAloneHasNoAuthority() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=service(a,true);var gb=service(b,false)) {
            connect(a,b,ga,gb);var request=gb.request(b.sessions,a.id);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),request);
            var candidate=ga.approve(a.sessions,b.id);assertEquals(1,a.state.administrators().version());
            gb.receive(b.sessions,a.id,b.sessions.sessionId(a.id),candidate.notice());assertFalse(gb.isAdministrator());
            ga.persist(candidate,s->{},c->{});assertEquals(2,a.state.administrators().version());
            gb.persist(gb.received(candidate.administrators(),candidate.revocations()),s->{},c->{});assertTrue(gb.isAdministrator());
            assertThrows(SecurityException.class,()->ga.approve(a.sessions,b.id));
        }
    }
    @Test void failedSaveDoesNotApplyOrPublishAndCandidateCanBeRetried() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=service(a,true);var gb=service(b,false)) {
            connect(a,b,ga,gb);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),gb.request(b.sessions,a.id));var candidate=ga.approve(a.sessions,b.id);
            assertThrows(IllegalStateException.class,()->ga.persist(candidate,s->{throw new IllegalStateException();},c->fail()));
            assertEquals(1,a.state.administrators().version());ga.persist(candidate,s->{},c->{});assertEquals(2,a.state.administrators().version());
        }
    }
    @Test void listMayArriveBeforeNoticeButMustContainExactPendingProof() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=service(a,true);var gb=service(b,false)) {
            connect(a,b,ga,gb);var request=gb.request(b.sessions,a.id);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),request);var candidate=ga.approve(a.sessions,b.id);
            gb.persist(gb.received(candidate.administrators(),candidate.revocations()),s->{},c->{});assertTrue(gb.isAdministrator());
        }
    }
    @Test void offerCreatesKeyOnlyOnTargetAndKeepsIdentitySeparate() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=service(a,true);var gb=service(b,false)) {
            connect(a,b,ga,gb);var offer=ga.offer(a.sessions,b.id);var proof=gb.receive(b.sessions,a.id,b.sessions.sessionId(a.id),offer);
            assertEquals(AdminControl.Operation.KEY_PROOF,proof.operation());assertFalse(Crypto.equal(proof.identityKey(),proof.administratorKey()));
            ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),proof);ga.persist(ga.approve(a.sessions,b.id),s->{},c->{});
        }
    }
    @Test void staleSessionAndWrongPeerCannotSupplyProof() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=service(a,true);var gb=service(b,false)) {
            connect(a,b,ga,gb);var request=gb.request(b.sessions,a.id);
            assertThrows(SecurityException.class,()->ga.receive(a.sessions,b.id,new byte[16],request));
            assertThrows(SecurityException.class,()->ga.receive(a.sessions,a.id,a.sessions.sessionId(b.id),request));
        }
    }
    @Test void timeoutErasesPendingKeyAndCannotBeExtendedByRetry() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=service(a,true);var gb=service(b,false)) {
            connect(a,b,ga,gb);var request=gb.request(b.sessions,a.id);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),request);var candidate=ga.approve(a.sessions,b.id);
            f.time.advance(601);gb.expire();gb.persist(gb.received(candidate.administrators(),candidate.revocations()),s->{},c->{});assertFalse(gb.isAdministrator());
        }
    }
    @Test void ownLegacyBindingIsAnOverlayAndDoesNotRewriteSignedHistory() {
        try(var a=f.new Node(1);var ga=service(a,true)) {
            byte[] original=a.state.administrators().encode();assertEquals(AdminBinding.State.BOUND,ga.bindings().get(0).state());
            assertTrue(Arrays.equals(original,a.state.administrators().encode()));
        }
    }
    @Test void lastAdministratorAndSelfRemovalDoNotSaveAnything() {
        try(var a=f.new Node(1);var ga=service(a,true)) {
            assertThrows(SecurityException.class,()->ga.prepareRemoval(a.sessions,List.of(Crypto.ed25519Public(f.admin)),false));
            assertEquals(0,a.state.administrators().version());
        }
    }
    @Test void rekeyKeepsExactRequestButCertificateChangeCancelsIt() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=service(a,true);var gb=service(b,false)) {
            connect(a,b,ga,gb);var request=gb.request(b.sessions,a.id);
            f.time.advance(6);var reply=a.sessions.receive(b.sessions.start(a.id).packet());var confirm=b.sessions.receive(reply.outbound().get(0).packet());a.sessions.receive(confirm.outbound().get(0).packet());
            assertTrue(Arrays.equals(request.encode(),gb.request(b.sessions,a.id).encode()));
            ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),request);
            var changed=a.certificate(a.secret,f.time.millis);a.sessions.updateLocalCertificate(changed);f.time.advance(6);
            var second=b.sessions.receive(a.sessions.start(b.id).packet());var confirmation=a.sessions.receive(second.outbound().get(0).packet());b.sessions.receive(confirmation.outbound().get(0).packet());
            var fresh=gb.request(b.sessions,a.id);assertFalse(Arrays.equals(request.requestId(),fresh.requestId()));
            assertFalse(Crypto.equal(request.administratorKey(),fresh.administratorKey()));
        }
    }
    @Test void changingListVersionCancelsPendingProofAndStaleCandidate() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=service(a,true);var gb=service(b,false)) {
            connect(a,b,ga,gb);var request=gb.request(b.sessions,a.id);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),request);var candidate=ga.approve(a.sessions,b.id);
            var next=AdminRecords.administrators(f.group,2,f.time.millis,ga.bindings(),f.admin);a.state.acceptAdministrators(next,v->fail());b.state.acceptAdministrators(next,v->fail());
            assertThrows(SecurityException.class,()->ga.persist(candidate,x->fail(),x->fail()));gb.expire();
            gb.persist(gb.received(candidate.administrators(),candidate.revocations()),x->{},x->{});assertFalse(gb.isAdministrator());
        }
    }
    @Test void pendingRequestsHaveGlobalLimitAndOneSlotPerPeer() {
        var nodes=new ArrayList<SessionManagerTest.Node>();var services=new ArrayList<GroupAdministration>();
        try(var a=f.new Node(1);var ga=service(a,true)) {
            for(int i=0;i<33;i++) {
                var b=f.new Node(i+2);nodes.add(b);var gb=service(b,false);services.add(gb);connect(a,b,ga,gb);
                var request=gb.request(b.sessions,a.id);assertTrue(Arrays.equals(request.encode(),gb.request(b.sessions,a.id).encode()));
                if(i<32){ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),request);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),request);}
                else assertThrows(SecurityException.class,()->ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),request));
            }
        }finally{for(var service:services)service.close();for(var node:nodes)node.close();}
    }
    @Test void revokedLocalAdministratorCannotApproveOrIssueCertificates() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=service(a,true);var gb=service(b,false)) {
            connect(a,b,ga,gb);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),gb.request(b.sessions,a.id));
            a.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,1,f.time.millis,List.of(a.id),f.admin));
            assertThrows(SecurityException.class,()->ga.approve(a.sessions,b.id));
            assertThrows(SecurityException.class,()->ga.issueCertificate(b.cert.field(0),b.cert.field(1),b.cert.field(2)));
        }
    }
    @Test void publicationFailureStopsFurtherManagementAfterSavedStateIsApplied() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=service(a,true);var gb=service(b,false)) {
            connect(a,b,ga,gb);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),gb.request(b.sessions,a.id));var candidate=ga.approve(a.sessions,b.id);
            assertThrows(IllegalStateException.class,()->ga.persist(candidate,x->{},x->{throw new IllegalStateException();}));
            assertEquals(2,a.state.administrators().version());assertFalse(ga.isAdministrator());assertThrows(IllegalStateException.class,ga::expire);
        }
    }
    @Test void approvalCandidateCannotBeSavedAfterRequestExpires() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=service(a,true);var gb=service(b,false)) {
            connect(a,b,ga,gb);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),gb.request(b.sessions,a.id));var candidate=ga.approve(a.sessions,b.id);
            f.time.advance(600);assertThrows(SecurityException.class,()->ga.persist(candidate,x->{},x->{}));assertEquals(1,a.state.administrators().version());
        }
    }
    @Test void offerWithBoundKeyRequiresItsActualMemberSession() {
        try(var a=f.new Node(1);var b=f.new Node(2);var other=f.new Node(3);var ga=service(a,true);var gb=service(b,false)) {
            connect(a,b,ga,gb);f.connect(other,b);
            var offer=AdminControl.offer(f.group,new byte[16],b.id,1,f.admin);
            assertThrows(SecurityException.class,()->gb.receive(b.sessions,other.id,b.sessions.sessionId(other.id),offer));
            assertNotNull(gb.receive(b.sessions,a.id,b.sessions.sessionId(a.id),offer));
        }
    }
    @Test void unknownKeyOfferStillAcceptsProofOfTheCurrentAdministratorKey() {
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=service(a,true);var gb=service(b,false)) {
            f.connect(a,b);var offer=ga.offer(a.sessions,b.id);
            assertNotNull(gb.receive(b.sessions,a.id,b.sessions.sessionId(a.id),offer));
        }
    }
}
