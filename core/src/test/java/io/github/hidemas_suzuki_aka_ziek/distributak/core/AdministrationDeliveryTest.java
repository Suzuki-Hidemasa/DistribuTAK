// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AdministrationDeliveryTest {
    @Test void legacyPreparationMustRestartProofExchangeAfterRekey() throws Exception {
        var t=new InvitationPreparationTest();
        try(var p=t.new Pair()) {
            t.f.time.advance(6);
            var prep=p.ga.prepareInvitation(p.sa);
            prep.reissue(c->{});p.sa.updateLocalCertificate(p.ga.certificate());
            var request=prep.next(p.m.id,c->fail());
            var reply=p.gm.receiveProofRequest(p.sm,p.a.id,p.sm.sessionId(p.a.id),request);
            var lostDelivery=prep.reply(p.m.id,p.sa.sessionId(p.m.id),reply,c->{});
            assertEquals(RenewalMessage.Operation.CERTIFICATE_DELIVERY,lostDelivery.operation());
            // 同じセッションなら同じ配送を再送し、再鍵交換後は要求からやり直す。
            t.f.time.advance(5);var retry=prep.next(p.m.id,c->fail("the issued certificate is already saved"));
            assertTrue(java.util.Arrays.equals(lostDelivery.encode(),retry.encode()));
            t.f.time.advance(1);t.first(p.sm,p.sa,p.a.id);
            var restarted=prep.next(p.m.id,c->{});
            assertFalse(java.util.Arrays.equals(request.requestId(),restarted.requestId()));
            assertEquals(RenewalMessage.Operation.PROOF_REQUEST,restarted.operation());
            assertThrows(SecurityException.class,()->p.gm.receiveCertificateDelivery(p.sm,p.a.id,p.sm.sessionId(p.a.id),lostDelivery,c->fail()));
            var freshReply=p.gm.receiveProofRequest(p.sm,p.a.id,p.sm.sessionId(p.a.id),restarted);
            var resent=prep.reply(p.m.id,p.sa.sessionId(p.m.id),freshReply,c->fail("the issued certificate is already saved"));
            assertTrue(java.util.Arrays.equals(lostDelivery.certificate(),resent.certificate()));
            var received=p.gm.receiveCertificateDelivery(p.sm,p.a.id,p.sm.sessionId(p.a.id),resent,c->{});p.sm.updateLocalCertificate(received);
            assertFalse(prep.confirm(p.m.id));t.f.time.advance(6);t.first(p.sm,p.sa,p.a.id);assertTrue(prep.confirm(p.m.id));
        }
    }

    @Test void duplicateAcceptedCertificateDeliveryMustBeIdempotent() throws Exception {
        var t=new InvitationPreparationTest();
        try(var p=t.new Pair()) {
            t.f.time.advance(6);
            var prep=p.ga.prepareInvitation(p.sa);
            prep.reissue(c->{});p.sa.updateLocalCertificate(p.ga.certificate());
            var request=prep.next(p.m.id,c->fail());
            var reply=p.gm.receiveProofRequest(p.sm,p.a.id,p.sm.sessionId(p.a.id),request);
            var delivery=prep.reply(p.m.id,p.sa.sessionId(p.m.id),reply,c->{});
            var renewed=p.gm.receiveCertificateDelivery(p.sm,p.a.id,p.sm.sessionId(p.a.id),delivery,c->{});
            p.sm.updateLocalCertificate(renewed);
            assertDoesNotThrow(()->p.gm.receiveCertificateDelivery(p.sm,p.a.id,
                p.sm.sessionId(p.a.id),delivery,c->fail("duplicate delivery must not save twice")));
            assertFalse(prep.confirm(p.m.id));t.f.time.advance(6);t.first(p.sm,p.sa,p.a.id);assertTrue(prep.confirm(p.m.id));
            assertDoesNotThrow(()->p.gm.receiveCertificateDelivery(p.sm,p.a.id,p.sm.sessionId(p.a.id),delivery,c->fail("duplicate after rekey must not save")));
        }
    }

    @Test void directProof2DeliveryMustBeAcceptedByTheActualReceiver() {
        var t = new AdministrationPreparationTest();
        var f = t.f;
        try (var a=f.new Node(1); var b=f.new Node(2); var m=f.new Node(3);
             var ga=t.t.service(a,true); var gb=t.t.service(b,false)) {
            var grant=t.grant(a,b,ga,gb);
            byte[] aKey=Crypto.ed25519Public(f.admin);
            var bound=AdminRecords.administrators(f.group,1,f.time.millis,
                ga.bindings().stream().filter(x->Crypto.equal(x.administratorKey(),aKey)).toList(),f.admin);
            m.state.acceptAdministrators(bound,v->fail());
            m.state.acceptAdministrators(grant.administrators(),v->fail());
            m.state.acceptRevocations(grant.revocations());
            f.connect(b,m);
            gb.joined(new UdpEndpoint.AdminJoined(m.cert,new java.net.InetSocketAddress("192.0.2.1",54321)));
            try (var gm=t.t.service(m,false)) {
                f.time.advance(6);
                var prep=gb.prepareRemoval(b.sessions,List.of(aKey),false);
                prep.reissue(c->{});
                b.sessions.updateLocalCertificate(gb.certificate());
                b.cert=gb.certificate();
                var delivery=prep.next(m.id,c->{});
                assertEquals(RenewalMessage.Operation.CERTIFICATE_DELIVERY,delivery.operation());
                assertDoesNotThrow(()->gm.receiveCertificateDelivery(m.sessions,b.id,
                    m.sessions.sessionId(b.id),delivery,c->{}));
            }
        }
    }
}
