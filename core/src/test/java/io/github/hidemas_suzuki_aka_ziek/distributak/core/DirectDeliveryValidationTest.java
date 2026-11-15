// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
class DirectDeliveryValidationTest {
    final SessionManagerTest f=new SessionManagerTest();
    final class Pair implements AutoCloseable {
        final SessionManagerTest.Node a=f.new Node(1),m=f.new Node(2),other=f.new Node(3);
        final GroupAdministration gm;final AdminRecords.Record next;final RenewalMessage delivery;final byte[] session;
        Pair() {
            var proof=AdminControl.keyProof(f.group,new byte[16],0,a.identity,f.admin);
            var list=AdminRecords.administrators(f.group,1,f.time.millis,List.of(AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode())),f.admin);
            for(var node:List.of(a,m,other))node.state.acceptAdministrators(list,v->fail());
            f.connect(a,m);f.connect(other,m);f.time.advance(6);
            gm=new GroupAdministration(m.state,m.cert,m.identity,m.secret,null,f.time,()->f.time.nanos,new java.security.SecureRandom());
            next=m.certificate(m.secret,f.time.millis);delivery=delivery(m.cert,next,RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,new byte[16]);session=m.sessions.sessionId(a.id);
        }
        RenewalMessage delivery(AdminRecords.Record base,AdminRecords.Record next,RenewalMessage.Reason reason,byte[] operation) {
            return RenewalMessage.delivery(RenewalMessage.request(base,new byte[16],Crypto.ed25519Public(f.admin),reason,operation),next.encode());
        }
        public void close(){gm.close();a.close();m.close();other.close();}
    }
    @ParameterizedTest @ValueSource(strings={"sender","session","base","group","invitation","notDue","identity","handshake","proof","signature","oldTime","equalTime","future","revokedMember","revokedSender","expired"})
    void invalidDirectDeliveryNeverSavesOrChangesCertificate(String condition) {
        try(var p=new Pair()) {
            RenewalMessage message=p.delivery;byte[] sender=p.a.id,session=p.session;
            switch(condition) {
                case "sender" -> {sender=p.other.id;session=p.m.sessions.sessionId(sender);}
                case "session" -> session=new byte[16];
                case "base" -> message=p.delivery(p.m.certificate(p.m.secret,p.m.cert.issuedAt()+1),p.next,RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,new byte[16]);
                case "group" -> {
                    byte[] group=AdminRecordsTest.key(80),handshake=p.m.cert.field(1);
                    var base=AdminRecords.certificate(group,p.m.cert.field(0),handshake,SignaturePurpose.identityProof(p.m.identity,group,handshake),p.m.cert.issuedAt(),f.admin);
                    message=p.delivery(base,p.next,RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,new byte[16]);
                }
                case "invitation" -> message=p.delivery(p.m.cert,p.next,RenewalMessage.Reason.INVITATION_PREPARE,new byte[16]);
                case "notDue" -> message=p.delivery(p.m.cert,p.next,RenewalMessage.Reason.AUTO_RENEWAL,null);
                case "identity" -> message=p.delivery(p.m.cert,p.other.certificate(p.other.secret,f.time.millis),RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,new byte[16]);
                case "handshake" -> message=p.delivery(p.m.cert,p.m.certificate(AdminRecordsTest.key(70),f.time.millis),RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,new byte[16]);
                case "proof" -> {byte[] proof=p.next.field(2);proof[0]^=1;var bad=AdminRecords.certificate(f.group,p.next.field(0),p.next.field(1),proof,f.time.millis,f.admin);message=p.delivery(p.m.cert,bad,RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,new byte[16]);}
                case "signature" -> {byte[] bad=p.next.encode();bad[bad.length-1]^=1;message=p.delivery(p.m.cert,AdminRecords.decode(bad),RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,new byte[16]);}
                case "oldTime" -> message=p.delivery(p.m.cert,p.m.certificate(p.m.secret,p.m.cert.issuedAt()-1),RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,new byte[16]);
                case "equalTime" -> message=p.delivery(p.m.cert,p.m.cert,RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,new byte[16]);
                case "future" -> message=p.delivery(p.m.cert,p.m.certificate(p.m.secret,f.time.millis+300001),RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,new byte[16]);
                case "revokedMember","revokedSender" -> p.m.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,1,f.time.millis,List.of(condition.equals("revokedMember")?p.m.id:p.a.id),f.admin));
                case "expired" -> f.time.millis=p.next.expiresAt();
            }
            var supplied=message;var peer=sender;var active=session;var saved=new AtomicInteger();
            assertThrows(SecurityException.class,()->p.gm.receiveCertificateDelivery(p.m.sessions,peer,active,supplied,c->saved.incrementAndGet()));
            assertEquals(0,saved.get());assertTrue(Arrays.equals(p.m.cert.encode(),p.gm.certificate().encode()));
        }
    }
    @Test void saveFailureCanRetryDirectDeliveryAndExactDuplicateDoesNotSaveAgain() {
        try(var p=new Pair()) {
            assertThrows(IllegalStateException.class,()->p.gm.receiveCertificateDelivery(p.m.sessions,p.a.id,p.session,p.delivery,c->{throw new IllegalStateException();}));
            assertTrue(Arrays.equals(p.m.cert.encode(),p.gm.certificate().encode()));var saved=new AtomicInteger();
            var next=p.gm.receiveCertificateDelivery(p.m.sessions,p.a.id,p.session,p.delivery,c->saved.incrementAndGet());p.m.sessions.updateLocalCertificate(next);
            assertSame(next,p.gm.receiveCertificateDelivery(p.m.sessions,p.a.id,p.session,p.delivery,c->saved.incrementAndGet()));assertEquals(1,saved.get());
            byte[] operation=new byte[16];operation[0]=1;var changed=p.delivery(p.m.cert,p.next,RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,operation);
            assertThrows(SecurityException.class,()->p.gm.receiveCertificateDelivery(p.m.sessions,p.a.id,p.session,changed,c->fail()));
        }
    }
    @Test void legacyCertificateCannotBeUpgradedByAnUnsolicitedDelivery()throws Exception {
        var t=new InvitationPreparationTest();try(var p=t.new Pair()) {
            t.f.time.advance(6);var prep=p.ga.prepareInvitation(p.sa);prep.reissue(c->{});var request=prep.next(p.m.id,c->fail());
            var next=p.a.state.issueCertificateRenewal(p.oldM,SignaturePurpose.identityProof(p.m.identity,t.f.group,p.oldM.field(1)),t.f.admin,RenewalMessage.Reason.INVITATION_PREPARE,request.managementOperation());
            var delivery=RenewalMessage.delivery(request,next.encode());
            assertThrows(SecurityException.class,()->p.gm.receiveCertificateDelivery(p.sm,p.a.id,p.sm.sessionId(p.a.id),delivery,c->fail()));
            assertEquals(1,p.gm.certificate().format());
        }
    }
    @Test void dueAutomaticRenewalCanReuseExistingProofThroughActualReceiver() {
        try(var p=new Pair()) {
            f.time.millis=p.m.cert.expiresAt()-AdminRecords.CERTIFICATE_LIFETIME_MILLIS/3;
            var next=p.m.certificate(p.m.secret,f.time.millis);var message=p.delivery(p.m.cert,next,RenewalMessage.Reason.AUTO_RENEWAL,null);
            var saved=new AtomicInteger();var received=p.gm.receiveCertificateDelivery(p.m.sessions,p.a.id,p.session,message,c->saved.incrementAndGet());
            assertEquals(1,saved.get());assertTrue(Arrays.equals(next.encode(),received.encode()));
        }
    }
}
