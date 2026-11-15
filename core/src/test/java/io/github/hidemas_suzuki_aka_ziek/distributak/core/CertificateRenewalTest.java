// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class CertificateRenewalTest {
    final SessionManagerTest f=new SessionManagerTest();
    final long lifetime=AdminRecords.CERTIFICATE_LIFETIME_MILLIS;
    void due(SessionManagerTest.Node a,SessionManagerTest.Node b) {
        a.remember(b);b.remember(a);f.time.millis=b.cert.expiresAt()-lifetime/3;
    }
    Object uncheckedLocal(SessionManagerTest.Node b) {
        try{return SessionManagerTest.field(b.sessions,"localCertificate");}catch(Exception e){throw new AssertionError(e);}
    }
    @Test void oldIssuedAtAndEqualTimeDifferentBytesAreRejected() {
        try(var b=f.new Node(2)) {
            var old=b.certificate(b.secret,b.cert.issuedAt()-1);
            assertThrows(SecurityException.class,()->b.sessions.validateLocalCertificateRenewal(old));
            assertThrows(SecurityException.class,()->b.sessions.updateLocalCertificate(old));
            var otherAdmins=AdminProofFixtures.list(f.group,1,f.time.millis,List.of(Crypto.ed25519Public(f.admin),Crypto.ed25519Public(key(90))),f.admin,f.admin,key(90));
            b.state.acceptAdministrators(otherAdmins,v->fail());
            var conflict=AdminRecords.certificate(f.group,b.cert.field(0),b.cert.field(1),b.cert.field(2),b.cert.issuedAt(),key(90));
            assertThrows(SecurityException.class,()->b.sessions.updateLocalCertificate(conflict));
        }
    }
    @Test void identicalBytesAreNoOp() {
        try(var b=f.new Node(2)) {
            assertFalse(b.sessions.validateLocalCertificateRenewal(AdminRecords.decode(b.cert.encode())));
            b.sessions.updateLocalCertificate(AdminRecords.decode(b.cert.encode()));assertSame(b.cert,uncheckedLocal(b));
        }
    }
    @Test void differentIdentityAndHandshakeAreRejected() {
        try(var b=f.new Node(2);var c=f.new Node(3)) {
            f.time.millis++;
            assertThrows(SecurityException.class,()->b.sessions.validateLocalCertificateRenewal(c.certificate(c.secret,f.time.millis)));
            assertThrows(SecurityException.class,()->b.sessions.validateLocalCertificateRenewal(b.certificate(key(90),f.time.millis)));
        }
    }
    @Test void receivedRenewalMustPassSignatureBindingAndClockChecks() {
        try(var b=f.new Node(2)) {
            var valid=b.certificate(b.secret,f.time.millis+1);byte[] bad=valid.encode();bad[bad.length-1]^=1;
            assertThrows(SecurityException.class,()->b.sessions.validateLocalCertificateRenewal(AdminRecords.decode(bad)));
            var binding=AdminRecords.certificate(f.group,b.cert.field(0),b.cert.field(1),new byte[64],f.time.millis+1,f.admin);
            assertThrows(SecurityException.class,()->b.sessions.validateLocalCertificateRenewal(binding));
            assertThrows(SecurityException.class,()->b.sessions.validateLocalCertificateRenewal(b.certificate(b.secret,f.time.millis+300_001)));
            f.time.millis=valid.expiresAt();assertThrows(SecurityException.class,()->b.sessions.validateLocalCertificateRenewal(valid));
            f.time.millis=-1;assertThrows(SecurityException.class,()->b.sessions.validateLocalCertificateRenewal(valid));
        }
    }
    @Test void renewalProtoCarriesCertificateWithoutChangingRecordBytes() throws Exception {
        try(var b=f.new Node(2)) {
            var message=io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.RenewalSchema.CertificateRenewal.newBuilder()
                .setCertificate(com.google.protobuf.ByteString.copyFrom(b.cert.encode())).build();
            var decoded=io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.RenewalSchema.CertificateRenewal.parseFrom(message.toByteArray());
            assertArrayEquals(b.cert.encode(),decoded.getCertificate().toByteArray());
        }
    }
    @Test void delayedOlderRenewalCannotRollBack() {
        try(var b=f.new Node(2)) {
            var old=b.certificate(b.secret,f.time.millis+1);var newer=b.certificate(b.secret,f.time.millis+2);
            b.sessions.updateLocalCertificate(newer);
            assertThrows(SecurityException.class,()->b.sessions.validateLocalCertificateRenewal(old));
            assertThrows(SecurityException.class,()->b.sessions.updateLocalCertificate(old));assertSame(newer,uncheckedLocal(b));
        }
    }    AdminRecords.Record issue(SessionManagerTest.Node a,SessionManagerTest.Node b,byte[] key) {
        return a.state.issueCertificateRenewal(b.cert,b.cert.field(2),key,RenewalMessage.Reason.AUTO_RENEWAL,null);
    }
    @Test void separateAdministratorRequiredForStateIssuance() {
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            due(a,b);assertThrows(SecurityException.class,()->issue(a,b,a.identity));assertNotNull(issue(a,b,f.admin));
        }
    }
    @Test void automaticIssuanceHonorsOneThirdAndExpiryBoundary() {
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            due(a,b);f.time.millis--;assertThrows(SecurityException.class,()->issue(a,b,f.admin));
            f.time.millis++;assertEquals(f.time.millis,issue(a,b,f.admin).issuedAt());f.time.millis=b.cert.expiresAt()-1;assertNotNull(issue(a,b,f.admin));
            f.time.millis++;assertThrows(SecurityException.class,()->issue(a,b,f.admin));
        }
    }
    @Test void revokedMemberCannotReceiveRenewal() {
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            due(a,b);a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis,List.of(b.id),f.admin));
            assertThrows(SecurityException.class,()->issue(a,b,f.admin));
        }
    }
    @Test void issuedRenewalDoesNotChangePeerUntilAuthenticatedHandshake() {
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            due(a,b);var issued=issue(a,b,f.admin);assertTrue(java.util.Arrays.equals(b.cert.encode(),a.sessions.peerCertificate(b.id).encode()));
            b.sessions.updateLocalCertificate(issued);var reply=a.sessions.receive(b.sessions.start(a.id).packet());
            a.sessions.receive(b.sessions.receive(reply.outbound().get(0).packet()).outbound().get(0).packet());
            assertTrue(java.util.Arrays.equals(issued.encode(),a.sessions.peerCertificate(b.id).encode()));
        }
    }
    @Test void savedLegacyPendingIsCopiedAndClearedAfterNewFirst()throws Exception {
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            due(a,b);var issued=issue(a,b,f.admin);byte[] stored=issued.encode();a.sessions.restorePeerRenewal(b.id,stored,Crypto.ed25519Public(f.admin));stored[0]^=1;
            assertTrue(java.util.Arrays.equals(issued.encode(),(byte[])SessionManagerTest.field(f.peerState(a,b),"renewal")));
            b.sessions.updateLocalCertificate(issued);var reply=a.sessions.receive(b.sessions.start(a.id).packet());
            a.sessions.receive(b.sessions.receive(reply.outbound().get(0).packet()).outbound().get(0).packet());
            assertNull(SessionManagerTest.field(f.peerState(a,b),"renewal"));
        }
    }
    @Test void restoreRejectsWrongSignerIdentityHandshakeAndOlderCertificate() {
        try(var a=f.new Node(1);var b=f.new Node(2);var c=f.new Node(3)) {
            due(a,b);long now=f.time.millis;byte[] signer=Crypto.ed25519Public(f.admin);
            assertThrows(SecurityException.class,()->a.sessions.restorePeerRenewal(b.id,b.cert.encode(),signer));
            assertThrows(SecurityException.class,()->a.sessions.restorePeerRenewal(b.id,c.certificate(c.secret,now).encode(),signer));
            assertThrows(SecurityException.class,()->a.sessions.restorePeerRenewal(b.id,b.certificate(key(90),now).encode(),signer));
            assertThrows(SecurityException.class,()->a.sessions.restorePeerRenewal(b.id,issue(a,b,f.admin).encode(),Crypto.ed25519Public(a.identity)));
            a.sessions.restorePeerRenewal(b.id,issue(a,b,f.admin).encode(),signer);f.time.millis++;
            assertThrows(SecurityException.class,()->a.sessions.restorePeerRenewal(b.id,issue(a,b,f.admin).encode(),signer));
        }
    }
}
