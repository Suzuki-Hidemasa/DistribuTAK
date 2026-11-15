// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpoint.CloseReason.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class LocalCertificateReasonTest {
    final SessionManagerTest f=new SessionManagerTest();
    @Test void wrongKindIsInternalLocallyAndRejectedForPeer() {
        try(var a=f.new Node(1)) {
            var wrong=a.state.administrators();
            assertEquals(INTERNAL_FAILURE,a.state.localCertificateReason(wrong,a.cert.field(1)));
            assertThrows(SecurityException.class,()->a.state.verifyCertificate(wrong,a.cert.field(1)));
        }
    }
    @Test void wrongGroupIsInternalLocallyAndRejectedForPeer() {
        try(var a=f.new Node(1)) {
            var wrong=AdminRecords.certificate(key(90),a.cert.field(0),a.cert.field(1),a.cert.field(2),f.time.millis,f.admin);
            assertEquals(INTERNAL_FAILURE,a.state.localCertificateReason(wrong,a.cert.field(1)));
            assertThrows(SecurityException.class,()->a.state.verifyCertificate(wrong,a.cert.field(1)));
        }
    }
    @Test void missingAdministratorsIsInternalFailure() {
        try(var a=f.new Node(1)) {
            var empty=new AdminState(f.group,Crypto.ed25519Public(f.admin),f.time,new InMemoryAdminRecordStore());
            assertEquals(INTERNAL_FAILURE,empty.localCertificateReason(a.cert,a.cert.field(1)));
        }
    }
    @Test void missingRevocationsIsInternalFailure() {
        try(var a=f.new Node(1)) {
            var incomplete=new AdminState(f.group,Crypto.ed25519Public(f.admin),f.time,new InMemoryAdminRecordStore());
            var admins=a.state.administrators();incomplete.bootstrap(admins,AdminRecords.signAnchor(admins,f.admin));
            assertEquals(INTERNAL_FAILURE,incomplete.localCertificateReason(a.cert,a.cert.field(1)));
        }
    }
    @Test void unexpectedNullIsInternalFailure() {
        try(var a=f.new Node(1)) {
            assertEquals(INTERNAL_FAILURE,a.state.localCertificateReason(null,a.cert.field(1)));
            assertEquals(INTERNAL_FAILURE,a.state.localCertificateReason(a.cert,null));
        }
    }
    @Test void clearingAdminStateStopsSessionWithoutInvalidReason() {
        try(var a=f.new Node(1)) {
            a.state.clear();a.sessions.refresh();assertTrue(a.sessions.isClosed());assertEquals(INTERNAL_FAILURE,a.sessions.closeReason());
        }
    }
    @Test void originalCloseReasonOrdinalsRemainStable() {
        var original=java.util.List.of(RUNNING,CLOSED_BY_CALLER,LOCAL_CERTIFICATE_INVALID,RECEIVE_FAILURE,CLOCK_FAILURE,JOIN_FAILURE);
        for(int i=0;i<original.size();i++)assertEquals(i,original.get(i).ordinal());
        assertEquals(UdpEndpoint.CloseReason.values().length-1,INTERNAL_FAILURE.ordinal());
    }
    @Test void validAndExactlyFiveMinutesFutureAreRunning() {
        try(var a=f.new Node(1)) {
            assertEquals(RUNNING,a.state.localCertificateReason(a.cert,Crypto.x25519Public(a.secret)));
            assertEquals(RUNNING,a.state.localCertificateReason(a.certificate(a.secret,f.time.millis+300_000),Crypto.x25519Public(a.secret)));
        }
    }
    @Test void expiredAloneHasItsOwnReason() {
        try(var a=f.new Node(1)) {
            f.time.millis=a.cert.expiresAt();
            assertEquals(LOCAL_CERTIFICATE_EXPIRED,a.state.localCertificateReason(a.cert,Crypto.x25519Public(a.secret)));
            a.sessions.refresh();assertEquals(LOCAL_CERTIFICATE_EXPIRED,a.sessions.closeReason());
        }
    }
    @Test void revokedIsInvalid() { revoked(false); }
    @Test void revokedWinsOverExpiryAndFirstReasonRemains() { revoked(true); }
    void revoked(boolean expired) {
        try(var a=f.new Node(1)) {
            a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis,List.of(a.id),f.admin));
            if(expired)f.time.millis=a.cert.expiresAt();
            assertEquals(LOCAL_CERTIFICATE_INVALID,a.state.localCertificateReason(a.cert,Crypto.x25519Public(a.secret)));
            a.sessions.refresh();f.time.millis=-1;a.sessions.refresh();a.sessions.close();
            assertEquals(LOCAL_CERTIFICATE_INVALID,a.sessions.closeReason());
        }
    }
    @Test void negativeClockDoesNotBecomeInvalid() {
        try(var a=f.new Node(1)) {
            f.time.millis=-1;
            assertEquals(CLOCK_FAILURE,a.state.localCertificateReason(a.cert,Crypto.x25519Public(a.secret)));
            a.sessions.refresh();assertEquals(CLOCK_FAILURE,a.sessions.closeReason());
        }
    }
    @Test void futureBeyondFiveMinutesDoesNotBecomeInvalid() {
        try(var a=f.new Node(1)) {
            f.time.millis-=300_001;
            assertEquals(CLOCK_FAILURE,a.state.localCertificateReason(a.cert,Crypto.x25519Public(a.secret)));
            a.sessions.refresh();assertEquals(CLOCK_FAILURE,a.sessions.closeReason());
        }
    }
    @Test void invalidAdminSignatureWinsOverExpiry() {
        try(var a=f.new Node(1)) {
            byte[] wire=a.cert.encode();wire[wire.length-1]^=1;var bad=AdminRecords.decode(wire);
            f.time.millis=bad.expiresAt();
            assertEquals(LOCAL_CERTIFICATE_INVALID,a.state.localCertificateReason(bad,Crypto.x25519Public(a.secret)));
        }
    }
    @Test void signerOutsideAdministratorsIsInvalid() {
        try(var a=f.new Node(1)) {
            var bad=AdminRecords.certificate(f.group,a.cert.field(0),a.cert.field(1),a.cert.field(2),f.time.millis,key(90));
            assertEquals(LOCAL_CERTIFICATE_INVALID,a.state.localCertificateReason(bad,a.cert.field(1)));
        }
    }
    @Test void handshakeMismatchAndInvalidBindingAreInvalid() {
        try(var a=f.new Node(1)) {
            assertEquals(LOCAL_CERTIFICATE_INVALID,a.state.localCertificateReason(a.cert,Crypto.x25519Public(key(90))));
            var bad=AdminRecords.certificate(f.group,a.cert.field(0),a.cert.field(1),new byte[64],f.time.millis,f.admin);
            assertEquals(LOCAL_CERTIFICATE_INVALID,a.state.localCertificateReason(bad,a.cert.field(1)));
        }
    }
}
