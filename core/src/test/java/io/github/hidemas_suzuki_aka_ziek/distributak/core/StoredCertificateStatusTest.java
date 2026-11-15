// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class StoredCertificateStatusTest {
    final AdminFormatTest fixture=new AdminFormatTest();
    @Test void storedExpiryIsDistinctFromInvalidSignature()throws Exception {
        var certificate=fixture.certificate(100);var state=fixture.state(certificate.expiresAt());
        assertEquals(AdminState.StoredCertificateStatus.EXPIRED,state.storedCertificateStatus(certificate,fixture.handshake));
        var invalid=AdminFormatTest.signed(certificate.signedBytes(),fixture.secret,false);
        assertThrows(SecurityException.class,()->state.storedCertificateStatus(invalid,fixture.handshake));
        assertThrows(SecurityException.class,()->state.verifyCertificate(certificate,fixture.handshake));
    }
    @Test void storedRevocationStillChecksIdentityProofAndSignature()throws Exception {
        var certificate=fixture.certificate(100);var state=fixture.state(1000);
        state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,fixture.group,1,1000,List.of(Crypto.blake2s(certificate.field(0))),fixture.secret));
        assertEquals(AdminState.StoredCertificateStatus.REVOKED,state.storedCertificateStatus(certificate,fixture.handshake));
        var invalid=AdminFormatTest.signed(certificate.signedBytes(),fixture.secret,false);
        assertThrows(SecurityException.class,()->state.storedCertificateStatus(invalid,fixture.handshake));
        assertThrows(SecurityException.class,()->state.verifyCertificate(certificate,fixture.handshake));
    }
    @Test void futureCertificateHasTypedClockStatus() {
        assertEquals(AdminState.StoredCertificateStatus.CLOCK_FAILURE,fixture.state(1000).storedCertificateStatus(fixture.certificate(301_001),fixture.handshake));
    }
    @Test void inheritanceCopiesOnlyAnExactPreviouslyPinnedCertificate()throws Exception {
        var old=AdminFormatTest.legacy(fixture.certificate(100),fixture.identity,fixture.secret);
        var unknown=AdminFormatTest.legacy(fixture.certificate(101),fixture.identity,fixture.secret);
        var previous=fixture.state(1000);var next=fixture.state(1000);previous.trustStoredLegacyCertificate(old);
        next.inheritStoredLegacyCertificate(previous,old);next.verifyCertificate(old,fixture.handshake);
        assertThrows(SecurityException.class,()->next.inheritStoredLegacyCertificate(previous,unknown));
        assertThrows(SecurityException.class,()->next.verifyCertificate(unknown,fixture.handshake));
    }
}
