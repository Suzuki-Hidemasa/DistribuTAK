// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.List;
import java.time.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class MemberDirectoryTest {
    final SessionManagerTest fixture=new SessionManagerTest();
    UdpEndpoint.AdminJoined joined(AdminRecords.Record certificate){return new UdpEndpoint.AdminJoined(certificate,new java.net.InetSocketAddress("192.0.2.1",54321));}
    @Test void joinedRecordStoresPublicCertificateOnlyAndDoesNotChangeSessionPeer() {
        try(var a=fixture.new Node(1);var b=fixture.new Node(2)) {
            a.remember(b);var directory=new MemberDirectory(a.state);assertTrue(directory.joined(joined(b.cert)));
            var entry=directory.get(b.id);assertTrue(Crypto.equal(entry.identityKey(),b.cert.field(0)));assertTrue(Crypto.equal(entry.handshakeKey(),b.cert.field(1)));
            assertTrue(Crypto.equal(entry.digest(),Crypto.blake2s(b.cert.signedBytes())));assertEquals(b.cert.issuedAt(),entry.issuedAt());
            fixture.time.millis++;var next=b.certificate(AdminRecordsTest.key(90),fixture.time.millis);assertTrue(directory.joined(joined(next)));
            assertTrue(java.util.Arrays.equals(b.cert.encode(),a.sessions.peerCertificate(b.id).encode()));
        }
    }
    @Test void olderHandshakeCannotReplaceLatestAndEqualTimeConflictIsRejected() {
        try(var a=fixture.new Node(1);var b=fixture.new Node(2)) {
            var directory=new MemberDirectory(a.state);directory.saved(b.cert);fixture.time.millis++;
            var next=b.certificate(AdminRecordsTest.key(90),fixture.time.millis);directory.joined(joined(next));assertFalse(directory.saved(b.cert));
            var conflict=b.certificate(AdminRecordsTest.key(91),fixture.time.millis);
            assertThrows(MemberDirectory.Conflict.class,()->directory.joined(joined(conflict)));
            assertTrue(java.util.Arrays.equals(next.encode(),directory.get(b.id).certificate().encode()));
        }
    }
    @Test void summaryDistinguishesMissingNewerEqualAndConflict() {
        try(var b=fixture.new Node(2)) {
            var directory=new MemberDirectory(b.state);directory.saved(b.cert);var entry=directory.get(b.id);
            assertEquals(MemberDirectory.Difference.EQUAL,directory.compare(new MemberDirectory.Summary(b.id,entry.issuedAt(),entry.digest())));
            assertEquals(MemberDirectory.Difference.REMOTE_NEWER,directory.compare(new MemberDirectory.Summary(b.id,entry.issuedAt()+1,entry.digest())));
            assertEquals(MemberDirectory.Difference.LOCAL_NEWER,directory.compare(new MemberDirectory.Summary(b.id,entry.issuedAt()-1,entry.digest())));
            assertEquals(MemberDirectory.Difference.UNKNOWN,directory.compare(new MemberDirectory.Summary(new byte[32],entry.issuedAt(),entry.digest())));
            byte[] other=entry.digest();other[0]^=1;assertEquals(MemberDirectory.Difference.CONFLICT,directory.compare(new MemberDirectory.Summary(b.id,entry.issuedAt(),other)));
        }
    }
    @Test void firstRegistrationRequiresAnAuthenticatedFirstAndCannotBeSatisfiedBySecond() {
        try(var a=fixture.new Node(1);var b=fixture.new Node(2)) {
            fixture.connect(a,b);var directory=new MemberDirectory(a.state);
            assertThrows(SecurityException.class,()->directory.authenticatedFirst(a.sessions,b.id));
            assertTrue(directory.authenticatedFirst(b.sessions,a.id));
        }
    }
    @Test void directoryDeliveryRequiresBoundAdministratorAndIsAtomic() {
        try(var a=fixture.new Node(1);var b=fixture.new Node(2);var m=fixture.new Node(3)) {
            fixture.connect(a,b);var directory=new MemberDirectory(a.state);
            assertThrows(SecurityException.class,()->directory.administratorDirectory(b.sessions,a.id,List.of(m.cert)));
            var proof=AdminControl.keyProof(fixture.group,new byte[16],0,a.identity,fixture.admin);
            a.state.acceptAdministrators(AdminRecords.administrators(fixture.group,1,fixture.time.millis,List.of(AdminBinding.bound(proof.administratorKey(),a.id,proof.encode())),fixture.admin),v->fail());
            assertTrue(directory.administratorDirectory(b.sessions,a.id,List.of(m.cert)));assertNotNull(directory.get(m.id));
            byte[] bad=m.cert.encode();bad[bad.length-1]^=1;var invalid=AdminRecords.decode(bad);int before=directory.size();
            assertThrows(SecurityException.class,()->directory.administratorDirectory(b.sessions,a.id,List.of(b.cert,invalid)));assertEquals(before,directory.size());assertNull(directory.get(b.id));
        }
    }
    @Test void savedExpiryIsRetainedButNotUsedAsARecipient() {
        var f=new AdminFormatTest();var cert=f.certificate(100);var state=f.state(cert.expiresAt());var directory=new MemberDirectory(state);
        assertTrue(directory.saved(cert));assertEquals(1,directory.size());assertTrue(directory.validRecipients().isEmpty());
        assertThrows(SecurityException.class,()->directory.joined(joined(cert)));
    }
    @Test void revocationRemovesRecipientWithoutLosingLatestCertificateMetadata() {
        try(var b=fixture.new Node(2)) {
            var directory=new MemberDirectory(b.state);directory.saved(b.cert);assertEquals(1,directory.validRecipients().size());
            b.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,fixture.group,1,fixture.time.millis,List.of(b.id),fixture.admin));
            assertTrue(directory.validRecipients().isEmpty());assertEquals(1,directory.size());
        }
    }
    @Test void unknownLegacyCannotEnterThroughSavedMigration()throws Exception {
        var f=new AdminFormatTest();var state=f.state(1000);var old=AdminFormatTest.legacy(f.certificate(100),f.identity,f.secret);var directory=new MemberDirectory(state);
        assertThrows(SecurityException.class,()->directory.saved(old));state.trustStoredLegacyCertificate(old);assertTrue(directory.saved(old));
    }
    @Test void snapshotRetainsExpiredAndRevokedCertificatesAndIsDefensive(){
        try(var b=fixture.new Node(2)){
            var directory=new MemberDirectory(b.state);directory.saved(b.cert);
            b.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,fixture.group,1,fixture.time.millis,List.of(b.id),fixture.admin));
            fixture.time.advance(31*24*60*60);assertTrue(directory.validRecipients().isEmpty());
            var restored=new MemberDirectory(b.state);restored.restoreSnapshot(directory.snapshot());assertEquals(1,restored.size());assertTrue(restored.validRecipients().isEmpty());
            assertEquals(1,directory.snapshot().size());byte[] bytes=directory.snapshot().get(0);bytes[0]^=1;
            assertArrayEquals(b.cert.encode(),directory.snapshot().get(0));
        }
    }

}
