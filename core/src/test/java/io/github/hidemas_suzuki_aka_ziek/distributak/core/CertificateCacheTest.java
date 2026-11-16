// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;

class CertificateCacheTest {
    @Test void stableReferencesSkipOnlySignaturesAndEveryDynamicCheckStillRuns() {
        var f=new SessionManagerTest();
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            var cache=new AdminState.CertificateChecks();byte[] pub=b.cert.field(1);
            a.state.verifyCertificateCached(b.cert,pub,cache);assertEquals(1,cache.checks);
            a.state.verifyCertificateCached(b.cert,pub,cache);assertEquals(1,cache.checks);
            assertThrows(SecurityException.class,()->a.state.verifyCertificateCached(b.cert,new byte[32],cache));
            assertEquals(1,cache.checks);
            long original=f.time.millis;f.time.millis=b.cert.issuedAt()-300_001;
            assertThrows(SecurityException.class,()->a.state.verifyCertificateCached(b.cert,pub,cache));
            f.time.millis=original;a.state.verifyCertificateCached(b.cert,pub,cache);assertEquals(1,cache.checks);
            var copy=AdminRecords.decode(b.cert.encode());a.state.verifyCertificateCached(copy,pub,cache);assertEquals(2,cache.checks);
            a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis(),List.of(b.id),f.admin));
            for(int i=0;i<10;i++)assertThrows(SecurityException.class,()->a.state.verifyCertificateCached(copy,pub,cache));
            assertEquals(3,cache.checks);
            a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,2,f.time.millis(),List.of(),f.admin));
            assertThrows(SecurityException.class,()->a.state.verifyCertificateCached(copy,pub,cache));assertEquals(4,cache.checks);
            f.time.advance(30L*24*60*60);
            for(int i=0;i<10;i++)assertThrows(SecurityException.class,()->a.state.verifyCertificateCached(copy,pub,cache));
            assertEquals(4,cache.checks);
        }
    }
    @Test void receiveRefreshDoesNotRepeatHeavyWorkAndRevokedPeersDoNotRepeatItEither() throws Exception {
        var f=new SessionManagerTest();
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            f.connect(a,b);a.sessions.refresh();
            var local=(AdminState.CertificateChecks)SessionManagerTest.field(a.sessions,"localChecks");
            var peer=(AdminState.CertificateChecks)SessionManagerTest.field(f.peerState(a,b),"checks");
            long before=local.checks+peer.checks;
            byte[] bad=f.data(b,a,1);bad[bad.length-1]^=1;
            for(int i=0;i<100;i++)assertThrows(SecurityException.class,()->a.sessions.receive(bad));
            assertEquals(before,local.checks+peer.checks);
            a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis(),List.of(b.id),f.admin));
            a.sessions.refresh();assertFalse(a.sessions.isEstablished(b.id));long invalid=local.checks+peer.checks;
            for(int i=0;i<100;i++)a.sessions.refresh();assertEquals(invalid,local.checks+peer.checks);
            a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,2,f.time.millis(),List.of(a.id),f.admin));
            a.sessions.refresh();assertTrue(a.sessions.isClosed());
        }
    }
    @Test void administratorReferenceChangesIncludingSameVersionInvalidateOnlySignatures() {
        var f=new SessionManagerTest();
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            var cache=new AdminState.CertificateChecks();byte[] pub=b.cert.field(1);
            a.state.verifyCertificateCached(b.cert,pub,cache);
            var next=AdminRecords.list(ADMINS,f.group,1,f.time.millis(),List.of(Crypto.ed25519Public(f.admin)),f.admin);
            assertTrue(a.state.acceptAdministrators(next,n->fail()));a.state.verifyCertificateCached(b.cert,pub,cache);assertEquals(2,cache.checks);
            var sameVersion=AdminRecords.list(ADMINS,f.group,1,f.time.millis()+1,List.of(Crypto.ed25519Public(f.admin)),f.admin);
            assertTrue(a.state.acceptAdministrators(sameVersion,n->fail()));a.state.verifyCertificateCached(b.cert,pub,cache);assertEquals(3,cache.checks);
            var removed=AdminProofFixtures.list(f.group,2,f.time.millis()+1,List.of(Crypto.ed25519Public(AdminRecordsTest.key(80))),f.admin,AdminRecordsTest.key(80));
            assertTrue(a.state.acceptAdministrators(removed,n->fail()));
            for(int n=0;n<10;n++)assertThrows(SecurityException.class,()->a.state.verifyCertificateCached(b.cert,pub,cache));
            assertEquals(4,cache.checks);
        }
    }
    @Test void failedSignaturesAreCachedAndPublicVerifierKeepsItsFailure() {
        var f=new SessionManagerTest();
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            byte[] encoded=b.cert.encode();encoded[encoded.length-1]^=1;var bad=AdminRecords.decode(encoded);
            var cache=new AdminState.CertificateChecks();
            var expected=assertThrows(SecurityException.class,()->a.state.verifyCertificate(bad,bad.field(1)));
            for(int n=0;n<10;n++)assertEquals(expected.getMessage(),assertThrows(SecurityException.class,()->a.state.verifyCertificateCached(bad,bad.field(1),cache)).getMessage());
            assertEquals(1,cache.checks);a.state.verifyCertificateCached(b.cert,b.cert.field(1),cache);assertEquals(2,cache.checks);
        }
    }

}
