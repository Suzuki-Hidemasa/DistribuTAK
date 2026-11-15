// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class SeparateAdministratorKeysTest {
    final SessionManagerTest f=new SessionManagerTest();
    @Test void separateAdministratorCanIssueRestoreAndSelfRenew()throws Exception {
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            a.remember(b);f.time.millis=b.cert.expiresAt()-AdminRecords.CERTIFICATE_LIFETIME_MILLIS/3;
            byte[] renewal=a.state.issueCertificateRenewal(b.cert,b.cert.field(2),f.admin,RenewalMessage.Reason.AUTO_RENEWAL,null).encode();assertNotNull(renewal);
            a.sessions.restorePeerRenewal(b.id,renewal,Crypto.ed25519Public(f.admin));
            var own=a.state.renewOwnCertificate(a.cert,a.secret,a.identity,f.admin);
            a.state.verifyCertificate(own,Crypto.x25519Public(a.secret));
            assertArrayEquals(Crypto.ed25519Public(a.identity),own.field(0));assertArrayEquals(Crypto.ed25519Public(f.admin),own.signer());
            try(var restored=new SessionManager(a.state,own,a.secret,f.psk,0,f.time,()->f.time.nanos,256)) {
                restored.rememberPeer(b.cert);restored.restorePeerRenewal(b.id,renewal,Crypto.ed25519Public(f.admin));
                assertTrue(java.util.Arrays.equals(renewal,(byte[])SessionManagerTest.field(((java.util.Map<?,?>)SessionManagerTest.field(restored,"peers")).get(org.bouncycastle.util.encoders.Hex.toHexString(b.id)),"renewal")));
            }
        }
    }
    @Test void identityKeyIsNotAdministratorAndWrongAdministratorCannotRestore() {
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            a.remember(b);f.time.millis=b.cert.expiresAt()-AdminRecords.CERTIFICATE_LIFETIME_MILLIS/3;
            assertThrows(SecurityException.class,()->a.state.issueCertificateRenewal(b.cert,b.cert.field(2),a.identity,RenewalMessage.Reason.AUTO_RENEWAL,null));
            assertThrows(SecurityException.class,()->a.state.renewOwnCertificate(a.cert,a.secret,a.identity,a.identity));
            byte[] renewal=AdminRecords.certificate(f.group,b.cert.field(0),b.cert.field(1),b.cert.field(2),f.time.millis,f.admin).encode();
            assertThrows(SecurityException.class,()->a.sessions.restorePeerRenewal(b.id,renewal,Crypto.ed25519Public(a.identity)));
        }
    }
}
