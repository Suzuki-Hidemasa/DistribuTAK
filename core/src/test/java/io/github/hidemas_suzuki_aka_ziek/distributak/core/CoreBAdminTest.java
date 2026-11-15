// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;
class CoreBAdminTest {
    final SessionManagerTest f=new SessionManagerTest();
    @Test void allowExpiredRelaxesOnlyExpiry() {
        try(var a=f.new Node(1)) {
            f.time.millis=a.cert.expiresAt();
            assertDoesNotThrow(()->a.state.verifyCertificate(a.cert,a.cert.field(1),true));
            assertThrows(SecurityException.class,()->a.state.verifyCertificate(a.cert,a.cert.field(1),false));
            assertThrows(SecurityException.class,()->a.state.verifyCertificate(a.cert,key(90),true));
            byte[] bad=a.cert.encode();bad[bad.length-1]^=1;
            assertThrows(SecurityException.class,()->a.state.verifyCertificate(AdminRecords.decode(bad),a.cert.field(1),true));
            a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis,List.of(a.id),f.admin));
            assertThrows(SecurityException.class,()->a.state.verifyCertificate(a.cert,a.cert.field(1),true));
        }
    }
    @Test void allowExpiredStillRejectsClockBindingSignerAndMissingLists() {
        try(var a=f.new Node(1)) {
            f.time.millis=-1;assertThrows(SecurityException.class,()->a.state.verifyCertificate(a.cert,a.cert.field(1),true));
            f.time.millis=a.cert.issuedAt()-300_001;assertThrows(SecurityException.class,()->a.state.verifyCertificate(a.cert,a.cert.field(1),true));
            f.time.millis=a.cert.issuedAt();
            var binding=AdminRecords.certificate(f.group,a.cert.field(0),a.cert.field(1),new byte[64],f.time.millis,f.admin);
            assertThrows(SecurityException.class,()->a.state.verifyCertificate(binding,a.cert.field(1),true));
            var signer=AdminRecords.certificate(f.group,a.cert.field(0),a.cert.field(1),a.cert.field(2),f.time.millis,key(90));
            assertThrows(SecurityException.class,()->a.state.verifyCertificate(signer,a.cert.field(1),true));
            assertThrows(SecurityException.class,()->a.state.verifyCertificate(a.cert,new byte[31],true));
            a.state.clear();assertThrows(SecurityException.class,()->a.state.verifyCertificate(a.cert,a.cert.field(1),true));
        }
    }
    @Test void selfRenewalAtOneThirdAndAfterExpiry() {
        try(var a=f.new Node(31)) {
            long threshold=a.cert.expiresAt()-(a.cert.expiresAt()-a.cert.issuedAt())/3;
            f.time.millis=threshold-1;assertNull(a.state.renewOwnCertificate(a.cert,a.secret,f.admin,f.admin));
            f.time.millis=threshold;var renewed=a.state.renewOwnCertificate(a.cert,a.secret,f.admin,f.admin);
            assertEquals(threshold,renewed.issuedAt());assertArrayEquals(a.cert.field(0),renewed.field(0));assertArrayEquals(a.cert.field(1),renewed.field(1));
            f.time.millis=a.cert.expiresAt();assertNotNull(a.state.renewOwnCertificate(a.cert,a.secret,f.admin,f.admin));
        }
    }
    @Test void expiredAdministratorRenewsBeforeSessionManagerConstruction() {
        try(var a=f.new Node(31)) {
            a.sessions.close();f.time.millis=a.cert.expiresAt();
            assertThrows(SecurityException.class,()->new SessionManager(a.state,a.cert,a.secret,f.psk,0,f.time,()->f.time.nanos,256));
            var renewed=a.state.renewOwnCertificate(a.cert,a.secret,f.admin,f.admin);
            try(var sessions=new SessionManager(a.state,renewed,a.secret,f.psk,0,f.time,()->f.time.nanos,256)) {
                sessions.refresh();assertFalse(sessions.isClosed());
            }
        }
    }
    @Test void revokedOrNonAdministratorCannotSelfRenew() {
        try(var a=f.new Node(31);var b=f.new Node(1)) {
            f.time.millis=a.cert.expiresAt();
            assertThrows(SecurityException.class,()->b.state.renewOwnCertificate(b.cert,b.secret,key(1),key(1)));
            a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis,List.of(a.id),f.admin));
            assertThrows(SecurityException.class,()->a.state.renewOwnCertificate(a.cert,a.secret,f.admin,f.admin));
        }
    }
}
