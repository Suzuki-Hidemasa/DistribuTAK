// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.bouncycastle.util.encoders.Hex;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;
class RejoinedPeerHandshakeTest {
    final SessionManagerTest f=new SessionManagerTest();
    @Test void newHandshakeAdoptsOnlyAfterAuthenticationAndKeepsNewFirstTimestamp() throws Exception {
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            f.connect(b,a);f.time.millis++;
            byte[] freshSecret=key(90);var renewed=b.certificate(freshSecret,f.time.millis);
            try(var fresh=new SessionManager(b.state,renewed,freshSecret,f.psk,0,f.time,()->f.time.nanos,256)) {
                fresh.rememberPeer(a.cert);byte[] first=fresh.start(a.id).packet();
                byte[] bad=first.clone();bad[bad.length-1]^=1;
                assertThrows(SecurityException.class,()->a.sessions.receive(bad));
                assertArrayEquals(b.cert.encode(),a.sessions.peerCertificate(b.id).encode());
                assertArrayEquals(new byte[]{7},a.sessions.receive(f.data(b,a,7)).plaintext());
                var secrets=f.secrets(a,b);var reply=a.sessions.receive(first);
                f.wiped(secrets);assertArrayEquals(renewed.encode(),a.sessions.peerCertificate(b.id).encode());
                var timestamps=(Map<?,?>)SessionManagerTest.field(SessionManagerTest.field(a.sessions,"replay"),"newest");
                assertFalse(timestamps.containsKey(Hex.toHexString(b.cert.field(1))));assertTrue(timestamps.containsKey(Hex.toHexString(renewed.field(1))));
                a.sessions.receive(fresh.receive(reply.outbound().get(0).packet()).outbound().get(0).packet());assertTrue(a.sessions.isEstablished(b.id));
                assertArrayEquals(new byte[]{8},fresh.receive(a.sessions.send(b.id,new byte[]{8}).get(0).packet()).plaintext());
                try(var duplicate=new SessionManager(b.state,renewed,freshSecret,f.psk,0,f.time,()->f.time.nanos,256)) {
                    duplicate.rememberPeer(a.cert);assertThrows(SecurityException.class,()->a.sessions.receive(duplicate.start(a.id).packet()));
                }
                f.time.advance(6);assertThrows(SecurityException.class,()->a.sessions.receive(b.sessions.start(a.id).packet()));
                assertArrayEquals(renewed.encode(),a.sessions.peerCertificate(b.id).encode());
            }
        }
    }
    @Test void sameIssuedAtWithNewHandshakeStillCannotReplaceKnownPeer() throws Exception {
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            f.connect(b,a);var changed=b.certificate(key(90),b.cert.issuedAt());
            try(var fresh=new SessionManager(b.state,changed,key(90),f.psk,0,f.time,()->f.time.nanos,256)) {
                fresh.rememberPeer(a.cert);assertThrows(SecurityException.class,()->a.sessions.receive(fresh.start(a.id).packet()));
                assertArrayEquals(new byte[]{7},a.sessions.receive(f.data(b,a,7)).plaintext());assertArrayEquals(b.cert.encode(),a.sessions.peerCertificate(b.id).encode());
            }
        }
    }
}
