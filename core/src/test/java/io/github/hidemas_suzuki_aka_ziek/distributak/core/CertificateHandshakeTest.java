// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class CertificateHandshakeTest {
    @Test void realCertificatesVerifiedOnBothMessagesBeforeTransport() {
        var f=new AdminStateTest();var state=f.fresh();var replay=new TimestampReplayGuard();
        byte[] initiatorSecret=key(21),responderSecret=key(22),psk=key(23);
        var first=AdminRecords.certificate(f.group,Crypto.ed25519Public(f.identity),Crypto.x25519Public(initiatorSecret),SignaturePurpose.identityProof(f.identity,f.group,Crypto.x25519Public(initiatorSecret)),f.now,f.a);
        var second=AdminRecords.certificate(f.group,Crypto.ed25519Public(f.c),Crypto.x25519Public(responderSecret),SignaturePurpose.identityProof(f.c,f.group,Crypto.x25519Public(responderSecret)),f.now,f.a);
        TimedHandshake.CertificateVerifier verify=(cert,peer)->state.verifyCertificate(AdminRecords.decode(cert),peer);
        try(var i=new TimedHandshake(new NoiseHandshake(true,initiatorSecret,Crypto.x25519Public(responderSecret),psk,new byte[0]),true,f.clock,replay,verify);
            var r=new TimedHandshake(new NoiseHandshake(false,responderSecret,null,psk,new byte[0]),false,f.clock,replay,verify)) {
            r.readMessage(i.writeMessage(first.encode()));
            assertThrows(IllegalStateException.class,()->i.transport(()->0L));
            i.readMessage(r.writeMessage(second.encode()));
            try(var sending=i.transport(()->0L);var receiving=r.transport(()->0L)) {
                assertArrayEquals(new byte[]{7},receiving.receive(sending.send(new byte[]{7})));
            }
            assertThrows(SecurityException.class,()->replay.check(Crypto.x25519Public(initiatorSecret),Tai64n.encode(f.clock.instant())));
        }
    }
    @Test void rejectedSecondCertificateClosesInitiatorAndWipesItsSecrets() throws Exception {
        var f=new NoiseTest();var v=new Vectors("noise");var guard=new TimestampReplayGuard();
        try(var raw=f.create(v,true,v.bytes("init_psks.0"));var r=f.create(v,false,v.bytes("resp_psks.0"));
            var i=new TimedHandshake(raw,true,Clock.systemUTC(),guard,(cert,peer)->{throw new SecurityException("拒否");})) {
            byte[] secret=SecretAssertions.bytes(raw,"s");
            r.readMessage(i.writeMessage(new byte[]{1}));
            assertThrows(SecurityException.class,()->i.readMessage(r.writeMessage(Crypto.concat(Tai64n.encode(Instant.EPOCH),new byte[]{2}))));
            SecretAssertions.zero(secret);assertThrows(IllegalStateException.class,()->i.transport(()->0L));
        }
    }
    @Test void checkDoesNotCommitAndCommitRechecksAndRemoveWorks() {
        var replay=new TimestampReplayGuard();byte[] peer=key(4),one=Tai64n.encode(Instant.ofEpochSecond(1)),two=Tai64n.encode(Instant.ofEpochSecond(2));
        replay.check(peer,one);replay.check(peer,one);
        replay.commit(peer,two);
        assertThrows(SecurityException.class,()->replay.commit(peer,one));
        replay.remove(peer);replay.commit(peer,one);
        assertThrows(SecurityException.class,()->replay.check(peer,one));
    }
    @Test void certificateFailureLeavesFirstTimestampUnchangedAndClosesNoise() throws Exception {
        var f=new NoiseTest();var v=new Vectors("noise");var replay=new TimestampReplayGuard();
        try(var i=f.create(v,true,v.bytes("init_psks.0"));
            var r=new TimedHandshake(f.create(v,false,v.bytes("init_psks.0")),false,Clock.systemUTC(),replay,(cert,peer)->{throw new SecurityException("証明書が違います");})) {
            byte[] time=Tai64n.encode(Instant.ofEpochSecond(100));
            assertThrows(SecurityException.class,()->r.readMessage(i.writeMessage(Crypto.concat(time,new byte[]{1}))));
            replay.check(Crypto.x25519Public(v.bytes("init_static")),time);
            assertThrows(IllegalStateException.class,()->r.writeMessage(new byte[0]));
            assertThrows(IllegalStateException.class,()->r.transport(()->0L));
        }
    }
    @Test void verifierSeesNoisePeerAndCommitRaceRejectsLosingHandshake() throws Exception {
        var f=new NoiseTest();var v=new Vectors("noise");var replay=new TimestampReplayGuard();
        byte[] peer=Crypto.x25519Public(v.bytes("init_static"));
        try(var i=f.create(v,true,v.bytes("init_psks.0"));
            var r=new TimedHandshake(f.create(v,false,v.bytes("init_psks.0")),false,Clock.systemUTC(),replay,(cert,actual)->{
                assertArrayEquals(peer,actual);assertArrayEquals(new byte[]{7},cert);
                replay.commit(actual,Tai64n.encode(Instant.ofEpochSecond(101)));
            })) {
            assertThrows(IllegalStateException.class,()->r.writeMessage(new byte[0]));
            assertThrows(IllegalStateException.class,()->r.transport(()->0L));
            assertThrows(SecurityException.class,()->r.readMessage(i.writeMessage(Crypto.concat(Tai64n.encode(Instant.ofEpochSecond(100)),new byte[]{7}))));
            assertThrows(SecurityException.class,()->replay.check(peer,Tai64n.encode(Instant.ofEpochSecond(100))));
        }
    }
}
