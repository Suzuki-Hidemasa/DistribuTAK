// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RejectionStateTest {
    private final NoiseTest factory=new NoiseTest();

    @Test void failedHandshakeWipesOwnedSecretsInBothDirections() throws Exception {
        var v=new Vectors("noise");
        for(boolean first:new boolean[]{true,false}) {
            try(var i=factory.create(v,true,v.bytes("init_psks.0"));var r=factory.create(v,false,v.bytes("resp_psks.0"))) {
                byte[] message=i.writeMessage(new byte[]{1});
                NoiseHandshake target=r;
                if(!first) { r.readMessage(message);message=r.writeMessage(new byte[]{2});target=i; }
                String[] names={"s","e","psk","ck","k"};byte[][] secrets=new byte[names.length][];
                for(int n=0;n<names.length;n++) secrets[n]=SecretAssertions.bytes(target,names[n]);
                byte[] bad=message;bad[bad.length-1]^=1;NoiseHandshake receiver=target;
                assertThrows(SecurityException.class,()->receiver.readMessage(bad));
                for(int n=0;n<names.length;n++) {
                    if(secrets[n]!=null) SecretAssertions.zero(secrets[n]);
                    SecretAssertions.zero(SecretAssertions.bytes(target,names[n]));
                }
                assertThrows(IllegalStateException.class,()->receiver.readMessage(bad));
            }
        }
    }
    @Test void noiseAuthenticationFailurePreservesReceiveCounter() throws Exception {
        try(var s=new NoiseTransport(new byte[32],new byte[32],()->0L);var r=new NoiseTransport(new byte[32],new byte[32],()->0L)) {
            for(int n=0;n<2;n++) {
                byte[] good=s.send(new byte[]{(byte)n}),bad=good.clone();bad[0]^=1;
                assertThrows(SecurityException.class,()->r.receive(bad));
                assertEquals((long)n,SecretAssertions.field(r,"received"));
                assertArrayEquals(new byte[]{(byte)n},r.receive(good));
            }
        }
    }
    @Test void hpkeAuthenticationFailurePreservesSequenceAndCloseWipes() throws Exception {
        var v=new Vectors("hpke");
        try(var s=Hpke.sender(v.bytes("pkRm"),v.bytes("info"),v.bytes("skEm"));var r=Hpke.recipient(v.bytes("skRm"),s.encapsulation(),v.bytes("info"))) {
            for(int n=0;n<2;n++) {
                byte[] before=SecretAssertions.bytes(r,"sequence").clone();
                byte[] good=s.seal(new byte[0],new byte[]{(byte)n}),bad=good.clone();bad[0]^=1;
                assertThrows(SecurityException.class,()->r.open(new byte[0],bad));
                assertArrayEquals(before,SecretAssertions.bytes(r,"sequence"));
                assertArrayEquals(new byte[]{(byte)n},r.open(new byte[0],good));
            }
            byte[] key=SecretAssertions.bytes(r,"key"),nonce=SecretAssertions.bytes(r,"baseNonce"),exporter=SecretAssertions.bytes(r,"exporter");
            r.close();SecretAssertions.zero(key);SecretAssertions.zero(nonce);SecretAssertions.zero(exporter);
        }
    }
    @Test void invalidFirstMessagesLeaveTimestampRecordUnchanged() throws Exception {
        var v=new Vectors("noise");
        for(boolean tamper:new boolean[]{true,false}) {
            var guard=new TimestampReplayGuard();byte[] peer=Crypto.x25519Public(v.bytes("init_static"));
            guard.accept(peer,Tai64n.encode(Instant.ofEpochSecond(50)));
            var before=Map.copyOf((Map<?,?>)SecretAssertions.field(guard,"newest"));
            byte[] previous=((byte[])before.values().iterator().next()).clone();
            try(var i=factory.create(v,true,v.bytes("init_psks.0"));
                var r=new TimedHandshake(factory.create(v,false,v.bytes("resp_psks.0")),false,Clock.systemUTC(),guard,(cert,pub)->{})) {
                byte[] message=i.writeMessage(tamper ? Tai64n.encode(Instant.ofEpochSecond(200)) : new byte[11]);
                if(tamper) message[message.length-1]^=1;
                assertThrows(SecurityException.class,()->r.readMessage(message));
            }
            assertEquals(before,SecretAssertions.field(guard,"newest"));
            assertArrayEquals(previous,(byte[])((Map<?,?>)SecretAssertions.field(guard,"newest")).values().iterator().next());
            // 失敗した200秒の記録が入っていなければ、100秒を受けられる。
            try(var i=new TimedHandshake(factory.create(v,true,v.bytes("init_psks.0")),true,Clock.fixed(Instant.ofEpochSecond(100),ZoneOffset.UTC),guard,(cert,pub)->{});
                var r=new TimedHandshake(factory.create(v,false,v.bytes("resp_psks.0")),false,Clock.systemUTC(),guard,(cert,pub)->{})) {
                r.readMessage(i.writeMessage(new byte[0]));
            }
        }
    }
    @Test void receivingWithExpiredTransportKeyFailsAndWipes() throws Exception {
        var ticker=new AtomicLong();
        byte[] key=TotpTest.SECRET.clone();
        try(var s=new NoiseTransport(key,key,()->0L);var r=new NoiseTransport(key,key,ticker::get)) {
            byte[] receiving=SecretAssertions.bytes(r,"receiving");
            byte[] ciphertext=s.send(new byte[]{1});ticker.set(180_000_000_001L);
            assertThrows(SecurityException.class,()->r.receive(ciphertext));
            SecretAssertions.zero(receiving);
            assertThrows(IllegalStateException.class,()->r.receive(ciphertext));
        }
    }
    @Test void overlyLongInvitationUrlRejected() {
        assertThrows(IllegalArgumentException.class,()->InvitationUrl.decode("distributak://join#"+"A".repeat(233)));
    }
    @Test void nullHandshakeArgumentsRejectedBeforeUse() {
        byte[] key=new byte[32];
        assertThrows(IllegalArgumentException.class,()->new NoiseHandshake(true,null,key,key,new byte[0]));
        assertThrows(IllegalArgumentException.class,()->new NoiseHandshake(true,key,null,key,new byte[0]));
        assertThrows(IllegalArgumentException.class,()->new NoiseHandshake(true,key,key,null,new byte[0]));
        assertThrows(IllegalArgumentException.class,()->new NoiseHandshake(true,key,key,key,null));
        assertThrows(IllegalArgumentException.class,()->new NoiseHandshake(false,key,null,key,null));
    }
    @Test void lowOrderPeerKeysAlwaysRaiseSecurityException() {
        byte[] secret=TotpTest.SECRET;
        for(int firstByte:new int[]{0,1}) {
            byte[] lowOrder=new byte[32];lowOrder[0]=(byte)firstByte;
            assertThrowsExactly(SecurityException.class,()->Crypto.x25519(secret,lowOrder));
            assertThrowsExactly(SecurityException.class,()->Hpke.sender(lowOrder,new byte[0]));
            assertThrowsExactly(SecurityException.class,()->Hpke.recipient(secret,lowOrder,new byte[0]));
        }
    }
}
