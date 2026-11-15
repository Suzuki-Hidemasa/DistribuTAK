// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class NoiseTest {
    NoiseHandshake create(Vectors v, boolean initiator, byte[] psk) {
        return new NoiseHandshake(initiator, v.bytes(initiator ? "init_static" : "resp_static"),
            initiator ? v.bytes("init_remote_static") : null, psk,
            v.bytes("init_prologue"), v.bytes(initiator ? "init_ephemeral" : "resp_ephemeral"));
    }
    @Test void publicCacophonyVector() throws Exception {
        var v = new Vectors("noise");
        try (var i = create(v,true,v.bytes("init_psks.0")); var r = create(v,false,v.bytes("resp_psks.0"))) {
            byte[] first = i.writeMessage(v.bytes("messages.0.payload"));
            assertArrayEquals(v.bytes("messages.0.ciphertext"), first);
            assertArrayEquals(v.bytes("messages.0.payload"),r.readMessage(first));
            byte[] second = r.writeMessage(v.bytes("messages.1.payload"));
            assertArrayEquals(v.bytes("messages.1.ciphertext"),second);
            assertArrayEquals(v.bytes("messages.1.payload"),i.readMessage(second));
            assertArrayEquals(v.bytes("handshake_hash"),i.handshakeHash());
            assertArrayEquals(i.handshakeHash(),r.handshakeHash());
            try (var it = i.transport(() -> 0L); var rt = r.transport(() -> 0L)) {
                for (int n=2; n<v.count("messages"); n++) {
                    var sender = n%2 == 0 ? it : rt; var receiver = n%2 == 0 ? rt : it;
                    byte[] ct = sender.send(v.bytes("messages."+n+".payload"));
                    assertArrayEquals(v.bytes("messages."+n+".ciphertext"),ct);
                    assertArrayEquals(v.bytes("messages."+n+".payload"),receiver.receive(ct));
                }
            }
            assertThrows(IllegalStateException.class, () -> i.writeMessage(new byte[0]));
        }
    }
    @Test void tamperedMessagesAndWrongPskFailClosed() throws Exception {
        var v = new Vectors("noise");
        for (int stage=0;stage<3;stage++) {
            byte[] psk = v.bytes("resp_psks.0"); if (stage==2) psk[0]^=1;
            try (var i=create(v,true,v.bytes("init_psks.0"));var r=create(v,false,psk)) {
                byte[] m=i.writeMessage(new byte[]{1});
                if (stage==0) {
                    m[m.length-1]^=1;
                    assertThrows(SecurityException.class,()->r.readMessage(m));
                    assertThrows(IllegalStateException.class,()->r.readMessage(m));
                } else {
                    r.readMessage(m); byte[] second=r.writeMessage(new byte[]{2});
                    if(stage==1) second[second.length-1]^=1;
                    assertThrows(SecurityException.class,()->i.readMessage(second));
                    assertThrows(IllegalStateException.class,()->i.readMessage(second));
                }
            }
        }
    }
    @Test void wrongOrderAndTruncation() throws Exception {
        var v = new Vectors("noise");
        try(var r=create(v,false,v.bytes("resp_psks.0"))) {
            assertThrows(IllegalStateException.class,()->r.writeMessage(new byte[0]));
            assertThrows(SecurityException.class,()->r.readMessage(new byte[95]));
        }
    }
    @Test void noiseMessageSizeLimit() throws Exception {
        var v=new Vectors("noise");
        try(var i=create(v,true,v.bytes("init_psks.0"))) {
            assertThrows(IllegalArgumentException.class,()->i.writeMessage(new byte[65535-96+1]));
        }
        try(var r=create(v,false,v.bytes("resp_psks.0"))) {
            assertThrows(SecurityException.class,()->r.readMessage(new byte[65536]));
        }
        try(var t=new NoiseTransport(new byte[32],new byte[32],()->0L)) {
            assertEquals(65535,t.send(new byte[65519]).length);
            assertThrows(IllegalArgumentException.class,()->t.send(new byte[65520]));
            assertThrows(IllegalArgumentException.class,()->t.receive(new byte[65536]));
        }
    }
}
