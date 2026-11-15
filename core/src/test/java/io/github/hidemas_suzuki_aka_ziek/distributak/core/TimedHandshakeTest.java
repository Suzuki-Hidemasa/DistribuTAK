// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TimedHandshakeTest {
    final NoiseTest factory=new NoiseTest();
    TimedHandshake timed(Vectors v, boolean initiator, Instant time, TimestampReplayGuard guard) {
        // この試験は時計の層のみ。実際の証明書の検査は CertificateHandshakeTest と AdminStateTest。
        return new TimedHandshake(factory.create(v,initiator,v.bytes("init_psks.0")),initiator,Clock.fixed(time,ZoneOffset.UTC),guard,(cert,peer)->{});
    }
    @Test void roundTripClockOffsetAndOpaqueCertificates() throws Exception {
        var v=new Vectors("noise");var replay=new TimestampReplayGuard();
        try(var i=timed(v,true,Instant.EPOCH,replay);var r=timed(v,false,Instant.EPOCH.plusSeconds(99999999),replay)) {
            var first=r.readMessage(i.writeMessage(new byte[]{1,2,3}));
            assertArrayEquals(new byte[]{1,2,3},first.certificate());
            assertEquals(Duration.ofSeconds(-99999999),first.peerClockOffset());
            var second=i.readMessage(r.writeMessage(new byte[]{4,5}));
            assertArrayEquals(new byte[]{4,5},second.certificate());
            assertEquals(Duration.ofSeconds(99999999),second.peerClockOffset());
            try(var it=i.transport(()->0L);var rt=r.transport(()->0L)) {
                assertArrayEquals(new byte[]{6},rt.receive(it.send(new byte[]{6})));
            }
        }
    }
    @Test void validButOldAndEqualFirstMessagesRejected() throws Exception {
        var v=new Vectors("noise");var replay=new TimestampReplayGuard();
        for(int seconds:new int[]{100,100,99,101}) {
            try(var i=timed(v,true,Instant.ofEpochSecond(seconds),replay);var r=timed(v,false,Instant.EPOCH,replay)) {
                byte[] msg=i.writeMessage(new byte[0]);
                if(seconds==100 && replayCase++==0 || seconds==101) r.readMessage(msg);
                else {
                    assertThrows(SecurityException.class,()->r.readMessage(msg));
                    assertThrows(IllegalStateException.class,()->r.writeMessage(new byte[0]));
                }
            }
        }
    }
    private int replayCase;
    @Test void shortAuthenticatedPayloadRejected() throws Exception {
        var v=new Vectors("noise");
        try(var i=factory.create(v,true,v.bytes("init_psks.0"));var r=timed(v,false,Instant.EPOCH,new TimestampReplayGuard())) {
            byte[] msg=i.writeMessage(new byte[11]);
            assertThrows(SecurityException.class,()->r.readMessage(msg));
        }
    }
}
