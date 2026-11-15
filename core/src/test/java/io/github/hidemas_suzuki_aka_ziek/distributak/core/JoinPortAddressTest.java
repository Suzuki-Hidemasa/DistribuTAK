// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.JoinPortLimitsTest.*;

class JoinPortAddressTest {
    @Test void mappedAndNativeV4UseTheSamePinnedAddressAndRateEntry() throws Exception {
        try(var f=new AdminFixture();var ready=JoinWire.decode(f.ready())) {
            var mapped=UdpEndpointDualStackTest.mapped(SOURCE.getPort());
            f.io.inject(JoinWire.fetch(f.id,f.transfer,ready.total(),0),mapped);
            var first=f.io.take();assertEquals(SOURCE,first.source());
            try(var frame=JoinWire.decode(first.wire())) { assertEquals(JoinWire.DATA,frame.kind()); }
            f.io.inject(JoinWire.fetch(f.id,f.transfer,ready.total(),0),SOURCE);
            assertEquals(SOURCE,f.io.take().source());
            var engine=(JoinPort)SessionManagerTest.field(f.endpoint,"joins");
            synchronized(engine) {
                assertEquals(1,((Map<?,?>)SessionManagerTest.field(engine,"responseRates")).size());
                var registration=(JoinPort.Registration)f.registration;
                assertEquals(SOURCE,registration.address);
            }
            assertEquals(SOURCE,f.registration.lastJoined().address());
        }
    }
}
