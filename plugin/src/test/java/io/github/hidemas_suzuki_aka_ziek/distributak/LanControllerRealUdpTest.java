// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

/** 実UDPは並行反復するOrderTestから分け、通常の単一forkで確認する。 */
public class LanControllerRealUdpTest {
    @Test public void actualSocketIoCompletesJoinAndPersistsPendingPeer()throws Exception{
        try(var admin=LanControllerHarness.realUdp();var member=LanControllerHarness.realUdp()){
            admin.create();member.beginJoin(admin);
            LanControllerHarness.until(()->member.ui.last.member&&admin.logs.contains("LAN_MEMBER_ISSUED"),admin,member);
            assertTrue(admin.link.received.get()>0);assertTrue(member.link.received.get()>0);
            try(var group=member.disk.load(LanControllerHarness.CLOCK)){assertNotNull(group.pendingHandshake);assertNull(group.peerCertificate);}
        }
    }
}
