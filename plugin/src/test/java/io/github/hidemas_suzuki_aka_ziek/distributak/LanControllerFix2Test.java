// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class LanControllerFix2Test {
    @Test public void lostThenSameNetworkBeforeWorkerRunsInvalidatesCameraTicket() throws Exception {
        try(var f=new LanControllerHarness()) {
            var ticket=f.controller.ticket();f.ui.sensitive=true;
            f.network.current=null;f.network.changed.run();f.network.current=f.link;f.network.changed.run();
            assertFalse(f.controller.accepts(ticket));f.drain();assertFalse(f.controller.accepts(ticket));assertFalse(f.ui.sensitive);
            f.controller.join(f.unreachable(),ticket);f.drain();assertEquals(0,f.link.opens);assertFalse(f.ui.last.busy);
        }
    }
    @Test public void sameNetworkIpv4ChangesAndReturnsBeforeWorkerRunsClosesInvitation() throws Exception {
        try(var f=new LanControllerHarness()) {
            f.create();f.invitation();var endpoint=f.endpoint();var ticket=f.controller.ticket();
            var other=f.new Link(f.link.id,(java.net.Inet4Address)java.net.InetAddress.getByAddress(new byte[]{(byte)192,0,2,(byte)240}));
            f.network.current=other;f.network.changed.run();f.network.current=f.link;f.network.changed.run();f.drain();
            assertFalse(f.controller.accepts(ticket));assertTrue(endpoint.isTerminated());assertNull(f.endpoint());
            assertNull(LanControllerHarness.field(f.controller,"invitation"));assertFalse(f.ui.sensitive);
        }
    }
    @Test public void identicalNetworkNotificationsPreserveTicketAndOpenInvitation() throws Exception {
        try(var f=new LanControllerHarness()) {
            f.create();f.invitation();var endpoint=f.endpoint();var ticket=f.controller.ticket();
            f.network.changed.run();f.network.changed.run();f.drain();
            assertTrue(f.controller.accepts(ticket));assertSame(endpoint,f.endpoint());assertTrue(f.ui.sensitive);
        }
    }
    @Test public void discardedQrDoesNotClaimItWasShown() throws Exception {
        try(var f=new LanControllerHarness()) {
            f.create();f.controller.showInvitation(f.controller.ticket());f.work.drain();f.ui.hide();f.ui.show();f.main.drain();
            f.work.drain();f.main.drain();assertEquals(0,f.ui.qrs);assertFalse(f.logs.contains("LAN_INVITATION_SHOWN"));
            assertFalse(f.ui.last.text.contains("招待QRを表示しました"));
            f.controller.showInvitation(f.controller.ticket());f.drain();f.drain();
            assertEquals(1,f.ui.qrs);assertTrue(f.logs.contains("LAN_INVITATION_SHOWN"));assertTrue(f.ui.last.text.contains("招待QRを表示しました"));
        }
    }

    private static void failAfterIssue(LanControllerHarness admin,LanControllerHarness joiner)throws Exception {
        admin.create();joiner.disk.afterStage=()->joiner.offset.addAndGet(11_000_000_000L);joiner.beginJoin(admin);
        LanControllerHarness.until("issued-but-uncommitted",()->joiner.disk.staged==1&&!joiner.ui.last.busy
                &&admin.logs.contains("LAN_MEMBER_ISSUED"),admin,joiner);
        assertTrue(admin.ui.last.member);assertFalse(admin.ui.last.admin);assertFalse(joiner.ui.last.member);
        assertFalse(joiner.ui.last.text.contains("加入できませんでした。新しい招待でやり直してください"));
        assertTrue(joiner.ui.last.text.contains("招待を出せる場合"));
    }
    @Test public void issuedAdminAndUncommittedJoinerCanRecoverBySwappingRoles() throws Exception {
        try(var admin=new LanControllerHarness();var joiner=new LanControllerHarness()) {
            failAfterIssue(admin,joiner);assertFalse(joiner.ui.last.erased);
            joiner.create();admin.controller.erase();admin.drain();assertFalse(admin.ui.last.member);assertTrue(admin.ui.last.erased);
            admin.beginJoin(joiner);LanControllerHarness.until("role-swap recovery",()->admin.ui.last.member,admin,joiner);
            assertTrue(admin.ui.last.ready);assertFalse(admin.ui.last.erased);
            try(var left=admin.disk.load(LanControllerHarness.CLOCK);var right=joiner.disk.load(LanControllerHarness.CLOCK)) {
                assertArrayEquals(left.groupId,right.groupId);
            }
        }
    }
    @Test public void bothErasedAfterIssuedJoinFailureCanRecoverWithNewGroup() throws Exception {
        try(var admin=new LanControllerHarness();var joiner=new LanControllerHarness()) {
            joiner.disk.erased=true;failAfterIssue(admin,joiner);admin.controller.erase();admin.drain();
            assertTrue(StoreRecovery.canCreate(admin.ui.last.member,admin.ui.last.erasing));
            assertTrue(StoreRecovery.canCreate(joiner.ui.last.member,joiner.ui.last.erasing));
            admin.create();joiner.disk.afterStage=()->{};joiner.beginJoin(admin);
            LanControllerHarness.until("both-erased issued-failure recovery",()->joiner.ui.last.member,admin,joiner);
            assertFalse(admin.ui.last.erased);assertFalse(joiner.ui.last.erased);
        }
    }
}
