// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.Arrays;
import java.util.concurrent.atomic.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ReviewExitFixTest {
    private static void assertFailureRetained(LanControllerHarness h,LanGroup group,byte[] before)throws Exception {
        assertSame(group,LanControllerHarness.field(h.controller,"group"));
        assertTrue((Boolean)LanControllerHarness.field(h.controller,"releasePending"));
        assertFalse((Boolean)LanControllerHarness.field(h.controller,"ready"));
        assertTrue(Arrays.equals(before,group.identitySecret));assertNull(h.endpoint());
        h.main.drain();assertFalse(h.ui.last.ready);
    }
    private static void assertReleased(LanControllerHarness h,LanGroup group)throws Exception {
        h.work.repeated.run();assertNull(LanControllerHarness.field(h.controller,"group"));assertNull(h.endpoint());
        assertTrue(Arrays.equals(new byte[group.identitySecret.length],group.identitySecret));
    }
    @Test public void failureCallbackRetainsReservedMembershipAndCompletesFailureStatus()throws Exception {
        try(var h=new LanControllerHarness()){
            h.create();var group=(LanGroup)LanControllerHarness.field(h.controller,"group");byte[] before=group.identitySecret.clone();
            try(var reservation=PersistenceExitTest.reserve(group)){
                h.controller.runMain(()->{throw new IllegalStateException("Injected main failure");});
                try{h.work.drain();}catch(RuntimeException failure){fail("Failure callback escaped while reserved");}
                assertFailureRetained(h,group,before);
            }
            assertReleased(h,group);Crypto.wipe(before);
        }
    }
    @Test public void periodicFailureDoesNotEscapeAndCleanupContinuesOnNextPoll()throws Exception {
        var injected=new AtomicBoolean();
        try(var h=new LanControllerHarness(null,CotPort.NONE,()->{
            if(injected.getAndSet(false))throw new IllegalStateException("Injected poll failure");return System.nanoTime();
        })){
            h.create();var group=(LanGroup)LanControllerHarness.field(h.controller,"group");byte[] before=group.identitySecret.clone();
            try(var reservation=PersistenceExitTest.reserve(group)){
                injected.set(true);
                try{h.work.repeated.run();}catch(RuntimeException failure){fail("Periodic failure escaped while reserved");}
                assertFailureRetained(h,group,before);
            }
            assertReleased(h,group);Crypto.wipe(before);
        }
    }
    @Test public void pendingReleaseBlocksAllTransientFailureReconnects()throws Exception {
        for(var reason:new UdpEndpoint.CloseReason[]{UdpEndpoint.CloseReason.CLOCK_FAILURE,UdpEndpoint.CloseReason.RANDOM_FAILURE,UdpEndpoint.CloseReason.RECEIVE_FAILURE}){
            try(var h=new LanControllerHarness()){
                h.create();var group=(LanGroup)LanControllerHarness.field(h.controller,"group");int opened=h.link.opens;
                var originalEndpoint=h.endpoint();var closes=new AtomicInteger();h.link.afterIoClose=closes::incrementAndGet;
                try(var reservation=PersistenceExitTest.reserve(group)){
                    var epoch=(AtomicLong)LanControllerHarness.field(h.controller,"generation");
                    var closed=LanController.class.getDeclaredMethod("closed",long.class,UdpEndpoint.CloseReason.class);closed.setAccessible(true);
                    closed.invoke(h.controller,epoch.get(),reason);h.drain();
                    assertTrue((Boolean)LanControllerHarness.field(h.controller,"releasePending"));
                    h.offset.addAndGet(6_000_000_000L);h.work.repeated.run();
                    assertTrue("Pending release reopened a membership",h.endpoint()==null);assertEquals(opened,h.link.opens);
                }
                h.work.repeated.run();
                assertFalse((Boolean)LanControllerHarness.field(h.controller,"releasePending"));
                var replacement=(LanGroup)LanControllerHarness.field(h.controller,"group");
                assertNotNull(replacement);assertNotSame(group,replacement);assertNotNull(h.endpoint());assertNotSame(originalEndpoint,h.endpoint());
                assertEquals(opened+1,h.link.opens);assertEquals(1,closes.get());
                assertTrue(Arrays.equals(new byte[group.identitySecret.length],group.identitySecret));
                assertSame(replacement.state,LanControllerHarness.field(h.endpoint(),"admin"));
                h.work.repeated.run();assertEquals(opened+1,h.link.opens);assertEquals(1,closes.get());
            }
        }
    }
    @Test public void eraseRetainsReservedMemoryUntilNextPollWithoutEscaping()throws Exception {
        try(var h=new LanControllerHarness()){
            h.create();var group=(LanGroup)LanControllerHarness.field(h.controller,"group");byte[] before=group.identitySecret.clone();
            try(var reservation=PersistenceExitTest.reserve(group)){
                h.controller.erase();
                try{h.drain();}catch(RuntimeException failure){fail("Erase escaped while reserved");}
                assertTrue((Boolean)LanControllerHarness.field(h.controller,"releasePending"));
                assertSame(group,LanControllerHarness.field(h.controller,"group"));assertTrue(Arrays.equals(before,group.identitySecret));
                assertTrue(h.disk.erased);assertFalse((Boolean)LanControllerHarness.field(h.controller,"savedMember"));
            }
            assertReleased(h,group);Crypto.wipe(before);
        }
    }
}
