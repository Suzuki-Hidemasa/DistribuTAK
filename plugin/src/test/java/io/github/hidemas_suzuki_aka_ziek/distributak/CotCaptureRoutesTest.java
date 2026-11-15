// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.util.*;
import java.util.function.Consumer;
import org.junit.Test;
import static org.junit.Assert.*;
public class CotCaptureRoutesTest {
    @Test public void routedListenerPreservesGenerationAndForwardsTypedAndBase(){
        var binding=new CotMapListenersTest.Binding();var listeners=new CotMapListeners<String,Consumer<String>>();
        var queued=new ArrayList<Runnable>();var seen=new ArrayList<CotMapListeners.Route>();
        listeners.startRouted(binding,queued::add,(route,event)->seen.add(route));binding.fire(CotMapListeners.Route.TYPED,0);
        listeners.rebind();for(var action:queued)action.run();assertTrue(seen.isEmpty());queued.clear();
        binding.fire(CotMapListeners.Route.TYPED,0);binding.fire(CotMapListeners.Route.BASE,0);for(var action:queued)action.run();
        assertEquals(List.of(CotMapListeners.Route.TYPED,CotMapListeners.Route.BASE),seen);listeners.stop();
    }
}
