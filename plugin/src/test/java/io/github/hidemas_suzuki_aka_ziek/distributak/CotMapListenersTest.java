// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.*;
import java.util.function.Consumer;

public class CotMapListenersTest {
    record Entry(CotMapListeners.Route route,int kind,Consumer<String> callback) {}
    static final class Binding implements CotMapListeners.Bindings<String,Consumer<String>> {
        final List<Entry> installed=new ArrayList<>(),removed=new ArrayList<>();
        CotMapListeners.Route addFailure,removeFailure;int failureKind;
        public Consumer<String> create(Consumer<String> callback){return callback;}
        public void add(CotMapListeners.Route route,int kind,Consumer<String> callback){
            installed.add(new Entry(route,kind,callback));
            if(route==addFailure&&kind==failureKind)throw new IllegalStateException("private add detail");
        }
        public void remove(CotMapListeners.Route route,int kind,Consumer<String> callback){
            var entry=new Entry(route,kind,callback);removed.add(entry);
            if(route==removeFailure&&kind==failureKind)throw new IllegalStateException("private remove detail");
            installed.remove(entry);
        }
        void fire(CotMapListeners.Route route,int kind){
            for(var entry:List.copyOf(installed))if(entry.route()==route&&entry.kind()==kind)entry.callback().accept("private event");
        }
    }

    @Test public void typedAndBaseForwardAndStartDoesNotDuplicate(){
        var binding=new Binding();var listeners=new CotMapListeners<String,Consumer<String>>();var seen=new ArrayList<String>();
        listeners.start(binding,seen::add);listeners.start(binding,event->fail());assertEquals(10,binding.installed.size());
        binding.fire(CotMapListeners.Route.TYPED,0);binding.fire(CotMapListeners.Route.BASE,0);assertEquals(2,seen.size());
        listeners.stop();assertTrue(binding.installed.isEmpty());assertEquals(10,binding.removed.size());listeners.stop();assertEquals(10,binding.removed.size());
    }
    @Test public void everyInstalledRouteIsUsedForProductionAndBothHaveFiveKinds(){
        var binding=new Binding();var listeners=new CotMapListeners<String,Consumer<String>>();var seen=new ArrayList<String>();listeners.start(binding,seen::add);
        assertEquals(2,CotMapListeners.Route.values().length);
        for(var route:CotMapListeners.Route.values())for(int kind=0;kind<5;kind++)binding.fire(route,kind);
        assertEquals(10,seen.size());listeners.stop();assertTrue(binding.installed.isEmpty());
    }
    @Test public void addAndRemoveFailuresStillAttemptAllCleanupAndRetainOnlyFailedRegistration(){
        var binding=new Binding();binding.addFailure=CotMapListeners.Route.BASE;binding.failureKind=2;
        var listeners=new CotMapListeners<String,Consumer<String>>();listeners.start(binding,event->{});
        binding.removeFailure=CotMapListeners.Route.TYPED;listeners.stop();assertEquals(10,binding.removed.size());assertEquals(1,binding.installed.size());
        binding.removeFailure=null;listeners.stop();assertTrue(binding.installed.isEmpty());
    }
    @Test public void unremovedRegistrationIsNotDuplicatedOnRestart(){
        var binding=new Binding();var listeners=new CotMapListeners<String,Consumer<String>>();var seen=new ArrayList<String>();listeners.start(binding,seen::add);
        binding.removeFailure=CotMapListeners.Route.BASE;binding.failureKind=0;listeners.rebind();assertEquals(10,binding.installed.size());
        binding.removeFailure=null;listeners.stop();assertTrue(binding.installed.isEmpty());
    }
    @Test public void oldCallbacksCannotForwardIntoRestart(){
        var binding=new Binding();var listeners=new CotMapListeners<String,Consumer<String>>();var seen=new ArrayList<String>();
        listeners.start(binding,seen::add);var old=binding.installed.get(0).callback();listeners.stop();listeners.start(binding,seen::add);
        old.accept("old event");assertTrue(seen.isEmpty());binding.fire(CotMapListeners.Route.TYPED,0);assertEquals(1,seen.size());listeners.stop();
    }
    @Test public void rebindRemovesOnlyOwnListenersAndDiscardsQueuedOldGeneration(){
        var binding=new Binding();Consumer<String> other=e->{};var entry=new Entry(CotMapListeners.Route.TYPED,0,other);binding.installed.add(entry);
        var listeners=new CotMapListeners<String,Consumer<String>>();var queued=new ArrayList<Runnable>();var seen=new ArrayList<String>();
        listeners.start(binding,queued::add,seen::add);binding.fire(CotMapListeners.Route.TYPED,0);listeners.rebind();for(Runnable action:queued)action.run();assertTrue(seen.isEmpty());
        assertTrue(binding.installed.contains(entry));assertEquals(11,binding.installed.size());assertEquals(10,binding.removed.size());listeners.stop();assertEquals(1,binding.installed.size());
    }
}
