// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.lang.reflect.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class PersistenceControllerTest {
    interface Action {void run()throws Exception;}
    static void saving(LanController controller,Action action)throws Exception{
        Class<?> api=Class.forName(LanController.class.getName()+"$SavedAction");
        Object proxy=Proxy.newProxyInstance(api.getClassLoader(),new Class<?>[]{api},(p,m,args)->{action.run();return null;});
        var method=LanController.class.getDeclaredMethod("saving",api);method.setAccessible(true);method.invoke(controller,proxy);
    }
    @Test public void controllerKeepsEndpointAndSessionsWhileStorageRuns()throws Exception{
        try(var harness=new LanControllerHarness()){
            harness.create();var endpoint=harness.endpoint();var sessions=LanControllerHarness.field(endpoint,"sessions");
            var coordinator=(CorePersistenceCoordinator)LanControllerHarness.field(harness.controller,"persistence");
            assertNotNull(coordinator);
            saving(harness.controller,()->{
                assertEquals(CorePersistenceCoordinator.State.PERSISTING,coordinator.state());
                assertSame(endpoint,harness.endpoint());assertFalse(Thread.holdsLock(endpoint));assertFalse(Thread.holdsLock(sessions));
                assertFalse(coordinator.permits(CorePersistenceCoordinator.Operation.COT_SEND));
            });
            assertEquals(CorePersistenceCoordinator.State.RUNNING,coordinator.state());assertSame(endpoint,harness.endpoint());
            assertSame(sessions,LanControllerHarness.field(endpoint,"sessions"));
        }
    }
}
