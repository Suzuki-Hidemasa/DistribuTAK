// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.List;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator.*;

class AdministratorPersistenceTest {
    final SessionManagerTest f=new SessionManagerTest();
    CorePersistenceCoordinator coordinator(SessionManagerTest.Node a){
        return new CorePersistenceCoordinator(a.state,a.sessions,new RevocationUnion(f.group,new AdminStateTrust(a.state)),f.time,new MonotonicClock(()->f.time.nanos));
    }
    AdminRecords.Record next(SessionManagerTest.Node a){
        var proof=AdminControl.keyProof(f.group,new byte[16],0,a.identity,f.admin);
        return AdminRecords.administrators(f.group,1,f.time.millis(),List.of(AdminBinding.bound(proof.administratorKey(),a.id,proof.encode())),f.admin);
    }
    boolean receive(CorePersistenceCoordinator c,AdminRecords.Record value,PersistenceHooks hooks)throws Exception{
        var method=CorePersistenceCoordinator.class.getMethod("receiveAdministrators",AdminRecords.Record.class,PersistenceHooks.class);
        return (boolean)method.invoke(c,value,hooks);
    }
    @Test void uncommittedFailureKeepsRunningAndReleasesReservation()throws Exception{
        try(var a=f.new Node(1)){
            var c=coordinator(a);var value=next(a);
            assertFalse(receive(c,value,s->{throw new IllegalStateException("injected failure");}));
            assertEquals(State.RUNNING,c.state());assertEquals(0,a.state.administrators().version());assertEquals("",c.statusText());
            assertFalse(a.sessions.isClosed());assertTrue(a.state.acceptAdministrators(value,v->fail()));
        }
    }
    @Test void committedGenerationChangeStopsWithoutCompensatingSave()throws Exception{
        try(var a=f.new Node(1)){
            var c=coordinator(a);int[] saves={0};
            assertFalse(receive(c,next(a),s->{saves[0]++;a.sessions.forgetAllVolatile();}));
            assertEquals(1,saves[0]);assertEquals(State.STORAGE_FAILED,c.state());assertEquals(StopReason.COMMITTED_NOT_APPLIED,c.stopReason());
            assertTrue(a.sessions.isClosed());assertEquals("",c.statusText());assertDoesNotThrow(a.state::clear);
        }
    }
    @Test void candidateIsSavedOutsideLocksBeforeOperationalPublication()throws Exception{
        try(var a=f.new Node(1)){
            var c=coordinator(a);var value=next(a);int[] saves={0};
            assertTrue(receive(c,value,s->{
                saves[0]++;assertFalse(Thread.holdsLock(a.sessions));assertFalse(Thread.holdsLock(a.state));
                assertEquals(State.PERSISTING,c.state());assertEquals(0,a.state.administrators().version());assertEquals(1,s.administratorVersion());
                assertThrows(IllegalStateException.class,()->a.state.acceptAdministrators(value,v->fail()));
            }));
            assertEquals(1,saves[0]);assertEquals(1,a.state.administrators().version());assertEquals(State.RUNNING,c.state());
            assertFalse(receive(c,value,s->fail()));assertEquals(0,a.state.revocations().version());
        }
    }
    @Test void futureClockAfterCommitStopsAndReleasesReservation()throws Exception{
        try(var a=f.new Node(1)){
            var c=coordinator(a);var value=next(a);
            assertFalse(receive(c,value,s->f.time.millis-=301000));
            assertEquals(StopReason.COMMITTED_NOT_APPLIED,c.stopReason());assertDoesNotThrow(a.state::clear);
        }
    }
}
