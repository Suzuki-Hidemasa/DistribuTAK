// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator.*;

class RosterPersistenceTest {
    final CorePersistenceCoordinatorTest f=new CorePersistenceCoordinatorTest();
    @Test void saveRunsOutsideLockAndPublishesBeforeCompletionAck(){
        try(var a=f.f.new Node(1);var b=f.f.new Node(2)){
            f.f.connect(a,b);var c=f.coordinator(a);var calls=new ArrayList<String>();
            var page=ManagementPage.split(ManagementPage.Kind.ROSTER,new byte[16],f.f.group,new byte[]{1},1).get(0);
            var result=c.receiveRosterPage(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),page,0,
                (data,count)->new RosterUpdate(()->{
                    assertFalse(Thread.holdsLock(a.sessions));assertEquals(State.PERSISTING,c.state());
                    assertFalse(c.permits(Operation.ROSTER));assertTrue(calls.isEmpty());calls.add("saved");
                },()->true,()->{assertEquals(List.of("saved"),calls);calls.add("published");}),()->fail());
            assertNotNull(result.ack());assertTrue(result.ack().complete());assertEquals(List.of("saved","published"),calls);
            assertEquals(State.RUNNING,c.state());assertEquals(0,a.state.revocations().version());
        }
    }
    @Test void failureStopsAllTrafficWithoutPublicationOrAck(){
        try(var a=f.f.new Node(1);var b=f.f.new Node(2)){
            f.f.connect(a,b);var c=f.coordinator(a);int[] stopped={0};
            var page=ManagementPage.split(ManagementPage.Kind.ROSTER,new byte[16],f.f.group,new byte[]{1},1).get(0);
            var result=c.receiveRosterPage(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),page,0,
                (data,count)->new RosterUpdate(()->{throw new IllegalStateException("injected save failure");},()->true,()->fail()),()->stopped[0]++);
            assertNull(result.ack());assertEquals(State.STORAGE_FAILED,c.state());assertEquals("保存がいっぱい",c.statusText());
            assertTrue(a.sessions.isClosed());assertEquals(1,stopped[0]);
        }
    }
    @Test void sessionLostDuringSaveNeverPublishesOrAcknowledges(){
        try(var a=f.f.new Node(1);var b=f.f.new Node(2)){
            f.f.connect(a,b);var c=f.coordinator(a);
            var page=ManagementPage.split(ManagementPage.Kind.ROSTER,new byte[16],f.f.group,new byte[]{1},1).get(0);
            var result=c.receiveRosterPage(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),page,0,
                (data,count)->new RosterUpdate(a.sessions::forgetAllVolatile,()->true,()->fail()),()->{});
            assertNull(result.ack());assertEquals(State.RUNNING,c.state());
        }
    }
    @Test void authorityLostDuringSaveNeverPublishesOrAcknowledges(){
        try(var a=f.f.new Node(1);var b=f.f.new Node(2)){
            f.f.connect(a,b);var c=f.coordinator(a);boolean[] valid={true};
            var page=ManagementPage.split(ManagementPage.Kind.ROSTER,new byte[16],f.f.group,new byte[]{1},1).get(0);
            var result=c.receiveRosterPage(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),page,0,
                (data,count)->new RosterUpdate(()->valid[0]=false,()->valid[0],()->fail()),()->{});
            assertNull(result.ack());assertEquals(State.RUNNING,c.state());
        }
    }
    @Test void failedPublicationNeverLeavesReusableCompletionAck(){
        try(var a=f.f.new Node(1);var b=f.f.new Node(2)){
            f.f.connect(a,b);var c=f.coordinator(a);byte[] session=a.sessions.sessionId(b.id);long generation=a.sessions.generation();
            var page=ManagementPage.split(ManagementPage.Kind.ROSTER,new byte[16],f.f.group,new byte[]{1},1).get(0);
            var result=c.receiveRosterPage(b.id,session,generation,page,0,
                (data,count)->new RosterUpdate(()->{},()->true,()->{throw new IllegalStateException("injected publication failure");}),()->{});
            assertNull(result.ack());
            var retry=c.receiveRosterPage(b.id,session,generation,page,0,(data,count)->{fail();return null;},()->{});
            assertNull(retry.ack());
        }
    }
    @Test void deadlinePassingDuringSaveNeverPublishesOrAcknowledges(){
        try(var a=f.f.new Node(1);var b=f.f.new Node(2)){
            f.f.connect(a,b);var c=f.coordinator(a);
            var page=ManagementPage.split(ManagementPage.Kind.ROSTER,new byte[16],f.f.group,new byte[]{1},1).get(0);
            var result=c.receiveRosterPage(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),page,0,
                (data,count)->new RosterUpdate(()->f.f.time.advance(240),()->true,()->fail()),()->{});
            assertNull(result.ack());
        }
    }

}
