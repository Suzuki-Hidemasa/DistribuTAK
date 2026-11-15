// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class SessionOriginTest {
    final SessionManagerTest fixture=new SessionManagerTest();
    @Test void originQueryIsBoundToExactEstablishedSession() {
        try(var a=fixture.new Node(1);var b=fixture.new Node(2)) {
            fixture.connect(a,b);byte[] session=a.sessions.sessionId(b.id);
            assertFalse(a.sessions.isPeerInitiatedSession(b.id,session));assertTrue(b.sessions.isPeerInitiatedSession(a.id,session));
            byte[] other=session.clone();other[0]^=1;
            assertFalse(b.sessions.isPeerInitiatedSession(a.id,other));assertFalse(b.sessions.isPeerInitiatedSession(new byte[32],session));
        }
    }
    @Test void newFirstChangesOriginOnlyAfterConfirmation() {
        try(var a=fixture.new Node(1);var b=fixture.new Node(2)) {
            fixture.connect(a,b);byte[] old=a.sessions.sessionId(b.id);fixture.time.advance(5);
            var second=a.sessions.receive(b.sessions.start(a.id).packet());
            assertFalse(a.sessions.isPeerInitiatedSession(b.id,old));
            var confirm=b.sessions.receive(second.outbound().get(0).packet());a.sessions.receive(confirm.outbound().get(0).packet());
            byte[] current=a.sessions.sessionId(b.id);assertTrue(a.sessions.isPeerInitiatedSession(b.id,current));
            assertFalse(b.sessions.isPeerInitiatedSession(a.id,current));assertFalse(a.sessions.isPeerInitiatedSession(b.id,old));
        }
    }
}
