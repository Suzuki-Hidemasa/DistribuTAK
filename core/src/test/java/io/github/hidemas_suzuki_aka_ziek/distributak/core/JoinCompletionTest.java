// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class JoinCompletionTest {
    @Test void successReturnsRecordAndIgnoresLaterCompletions() throws Exception {
        var fixture=new JoinHandshakeTest();
        try(var invitation=fixture.invitation();var admin=fixture.admin(invitation);var joiner=fixture.joiner(invitation);
            var materials=fixture.material();var joined=joiner.receive(admin.respond(joiner.request(),fixture.adminX,fixture.f.a,materials))) {
            var future=new JoinPort.Completion<AdminRecords.Record>();
            assertFalse(future.isDone());assertThrows(TimeoutException.class,()->future.get(1,TimeUnit.MILLISECONDS));
            var certificate=joined.certificate();future.complete(certificate);future.fail(new SecurityException());future.complete(null);
            assertTrue(future.isDone());assertFalse(future.isCancelled());assertSame(certificate,future.get());
            assertFalse(future.cancel(false));
        }
    }
    @Test void failureKeepsCauseAndCannotBeChangedToSuccess() {
        var future=new JoinPort.Completion<AdminRecords.Record>();var cause=new SecurityException("test");
        future.fail(cause);future.complete(null);
        assertTrue(future.isDone());assertFalse(future.isCancelled());
        assertSame(cause,assertThrows(ExecutionException.class,future::get).getCause());
    }
    @Test void explicitAndCloseCancellationKeepFutureContract() {
        for(boolean byClose:new boolean[]{false,true}) {
            var future=new JoinPort.Completion<AdminRecords.Record>();
            if(byClose)future.fail(new CancellationException("test"));else assertTrue(future.cancel(true));
            future.complete(null);future.fail(new SecurityException());
            assertTrue(future.isDone());assertTrue(future.isCancelled());assertThrows(CancellationException.class,future::get);
        }
    }
}
