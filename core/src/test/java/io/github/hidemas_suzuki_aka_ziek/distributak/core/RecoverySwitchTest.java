// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RecoverySwitchTest {
    @Test void abandoningPeerAllowsAnotherOperationWithoutExtendingTotalDeadline(){
        var t=new RevocationsRecoveryTest();var f=t.f;
        try(var a=f.new Node(1);var b=f.new Node(2);var d=f.new Node(3)){
            var c=t.recovering(a,t.requirement());t.bind(c,a,b);f.connect(a,d);f.time.advance(30);
            c.abandonRecovery();byte[] op=new byte[16];op[0]=1;
            assertTrue(c.bindRecovery(d.id,a.sessions.sessionId(d.id),a.sessions.generation(),
                    new RevocationsRecoveryRequest(f.group,op,1,t.request().targetDigest())));
            assertEquals(ManagementPageAssembler.Status.REJECTED,t.deliver(c,a,b,t.t.revoked(t.target),t.t.hooks(()->fail())).status());
            f.time.advance(210);assertFalse(c.permits(CorePersistenceCoordinator.Operation.HANDSHAKE));
        }
    }
    @Test void candidateLessRequirementUsesVerifiedSavedSetWithoutTreatingZeroAsDigest(){
        var t=new RevocationsRecoveryTest();
        var requirement=CorePersistenceCoordinator.RecoveryRequirement.candidateLess(1,List.of(t.target));
        assertTrue(requirement.covers(t.t.revoked(t.target)));assertFalse(requirement.covers(t.t.revoked()));
        assertArrayEquals(new byte[32],requirement.digest());
    }
}
