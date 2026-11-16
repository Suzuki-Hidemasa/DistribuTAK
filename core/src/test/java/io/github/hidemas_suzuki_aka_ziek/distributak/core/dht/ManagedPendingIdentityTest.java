// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.time.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecordTest.*;

class ManagedPendingIdentityTest {
    final Clock clock=Clock.fixed(Instant.ofEpochMilli(NOW),ZoneOffset.UTC);
    @Test void anonymousThirdEntryIsRefusedWithoutDisplacingOthers(){
        var pending=new ManagedPending(clock);
        assertTrue(pending.offer(revocationRecord(1,1,0,NOW,0),ManagedVerdict.NEEDS_ANNOUNCEMENT));
        assertTrue(pending.offer(revocationRecord(2,1,0,NOW,0),ManagedVerdict.NEEDS_ANNOUNCEMENT));
        assertFalse(pending.offer(revocationRecord(3,1,0,NOW,0),ManagedVerdict.NEEDS_ANNOUNCEMENT));assertEquals(2,pending.size());
    }
    @Test void eachAuthenticatedIdentityGetsTwoSlotsWithinGlobalEight(){
        var pending=new ManagedPending(clock);
        for(int member=0;member<4;member++){
            for(int i=1;i<=2;i++)assertTrue(pending.offer(revocationRecord(i,1,0,NOW,0),ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(member)));
            assertFalse(pending.offer(revocationRecord(3,1,0,NOW,0),ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(member)));
        }
        assertEquals(8,pending.size());assertFalse(pending.offer(revocationRecord(4,1,0,NOW,0),ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(9)));
    }
    @Test void unknownSignersRelayedByDifferentMembersShareAnonymousSlots(){
        var fixture=new ManagedVerifierTest();fixture.setUp();var verifier=fixture.verifierForPending();
        var pending=new ManagedPending(clock,verifier,member->true);
        for(int i=0;i<2;i++)assertTrue(pending.offer(fixture.latestRevocations(fixture.revocationList(i,NOW,4,0),4,0),ManagedVerdict.needsVersion(1),digest(i)));
        var stranger=fixture.latestRevocations(fixture.revocationList(3,NOW,4,0),4,0);
        assertFalse(pending.offer(stranger,ManagedVerdict.needsVersion(1),digest(3)));
    }
    @Test void losingTransportQualificationDiscardsRatherThanDemotesOnRetry(){
        var fixture=new ManagedVerifierTest();fixture.setUp();var verifier=fixture.verifierForPending();
        var active=new AtomicBoolean(true);var pending=new ManagedPending(clock,verifier,member->active.get());
        var record=fixture.latestRevocations(fixture.revocationList(1,NOW,1,0),1,0);
        assertTrue(pending.offer(record,ManagedVerdict.needsVersion(1),digest(8)));
        active.set(false);var results=pending.retry(verifier,key->null,checked->fail());
        assertEquals(1,results.size());assertEquals(ManagedVerdict.Status.INVALID,results.get(0).verdict().status());assertEquals(0,pending.size());assertEquals(0,pending.bytes());
    }
    @Test void losingEitherSignerQualificationDiscardsPendingEntry(){
        for(boolean outer:new boolean[]{false,true}){
            var fixture=new ManagedVerifierTest();fixture.setUp();var verifier=fixture.verifierForPending();
            var pending=new ManagedPending(clock,verifier,member->true);
            var record=fixture.latestRevocations(fixture.revocationList(1,NOW,outer?2:1,0),outer?1:2,0);
            assertTrue(pending.offer(record,ManagedVerdict.needsVersion(1),digest(8)));
            fixture.advance(1,2,2);
            var results=pending.retry(verifier,key->null,checked->fail());
            assertEquals(1,results.size());assertEquals(ManagedVerdict.Status.INVALID,results.get(0).verdict().status());assertEquals(0,pending.size());
        }
    }

    @Test void unknownOuterDoesNotHideLossOfPreviouslyQualifiedInnerSigner(){
        var fixture=new ManagedVerifierTest();fixture.setUp();var verifier=fixture.verifierForPending();
        var pending=new ManagedPending(clock,verifier,member->true);
        var record=ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,GROUP,secret(4),fixture.revocationList(1,NOW,1,0),1,5,digest(9),NOW,null);
        assertTrue(pending.offer(record,ManagedVerdict.needsVersion(1),digest(8)));fixture.advance(1,2,2);
        var results=pending.retry(verifier,key->null,checked->fail());
        assertEquals(1,results.size());assertEquals(ManagedVerdict.Status.INVALID,results.get(0).verdict().status());
    }
    @Test void qualificationLearnedDuringRetryCannotLaterBeLostWhileStillWaitingForVersion(){
        var fixture=new ManagedVerifierTest();fixture.setUp();var verifier=fixture.verifierForPending();
        var pending=new ManagedPending(clock,verifier,member->true);
        var record=ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,GROUP,secret(4),fixture.revocationList(1,NOW,4,0),1,5,digest(9),NOW,null);
        assertTrue(pending.offer(record,ManagedVerdict.needsVersion(1),digest(8)));fixture.advance(1,2,2,4);
        assertTrue(pending.retry(verifier,key->null,checked->fail()).isEmpty());fixture.advance(2,2,2);
        var results=pending.retry(verifier,key->null,checked->fail());
        assertEquals(1,results.size());assertEquals(ManagedVerdict.Status.INVALID,results.get(0).verdict().status());
    }

}
