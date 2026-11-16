// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminProofFixtures;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminState;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.InMemoryAdminRecordStore;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecordTest.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 失効の和 R（04 §4.5）。到着順・一覧の勝者・署名者の削除によらず、受理した失効を残す。
 * <p>
 * The revocation union R (04 §4.5). Accepted revocations stay regardless of arrival order, list winner or signer removal.
 */
class RevocationUnionTest {
    private final Clock clock=Clock.fixed(Instant.ofEpochMilli(NOW),ZoneOffset.UTC);
    private AdminState state;
    private RevocationUnion union;

    @BeforeEach void setUp() {
        state=new AdminState(GROUP,pub(1),clock,new InMemoryAdminRecordStore());
        var first=list(0,NOW-2000,1,1,2);
        state.bootstrap(first,AdminRecords.signAnchor(first,secret(1)));
        union=new RevocationUnion(GROUP,new AdminStateTrust(state));
    }

    // ---- 補助 / helpers ----
    AdminRecords.Record list(long version,long signedAt,int signer,int... who) {
        var keys=new ArrayList<byte[]>();for(int n:who)keys.add(pub(n));
        return AdminProofFixtures.list(GROUP,version,signedAt,keys,secret(signer),secret(1),secret(2),secret(3),secret(4));
    }
    /** 対象の番号 ids の失効の一覧。 / A revocation list of the subject numbers ids. */
    AdminRecords.Record revocations(long version,int signer,int... ids) {
        var subjects=new ArrayList<byte[]>();for(int n:ids)subjects.add(digest(n));
        return AdminRecords.list(AdminRecords.Kind.REVOCATIONS,GROUP,version,NOW,subjects,secret(signer));
    }

    // ---- 足す / adding ----
    @Test void aValidListAddsItsSubjects() {
        assertTrue(union.add(revocations(1,1,10,11)));
        assertTrue(union.contains(digest(10)));
        assertTrue(union.contains(digest(11)));
        assertFalse(union.contains(digest(12)));
        assertEquals(2,union.size());
    }
    @Test void addingTheSameListAgainChangesNothing() {
        var one=revocations(1,1,10);
        assertTrue(union.add(one));
        assertFalse(union.add(one));
        assertEquals(1,union.size());
    }
    @Test void aListThatAddsNothingNewReportsNoChange() {
        assertTrue(union.add(revocations(1,1,10,11)));
        assertFalse(union.add(revocations(2,2,10)));
        assertEquals(2,union.size());
    }

    // ---- 勝者によらず残る / kept regardless of the winner ----
    @Test void bothSidesOfTwoCompetingListsStayInTheUnion() {
        var x=revocations(3,1,10);
        var y=revocations(3,2,11);
        assertTrue(union.add(x));
        assertTrue(union.add(y));
        assertTrue(union.contains(digest(10)));
        assertTrue(union.contains(digest(11)));
    }
    @Test void theUnionDoesNotDependOnArrivalOrder() {
        var other=new RevocationUnion(GROUP,new AdminStateTrust(state));
        var x=revocations(3,1,10);
        var y=revocations(3,2,11,12);
        union.add(x);union.add(y);
        other.add(y);other.add(x);
        assertEquals(union.size(),other.size());
        for(int n:new int[]{10,11,12})assertEquals(union.contains(digest(n)),other.contains(digest(n)));
    }
    @Test void aLowerVersionListStillCountsAfterAHigherOneArrived() {
        assertTrue(union.add(revocations(5,1,10)));
        assertTrue(union.add(revocations(2,2,11)));
        assertTrue(union.contains(digest(11)));
    }

    // ---- 署名者の削除 / signer removal ----
    @Test void anAcceptedListStaysAfterItsSignerIsRemoved() {
        assertTrue(union.add(revocations(1,2,10)));
        assertTrue(state.acceptAdministrators(list(1,NOW-1000,1,1),v->fail()));
        assertTrue(union.contains(digest(10)));
    }
    @Test void aNewListFromARemovedSignerIsNotUsed() {
        assertTrue(state.acceptAdministrators(list(1,NOW-1000,1,1),v->fail()));
        assertThrows(SecurityException.class,()->union.add(revocations(1,2,10)));
        assertFalse(union.contains(digest(10)));
    }

    // ---- 断る / refusals ----
    @Test void aListSignedByANonAdministratorIsRefused() {
        assertThrows(SecurityException.class,()->union.add(revocations(1,3,10)));
        assertEquals(0,union.size());
    }
    @Test void aListForAnotherGroupIsRefused() {
        var other=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,digest(99),1,NOW,List.of(digest(10)),secret(1));
        assertThrows(SecurityException.class,()->union.add(other));
        assertEquals(0,union.size());
    }
    @Test void anAdministratorListIsNotARevocationList() {
        assertThrows(SecurityException.class,()->union.add(list(1,NOW,1,1,2)));
    }
    @Test void aListThatWouldPassTheLimitIsRefusedAndNothingIsDropped() {
        var big=new ArrayList<byte[]>();
        for(int i=0;i<AdminRecords.MAX_ENTRIES;i++)big.add(counted(i));
        assertTrue(union.add(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,GROUP,1,NOW,big,secret(1))));
        assertThrows(AdminRecords.RevocationLimitException.class,()->union.add(revocations(2,1,10)));
        assertEquals(AdminRecords.MAX_ENTRIES,union.size());
        assertFalse(union.contains(digest(10)));
    }
    private static byte[] counted(int i) {
        var bytes=new byte[32];
        bytes[0]=(byte)(i>>>24);bytes[1]=(byte)(i>>>16);bytes[2]=(byte)(i>>>8);bytes[3]=(byte)i;bytes[31]=(byte)0xEE;
        return bytes;
    }

    // ---- 包含 / coverage ----
    @Test void coversTellsWhetherAListHoldsEveryRevocationInTheUnion() {
        union.add(revocations(1,1,10));
        union.add(revocations(1,2,11));
        assertTrue(union.covers(revocations(2,1,10,11,12)));
        assertTrue(union.covers(revocations(2,1,10,11)));
        assertFalse(union.covers(revocations(2,1,10)));
        assertFalse(union.covers(revocations(2,1,11,12)));
    }
    @Test void anEmptyUnionIsCoveredByAnyList() {
        assertTrue(union.covers(revocations(1,1,10)));
    }

    // ---- 手元の最新だけの失効との分離 / separate from the latest-only list ----
    @Test void theUnionIsSeparateFromTheStatesLatestOnlyRevocations() {
        var winner=revocations(2,1,10);
        assertTrue(state.acceptRevocations(winner));
        union.add(winner);
        union.add(revocations(1,2,11));
        assertFalse(state.revocations().hasEntry(digest(11)));
        assertTrue(union.contains(digest(11)));
    }
}
