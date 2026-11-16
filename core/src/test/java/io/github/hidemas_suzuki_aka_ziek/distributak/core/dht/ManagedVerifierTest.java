// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminProofFixtures;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminState;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.InMemoryAdminRecordStore;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecordTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedVerdict.Status.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 管理用 DHT 記録の権限・版・競合の判定（04 §4.5）。本物の {@link AdminState} を信頼済みの鎖として使う。
 * <p>
 * The authority, version and conflict verdicts for managed DHT records (04 §4.5), using a real {@link AdminState}
 * as the trusted chain.
 */
class ManagedVerifierTest {
    static final long DAY=DhtLimits.RECORD_LIFETIME_MILLIS,FUTURE=300_000;
    private final Clock clock=Clock.fixed(Instant.ofEpochMilli(NOW),ZoneOffset.UTC);
    private AdminState state;
    private ManagedVerifier verifier;

    @BeforeEach void setUp() {
        state=new AdminState(GROUP,pub(1),clock,new InMemoryAdminRecordStore());
        var first=list(0,NOW-2000,1,1,2);
        state.bootstrap(first,AdminRecords.signAnchor(first,secret(1)));
        verifier=new ManagedVerifier(new AdminStateTrust(state),clock);
    }

    // ---- 補助 / helpers ----
    /** 管理者の一覧（所持証明つき）。signer は署名する管理者の番号。 / An administrator list with proofs; signer is the signing administrator's number. */
    AdminRecords.Record list(long version,long signedAt,int signer,int... who) {
        var keys=new ArrayList<byte[]>();for(int n:who)keys.add(pub(n));
        return AdminProofFixtures.list(GROUP,version,signedAt,keys,secret(signer),secret(1),secret(2),secret(3),secret(4));
    }
    AdminRecords.Record revocationList(long version,long signedAt,int signer,int count) {
        return AdminRecords.list(AdminRecords.Kind.REVOCATIONS,GROUP,version,signedAt,members(count),secret(signer));
    }
    byte[] digestAt(long version){return Crypto.blake2s(state.administratorsAt(version).signedBytes());}
    /** 外側が信頼済みの版 adminVersion を名指しする記録。 / A record whose outer layer names the trusted version adminVersion. */
    ManagedDhtRecord record(int kind,AdminRecords.Record inner,int outerSigner,long seq,long adminVersion,long signedAt) {
        return ManagedDhtRecord.issue(kind,GROUP,secret(outerSigner),inner,seq,adminVersion,digestAt(adminVersion),signedAt,null);
    }
    ManagedDhtRecord latestAdmins(AdminRecords.Record inner,int outerSigner,long adminVersion) {
        return record(DhtKeys.LATEST_ADMINS,inner,outerSigner,1,adminVersion,inner.signedAt());
    }
    ManagedDhtRecord latestRevocations(AdminRecords.Record inner,int outerSigner,long adminVersion) {
        return record(DhtKeys.LATEST_REVOCATIONS,inner,outerSigner,1,adminVersion,NOW);
    }
    ManagedDhtRecord history(AdminRecords.Record inner,int outerSigner,long adminVersion) {
        return record(DhtKeys.ADMIN_HISTORY,inner,outerSigner,0,adminVersion,NOW);
    }
    /** 手元の信頼済みの鎖を、署名者 signer で版 version の一覧まで進める。 / Advances the trusted chain to the given list. */
    void advance(long version,int signer,int... who) {
        assertTrue(state.acceptAdministrators(list(version,NOW-1000,signer,who),v->fail()));
    }
    ManagedVerdict judge(ManagedDhtRecord candidate,ManagedDhtRecord held){return verifier.judge(candidate,held);}
    void expect(ManagedVerdict.Status status,ManagedVerdict verdict){assertEquals(status,verdict.status());}

    // ---- 管理者の一覧（種類 2） / administrator list (kind 2) ----
    @Test void nextListChainedFromTheTrustedLatestIsAccepted() {
        expect(ACCEPTED,judge(latestAdmins(list(1,NOW,1,1,2,3),1,0),null));
    }
    @Test void aListWhoseSignerIsNotInThePreviousVersionIsRefused() {
        expect(INVALID,judge(latestAdmins(list(1,NOW,3,1,2,3),1,0),null));
    }
    @Test void anOuterDigestThatDoesNotMatchTheNamedListIsRefused() {
        var inner=list(1,NOW,1,1,2,3);
        var wrongDigest=ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,GROUP,secret(1),inner,1,0,digest(9),NOW,null);
        expect(INVALID,judge(wrongDigest,null));
    }
    @Test void anOuterSignerWhoIsNotAnAdministratorIsRefused() {
        expect(INVALID,judge(latestAdmins(list(1,NOW,1,1,2,3),4,0),null));
    }
    @Test void anOuterThatNamesAFutureAdministratorVersionNeedsThatVersion() {
        var inner=list(1,NOW,1,1,2,3);
        var future=ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,GROUP,secret(1),inner,1,5,digest(9),NOW,null);
        var verdict=judge(future,null);
        expect(NEEDS_VERSION,verdict);assertEquals(1,verdict.neededVersion());
    }
    @Test void aListTwoVersionsAheadNeedsTheMissingVersion() {
        var verdict=judge(latestAdmins(list(2,NOW,1,1,2,3),1,0),null);
        expect(NEEDS_VERSION,verdict);assertEquals(1,verdict.neededVersion());
    }
    @Test void anOuterThatDoesNotNameThePreviousVersionIsRefused() {
        advance(1,1,1,2,3);
        // 版 2 は外側が版 1 を名指さなければならない。版 0 を名指すものは受けない。
        // Version 2 must be named against version 1; a record naming version 0 is refused.
        expect(INVALID,judge(latestAdmins(list(2,NOW,1,1,2,3),1,0),null));
        expect(ACCEPTED,judge(latestAdmins(list(2,NOW,1,1,2,3),1,1),null));
    }
    @Test void anOlderListThanTheTrustedLatestIsOld() {
        advance(1,1,1,2,3);
        expect(OLD,judge(latestAdmins(list(0,NOW-2000,1,1,2),1,1),null));
    }
    @Test void aSameVersionCompetitorMustOutrankTheTrustedListAndChainFromThePreviousVersion() {
        advance(1,1,1,2,3);
        // 版 1 の別の中身。信頼済みの版 1（NOW-1000）より新しければ受ける。
        // A different version-1 payload is accepted only if it outranks the trusted version 1 (NOW-1000).
        expect(ACCEPTED,judge(latestAdmins(list(1,NOW,2,1,2),2,0),null));
        expect(OLD,judge(latestAdmins(list(1,NOW-2000,2,1,2),2,0),null));
        // 前の版に鎖でつながらない署名者は受けない（3 は版 0 の管理者ではない）。
        // A signer outside the previous version does not chain (3 is not an administrator of version 0).
        expect(INVALID,judge(latestAdmins(list(1,NOW,3,1,2,3),2,0),null));
        // 外側が前の版（0）を名指さないものは受けない。
        // An outer layer that does not name the previous version (0) is refused.
        expect(INVALID,judge(latestAdmins(list(1,NOW,2,1,2),2,1),null));
    }
    @Test void theTrustedListItselfRepublishedByAnotherAdministratorIsAcceptedOnce() {
        advance(1,1,1,2,3);
        var trusted=state.administratorsAt(1);
        var held=latestAdmins(trusted,1,1);
        expect(DUPLICATE,judge(held,held));
        expect(ACCEPTED,judge(latestAdmins(trusted,2,1),null));
    }
    @Test void anExpiredOrTooFarFutureOuterIsRefusedAtTheBoundary() {
        var inner=list(1,NOW,1,1,2,3);
        // 期限ちょうど（signedAt+24 時間 = 今）は期限切れ。1 ミリ秒前は有効。
        // Exactly at expiry (signedAt + 24 h = now) is expired; one millisecond earlier is valid.
        expect(INVALID,judge(record(DhtKeys.LATEST_ADMINS,inner,1,1,0,NOW-DAY),null));
        expect(ACCEPTED,judge(record(DhtKeys.LATEST_ADMINS,inner,1,1,0,NOW-DAY+1),null));
        // 5 分ちょうどの先の時刻は有効、1 ミリ秒先は拒否。
        // Exactly five minutes ahead is valid; one millisecond more is refused.
        expect(ACCEPTED,judge(record(DhtKeys.LATEST_ADMINS,inner,1,1,0,NOW+FUTURE),null));
        expect(INVALID,judge(record(DhtKeys.LATEST_ADMINS,inner,1,1,0,NOW+FUTURE+1),null));
    }

    // ---- 失効の一覧（種類 3） / revocation list (kind 3) ----
    @Test void aRevocationListSignedByAnAdministratorIsAccepted() {
        expect(ACCEPTED,judge(latestRevocations(revocationList(1,NOW,1,2),2,0),null));
    }
    @Test void aRevocationListSignedByANonAdministratorIsRefused() {
        expect(INVALID,judge(latestRevocations(revocationList(1,NOW,4,2),1,0),null));
    }
    @Test void aRevocationInnerSignedTooFarInTheFutureIsRefused() {
        expect(ACCEPTED,judge(latestRevocations(revocationList(1,NOW+FUTURE,1,2),1,0),null));
        expect(INVALID,judge(latestRevocations(revocationList(1,NOW+FUTURE+1,1,2),1,0),null));
    }
    @Test void aHigherRevocationListReplacesAndALowerOneIsOld() {
        var held=latestRevocations(revocationList(3,NOW,1,2),1,0);
        expect(ACCEPTED,judge(latestRevocations(revocationList(4,NOW,1,2),1,0),held));
        expect(OLD,judge(latestRevocations(revocationList(2,NOW,1,2),1,0),held));
        expect(OLD,judge(latestRevocations(revocationList(3,NOW-1,1,2),1,0),held));
    }
    @Test void theSameRevocationListWithADifferentOuterIsKeptByOuterTimeThenSequence() {
        var inner=revocationList(3,NOW,1,2);
        var held=record(DhtKeys.LATEST_REVOCATIONS,inner,1,5,0,NOW-1000);
        expect(DUPLICATE,judge(held,held));
        // 外側の時刻が新しければ、順位は内側のままで外側を取り替える。
        // A later outer time replaces the outer layer while the inner rank is unchanged.
        expect(ACCEPTED,judge(record(DhtKeys.LATEST_REVOCATIONS,inner,2,1,0,NOW-999),held));
        // 時刻が同じなら番号の大きい方。同じ番号・時刻なら取り替えない。
        // With equal time the higher sequence wins; equal time and sequence do not replace.
        expect(ACCEPTED,judge(record(DhtKeys.LATEST_REVOCATIONS,inner,2,6,0,NOW-1000),held));
        expect(DUPLICATE,judge(record(DhtKeys.LATEST_REVOCATIONS,inner,2,5,0,NOW-1000),held));
        expect(DUPLICATE,judge(record(DhtKeys.LATEST_REVOCATIONS,inner,2,9,0,NOW-2000),held));
    }
    @Test void anOuterSequenceOrTimeNeverOverturnsTheInnerRank() {
        var held=record(DhtKeys.LATEST_REVOCATIONS,revocationList(3,NOW,1,2),1,1,0,NOW-1000);
        var lowerInnerButNewerOuter=record(DhtKeys.LATEST_REVOCATIONS,revocationList(2,NOW,1,2),1,99,0,NOW);
        expect(OLD,judge(lowerInnerButNewerOuter,held));
    }
    @Test void aRevocationListFromARemovedSignerIsKeptButNeverOverturnedByAnEqualOrLowerVersion() {
        var held=latestRevocations(revocationList(3,NOW-5000,2,2),2,0);
        advance(1,1,1,3);
        // 2 は外された。版が同じか低い R は、時刻が新しくても受けない。
        // 2 was removed. An R with an equal or lower version is not accepted even with a newer time.
        expect(OLD,judge(latestRevocations(revocationList(3,NOW,1,2),1,1),held));
        expect(OLD,judge(latestRevocations(revocationList(2,NOW,1,2),1,1),held));
        expect(ACCEPTED,judge(latestRevocations(revocationList(4,NOW,1,2),1,1),held));
        // 外された署名者の新しい失効の一覧・外された署名者の外側は受けない。
        // A new list from the removed signer, or an outer signed by the removed signer, is refused.
        expect(INVALID,judge(latestRevocations(revocationList(5,NOW,2,2),1,1),held));
        expect(INVALID,judge(latestRevocations(revocationList(5,NOW,1,2),2,1),held));
    }

    // ---- 管理者の履歴（種類 5） / administrator history (kind 5) ----
    @Test void historyOfATrustedVersionIsAcceptedOnlyWhenThePayloadIsIdentical() {
        advance(1,1,1,2,3);
        expect(ACCEPTED,judge(history(state.administratorsAt(0),1,1),null));
        expect(ACCEPTED,judge(history(state.administratorsAt(1),1,1),null));
        // 版 0 の別の中身は、信頼済みの版 0 と違うので受けない。
        // A different payload for version 0 differs from the trusted version 0 and is refused.
        expect(INVALID,judge(history(list(0,NOW-1,1,1,2),1,1),null));
    }
    @Test void historyForTheNextVersionFollowsTheChainRule() {
        advance(1,1,1,2,3);
        expect(ACCEPTED,judge(history(list(2,NOW,3,1,2,3),1,1),null));
        expect(INVALID,judge(history(list(2,NOW,4,1,2,3,4),1,1),null));
        var verdict=judge(history(list(3,NOW,1,1,2,3),1,1),null);
        expect(NEEDS_VERSION,verdict);assertEquals(2,verdict.neededVersion());
    }
    @Test void historyRecordsAreRankedByTheirInnerRecordLikeAnyOther() {
        advance(1,1,1,2,3);
        var held=history(state.administratorsAt(1),1,1);
        expect(DUPLICATE,judge(held,held));
        expect(ACCEPTED,judge(history(state.administratorsAt(1),2,1),null));
    }

    // ---- 自己削除（種類 2・5） / self-removal (kinds 2 and 5) ----
    @Test void selfRemovalIsAcceptedForLatestAndHistoryWithoutChangingTrust() {
        var inner=list(1,NOW,1,2);
        expect(ACCEPTED,judge(latestAdmins(inner,1,0),null));
        expect(ACCEPTED,judge(history(inner,1,0),null));
        assertEquals(0,state.administrators().version());
    }
    @Test void selfRemovalRequiresTheSameInnerAndOuterSigner() {
        expect(INVALID,judge(latestAdmins(list(1,NOW,1,2),2,0),null));
    }
    @Test void selfRemovalRequiresTheExactPreviousDigest() {
        var candidate=ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,GROUP,secret(1),list(1,NOW,1,2),1,0,digest(99),NOW,null);
        expect(INVALID,judge(candidate,null));
    }
    @Test void selfRemovalRequiresASignerInThePreviousList() {
        expect(INVALID,judge(latestAdmins(list(1,NOW,3,2),3,0),null));
    }
    @Test void selfRemovalCannotRemoveTheLastAdministrator() {
        assertThrows(IllegalArgumentException.class,()->list(1,NOW,1));
    }
    @Test void selfRemovalStoreRequiresTheAuthenticatedBoundMember() {
        var candidate=latestAdmins(list(1,NOW,1,2),1,0);
        var member=state.administrators().binding(pub(1)).memberId();
        expect(ACCEPTED,verifier.judgeStore(candidate,null,member));
        expect(INVALID,verifier.judgeStore(candidate,null,digest(99)));
        expect(INVALID,verifier.judgeStore(candidate,null,null));
        expect(INVALID,verifier.judgeStore(candidate,null,new byte[31]));
    }
    @Test void storeCannotUseAnUnknownAdministratorBinding() {
        var first=AdminRecords.list(AdminRecords.Kind.ADMINS,GROUP,0,NOW-2000,java.util.List.of(pub(1),pub(2)),secret(1));
        state=new AdminState(GROUP,pub(1),clock,new InMemoryAdminRecordStore());
        state.bootstrap(first,AdminRecords.signAnchor(first,secret(1)));
        verifier=new ManagedVerifier(new AdminStateTrust(state),clock);
        expect(INVALID,verifier.judgeStore(latestAdmins(list(1,NOW,1,2),1,0),null,digest(99)));
    }
    @Test void anAcceptedSelfRemovalIsIdempotentAfterTheSignerIsRemoved() {
        var inner=list(1,NOW,1,2);
        var held=latestAdmins(inner,1,0);
        assertTrue(state.acceptAdministrators(inner,v->fail()));
        long expiry=held.expiresAt();
        expect(DUPLICATE,judge(held,held));
        expect(DUPLICATE,verifier.judgeStore(held,held,state.administratorsAt(0).binding(pub(1)).memberId()));
        assertEquals(expiry,held.expiresAt());
        expect(INVALID,judge(record(DhtKeys.LATEST_ADMINS,inner,1,2,0,NOW+1),held));
        expect(INVALID,judge(record(DhtKeys.LATEST_ADMINS,inner,1,1,0,NOW),null));
        expect(ACCEPTED,judge(record(DhtKeys.LATEST_ADMINS,inner,2,2,1,NOW+1),held));
    }
    @Test void selfRemovalCannotExtendCustodyBeforeTheListIsApplied() {
        var inner=list(1,NOW,1,2);var held=latestAdmins(inner,1,0);
        expect(DUPLICATE,judge(held,held));
        expect(INVALID,judge(record(DhtKeys.LATEST_ADMINS,inner,1,2,0,NOW+1),held));
    }
    @Test void removedSignerCannotPublishADifferentSelfRemovalAtTheSameVersion() {
        advance(1,1,2);
        expect(INVALID,judge(latestAdmins(list(1,NOW,1,2,3),1,0),null));
    }
    @Test void removedSignerCannotSkipVersionsOrRestoreAPastSelfRemoval() {
        advance(1,1,2);
        expect(INVALID,judge(latestAdmins(list(3,NOW,1,2),1,0),null));
        advance(2,2,2);
        expect(INVALID,judge(history(list(1,NOW,1,2),1,0),null));
    }
    @Test void selfRemovalMustNameTheImmediatelyPreviousVersion() {
        advance(1,1,1,2);
        expect(INVALID,judge(latestAdmins(list(2,NOW,1,2),1,0),null));
    }
    @Test void removedSignerCanWinBackOnlyWithAChainedHigherLatestListContainingItself() {
        advance(1,1,2);
        var winner=list(1,NOW,1,1,2);
        expect(ACCEPTED,judge(latestAdmins(winner,1,0),null));
        expect(ACCEPTED,verifier.judgeStore(latestAdmins(winner,1,0),null,state.administratorsAt(0).binding(pub(1)).memberId()));
        expect(INVALID,judge(history(winner,1,0),null));
        expect(INVALID,judge(latestAdmins(list(1,NOW-2000,1,1,2),1,0),null));
    }

    // ---- 対応しない種類 / unsupported kinds ----
    @Test void thisSliceDoesNotJudgeKeyKinds() {
        var announcement=ManagedDhtRecordTest.wrapped(1,NOW,DhtIdTest.id(55).bytes());
        var record=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(1),announcement,1,0,digestAt(0),NOW,ManagedDhtRecordTest.certificate());
        expect(INVALID,judge(record,null));
    }
}
