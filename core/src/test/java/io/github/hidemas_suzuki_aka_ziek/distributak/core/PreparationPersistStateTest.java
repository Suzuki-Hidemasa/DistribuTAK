// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
/**
 * DTAK-8: {@code Preparation} 由来の候補を {@code persist} に直接渡しても、{@code Preparation.publish} と同じ結果になること。
 * 保存に成功したあとは、公開が失敗しても {@code expired()}・{@code cancel()} が状態を CANCELLED に戻さないこと。
 * <p>
 * DTAK-8: Passing a candidate derived from a {@code Preparation} straight to {@code persist} gives the same result as {@code Preparation.publish}.
 * Once the save has succeeded, {@code expired()} and {@code cancel()} never turn the state into CANCELLED, even if publishing fails.
 */
class PreparationPersistStateTest {
    final SessionManagerTest f=new SessionManagerTest();
    final byte[] b=AdminRecordsTest.key(70);
    final byte[] c=AdminRecordsTest.key(71);
    AdminState state() {
        var s=new AdminState(f.group,Crypto.ed25519Public(f.admin),f.time,new InMemoryAdminRecordStore());
        var list=AdminRecords.list(AdminRecords.Kind.ADMINS,f.group,0,f.time.millis,List.of(Crypto.ed25519Public(f.admin),Crypto.ed25519Public(b),Crypto.ed25519Public(c)),f.admin);
        s.bootstrap(list,AdminRecords.signAnchor(list,f.admin));s.acceptRevocations(AdminRecords.initialRevocations(f.group,f.time.millis,f.admin));return s;
    }
    GroupAdministration service(SessionManagerTest.Node n,AdminState state) {
        return new GroupAdministration(state,n.cert,n.identity,n.secret,f.admin,f.time,()->f.time.nanos,new java.security.SecureRandom());
    }
    GroupAdministration.Preparation prepared(GroupAdministration ga,SessionManagerTest.Node n) {
        var p=ga.prepareRemoval(n.sessions,List.of(Crypto.ed25519Public(b),Crypto.ed25519Public(c)),true);p.reissue(x->{});return p;
    }
    @Test void persistDirectlyCompletesThePreparationLikePublish() {
        // persist に直接渡しても、保存と公開のあとは COMPLETE になる。
        // After save and publish, a direct persist call leaves the Preparation COMPLETE.
        try(var n=f.new Node(1)) {
            var state=state();
            try(var ga=service(n,state)) {
                var p=prepared(ga,n);var candidate=p.commit();assertEquals(GroupAdministration.Phase.COMMIT,p.phase());
                ga.persist(candidate,s->{},x->{});
                assertEquals(1,state.administrators().entries().size());assertEquals(GroupAdministration.Phase.COMPLETE,p.phase());
                // 60 秒たっても、取り消しても、COMPLETE のまま。
                // It stays COMPLETE after 60 seconds and after cancel().
                f.time.advance(60);assertFalse(p.expired());p.cancel();assertEquals(GroupAdministration.Phase.COMPLETE,p.phase());
            }
        }
    }
    @Test void publishFailureAfterSuccessfulSaveDoesNotTurnTheStateIntoCancelled() {
        // 保存は成功し公開が失敗したら、60 秒後も cancel() も状態を変えない。保存済みの事実が残る。
        // If the save succeeds but publishing fails, neither 60 seconds nor cancel() changes the state, because the save is a fact.
        try(var n=f.new Node(1)) {
            var state=state();
            try(var ga=service(n,state)) {
                var p=prepared(ga,n);var candidate=p.commit();
                assertThrows(IllegalStateException.class,()->ga.persist(candidate,s->{},x->{throw new IllegalStateException();}));
                assertEquals(1,state.administrators().entries().size());assertEquals(GroupAdministration.Phase.COMMIT,p.phase());
                f.time.advance(60);assertFalse(p.expired());assertEquals(GroupAdministration.Phase.COMMIT,p.phase());
                p.cancel();assertEquals(GroupAdministration.Phase.COMMIT,p.phase());
            }
        }
    }
    @Test void publishFailureThroughPreparationPublishKeepsTheSavedState() {
        // Preparation.publish 経由でも同じ。
        // The same holds through Preparation.publish.
        try(var n=f.new Node(1)) {
            var state=state();
            try(var ga=service(n,state)) {
                var p=prepared(ga,n);var candidate=p.commit();
                assertThrows(IllegalStateException.class,()->p.publish(candidate,s->{},x->{throw new IllegalStateException();}));
                assertEquals(1,state.administrators().entries().size());
                f.time.advance(60);assertFalse(p.expired());p.cancel();assertNotEquals(GroupAdministration.Phase.CANCELLED,p.phase());
            }
        }
    }
    @Test void saveFailureStillAllowsExpiryAndCancel() {
        // 保存が失敗したあとは、これまでどおり期限切れと取り消しで CANCELLED になる。
        // After a failed save, expiry and cancel() still turn the state into CANCELLED as before.
        try(var n=f.new Node(1)) {
            var state=state();
            try(var ga=service(n,state)) {
                var p=prepared(ga,n);var candidate=p.commit();
                assertThrows(IllegalStateException.class,()->ga.persist(candidate,s->{throw new IllegalStateException();},x->fail()));
                assertEquals(3,state.administrators().entries().size());assertEquals(GroupAdministration.Phase.COMMIT,p.phase());
                f.time.advance(60);assertTrue(p.expired());assertEquals(GroupAdministration.Phase.CANCELLED,p.phase());
            }
            try(var ga=service(n,state)) {
                var p=prepared(ga,n);var candidate=p.commit();
                assertThrows(IllegalStateException.class,()->ga.persist(candidate,s->{throw new IllegalStateException();},x->fail()));
                p.cancel();assertEquals(GroupAdministration.Phase.CANCELLED,p.phase());
            }
        }
    }
    @Test void expiryBeforeSaveIsStillCheckedByPersist() {
        // 保存の前に 60 秒たっていたら、persist は保存せずに断る。
        // If 60 seconds have passed before the save, persist refuses without saving.
        try(var n=f.new Node(1)) {
            var state=state();
            try(var ga=service(n,state)) {
                var p=prepared(ga,n);var candidate=p.commit();f.time.advance(60);
                assertThrows(SecurityException.class,()->ga.persist(candidate,s->fail(),x->fail()));
                assertEquals(3,state.administrators().entries().size());assertEquals(GroupAdministration.Phase.CANCELLED,p.phase());
            }
        }
    }
}
