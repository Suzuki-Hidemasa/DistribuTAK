// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ManagementScreenTest {
    @Test public void storageFailureStopsOperationsWithoutErasingRecords()throws Exception {
        try(var h=new LanControllerHarness()) {
            h.create();var c=LanControllerHarness.field(h.controller,"persistence");
            set(c,"state",CorePersistenceCoordinator.State.STORAGE_FAILED);set(c,"stopReason",CorePersistenceCoordinator.StopReason.STORAGE_FAILED);
            h.tick();h.tick();assertTrue(h.ui.last.text.contains("保存がいっぱい。通信を止めています"));
            assertFalse(h.ui.last.operationsReady);assertFalse(h.ui.last.text.contains("自分:"));assertFalse(h.disk.erased);
        }
    }
    @Test public void committedChangeFailureHasDistinctStopText()throws Exception {
        try(var h=new LanControllerHarness()) {
            h.create();var c=(CorePersistenceCoordinator)LanControllerHarness.field(h.controller,"persistence");
            set(c,"state",CorePersistenceCoordinator.State.STORAGE_FAILED);
            set(c,"stopReason",CorePersistenceCoordinator.StopReason.COMMITTED_NOT_APPLIED);
            h.tick();h.tick();assertTrue(h.ui.last.text.contains("保存した変更を適用できません。通信を止めています"));
            assertFalse(h.ui.last.text.contains("保存がいっぱい"));assertFalse(h.disk.erased);
        }
    }
    @Test public void recoveryPersistenceKeepsStorageFailureVisible()throws Exception {
        try(var h=new LanControllerHarness(recoveringDisk())) {
            var c=LanControllerHarness.field(h.controller,"persistence");set(c,"state",CorePersistenceCoordinator.State.PERSISTING);
            h.tick();assertTrue(h.ui.last.text.contains("保存がいっぱい"));assertFalse(h.ui.last.text.contains("保存中です"));
        }
    }
    static void set(Object value,String name,Object replacement)throws Exception {
        var field=value.getClass().getDeclaredField(name);field.setAccessible(true);field.set(value,replacement);
    }
    @Test public void noRecoveryPeerShowsThatRetrievalCannotContinue()throws Exception {
        try(var h=new LanControllerHarness(recoveringDisk())) {
            h.tick();assertTrue(h.ui.last.text.contains("取り直せないため"));
            assertFalse(h.ui.last.operationsReady);assertFalse(h.disk.erased);
        }
    }
    @Test public void recoveryExplainsThatOnlyRevocationsAreBeingRetrieved()throws Exception {
        var disk=recoveringDisk();
        try(var h=new LanControllerHarness(disk)) {
            assertTrue(h.ui.last.text.contains("保存がいっぱい"));
            assertTrue(h.ui.last.text.contains("取り直しています"));
            assertFalse(h.ui.last.text.contains("自分:"));
        }
    }
    @Test public void invalidMarkerHasItsOwnStopMessageAndKeepsRecords()throws Exception {
        var disk=recoveringDisk();
        disk.stopMarker.bytes[0]^=1;
        disk.stopMarker.bytes[128]^=1;
        try(var h=new LanControllerHarness(disk)) {
            assertTrue(h.ui.last.text.contains("保存した停止の記録を確かめられません。通信を止めています"));
            assertFalse(h.ui.last.text.contains("保存がいっぱい"));
            assertFalse(disk.erased);assertNotNull(disk.state.value);
        }
    }
    @Test public void persistenceIsTemporaryRatherThanStorageFailure()throws Exception {
        try(var h=new LanControllerHarness()) {
            h.create();var c=(CorePersistenceCoordinator)LanControllerHarness.field(h.controller,"persistence");
            c.saveUnchanged(()->{
                h.tick();h.drain();assertTrue(h.ui.last.text.contains("保存中です"));
                assertFalse(h.ui.last.text.contains("保存がいっぱい"));
            });
            h.tick();assertFalse(h.ui.last.text.contains("保存中です"));assertTrue(h.ui.last.operationsReady);
        }
    }
    @Test public void recoveryWithoutCandidatesExplainsOptionalErase()throws Exception {
        try(var h=new LanControllerHarness(recoveringDisk())) {
            h.offset.addAndGet(240_000_000_000L);h.tick();h.drain();
            assertTrue(h.ui.last.text.contains("取り直せないため"));
            assertTrue(h.ui.last.text.contains("消去して新しい招待で入り直せます"));
            assertFalse(h.disk.erased);
        }
    }
    @Test public void unknownAdministratorsAreCountedInOneRow()throws Exception {
        try(var h=new LanControllerHarness()) {
            h.create();addUnknown(h,2);h.tick();h.drain();
            assertTrue(h.ui.last.text.contains("対応のない管理者: 2 件"));
            assertEquals(1,h.ui.last.text.split("対応のない管理者:",-1).length-1);
        }
    }
    static LanControllerHarness.Disk recoveringDisk()throws Exception {
        var disk=new LanControllerHarness.Disk(LanControllerHarness.freePort());disk.enableSix();
        try(var g=LanGroup.create(disk.port(),LanControllerHarness.CLOCK,new java.security.SecureRandom())) {
            disk.save(g);disk.stopMarker.marker().active(new StopMarker.Target(g.saveSeq,1,new byte[32],new byte[32],StopMarker.RECEIVED));
        }
        return disk;
    }
    static void addUnknown(LanControllerHarness h,int count)throws Exception {
        addUnknown(LanBehaviourWiringTest.group(h),count);
    }
    static void addUnknown(LanGroup g,int count)throws Exception {
        var bindings=new ArrayList<>(g.state.administrators().bindings());
        // 旧一覧の UNKNOWN を保存から読み継ぐ場面を、その場で作った鍵で表す。
        // Model UNKNOWN entries retained from a legacy list using freshly generated keys.
        for(int i=0;i<count;i++){byte[] secret=new byte[32];new java.security.SecureRandom().nextBytes(secret);bindings.add(AdminBinding.unknown(Crypto.ed25519Public(secret)));Crypto.wipe(secret);}
        var list=AdminRecords.administrators(g.groupId,0,LanControllerHarness.CLOCK.millis(),bindings,g.administratorSecret);
        var revoked=g.state.revocations();
        var snapshot=new AdminRecordStore.Snapshot(List.of(list.encode(),revoked.encode()),AdminRecords.signAnchor(list,g.administratorSecret),revoked.encode(),0,revoked.version());
        g.state=LanGroup.restore(g.groupId,g.urlAdmin,snapshot,LanControllerHarness.CLOCK);
    }
}
