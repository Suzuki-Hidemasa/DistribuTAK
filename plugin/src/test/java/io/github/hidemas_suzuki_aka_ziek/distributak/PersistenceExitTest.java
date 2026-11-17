// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import java.security.SecureRandom;
import org.junit.Test;
import static org.junit.Assert.*;

public class PersistenceExitTest {
    @Test public void reservedTryCloseRefusesWithoutErasingAndOtherFailuresEscape()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())){
            byte[] before=group.identitySecret.clone();
            try(var reservation=reserve(group)){
                assertFalse(group.tryClose());assertTrue(Arrays.equals(before,group.identitySecret));
            }
            var unrelated=new IllegalStateException("Injected unrelated failure");
            assertSame(unrelated,assertThrows(IllegalStateException.class,()->LanGroup.reservedClose(unrelated)));
            assertTrue(group.tryClose());assertTrue(Arrays.equals(new byte[before.length],group.identitySecret));Crypto.wipe(before);
        }
    }
    @Test public void disconnectRetriesReservedReleaseOnNextPoll()throws Exception {
        try(var h=new LanControllerHarness()){
            h.create();var group=(LanGroup)LanControllerHarness.field(h.controller,"group");
            byte[] before=group.identitySecret.clone();
            try(var reservation=reserve(group)){
                h.controller.disconnect();h.work.drain();
                assertSame(group,LanControllerHarness.field(h.controller,"group"));
                assertTrue(Arrays.equals(before,group.identitySecret));assertNull(h.endpoint());
            }
            h.work.repeated.run();assertNull(LanControllerHarness.field(h.controller,"group"));
            assertTrue(Arrays.equals(new byte[before.length],group.identitySecret));Crypto.wipe(before);
        }
    }
    @Test public void controllerShutdownDuringReservationRetainsIntactGroupWithoutThrowing()throws Exception {
        try(var h=new LanControllerHarness()){
            h.create();var group=(LanGroup)LanControllerHarness.field(h.controller,"group");
            byte[] before=group.identitySecret.clone();
            try(var reservation=reserve(group)){
                h.controller.close();
                try{h.work.drain();}catch(IllegalStateException failure){fail("Reserved shutdown must retain the membership");}
                assertSame(group,LanControllerHarness.field(h.controller,"group"));
                assertTrue(Arrays.equals(before,group.identitySecret));
            }
            assertTrue(Arrays.equals(before,group.identitySecret));group.close();Crypto.wipe(before);
        }
    }
    static AutoCloseable reserve(LanGroup group)throws Exception {
        var method=AdminState.class.getDeclaredMethod("preparePersistence",AdminRecordStore.Snapshot.class,AdminState.class);
        var fork=AdminState.class.getDeclaredMethod("fork");fork.setAccessible(true);
        method.setAccessible(true);return (AutoCloseable)method.invoke(group.state,group.state.snapshot(),fork.invoke(group.state));
    }
    @Test public void reservedCloseLeavesEveryOwnedSecretIntactUntilRetry()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())){
            byte[][] owned={group.identitySecret,group.handshakeSecret,group.administratorSecret,group.groupKey};
            var before=Arrays.stream(owned).map(byte[]::clone).toArray(byte[][]::new);
            try(var reservation=reserve(group)){
                assertThrows(IllegalStateException.class,group::close);
                for(int i=0;i<owned.length;i++)assertTrue("Owned value changed before reservation release",Arrays.equals(before[i],owned[i]));
                assertNotNull(group.state.administrators());
            }
            group.close();for(byte[] secret:owned)assertTrue(Arrays.equals(new byte[secret.length],secret));
        }
    }
    @Test public void failedHookAcquisitionStillMarksStorageBlockedWithoutRetryingSupplier()throws Exception {
        try(var p=new RecoveryTransportTest.Pair(false)){
            int[] acquired={0};
            try(var recovery=new RevocationRecovery(p.a,p.sa,p.ca,p.time,new SecureRandom(),()->{
                acquired[0]++;throw new IllegalStateException("Injected hook acquisition failure");
            },p.requestWire)){
                var body=p.body(1,List.of(p.subject));
                var page=ManagementPage.split(ManagementPage.Kind.REVOCATION,new byte[16],p.a.groupId,body.encode(),1).get(0);
                assertTrue(recovery.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope()));
                assertEquals(CorePersistenceCoordinator.State.STORAGE_FAILED,p.ca.state());
                assertTrue(p.a.storageBlocked);assertEquals(1,acquired[0]);assertTrue(p.sa.isClosed());
            }
        }
    }
}
