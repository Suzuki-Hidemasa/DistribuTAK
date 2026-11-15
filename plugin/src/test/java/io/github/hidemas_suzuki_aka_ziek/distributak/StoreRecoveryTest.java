// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class StoreRecoveryTest {
    @Test public void authenticatedPortRepairsInterruptedOrCorruptPublicSettings() throws Exception {
        assertEquals(54322,StoreRecovery.port(54321,54322));
        assertEquals(54322,StoreRecovery.port(null,54322));
        assertEquals(54321,StoreRecovery.port(54321,null));
        assertThrows(Exception.class,()->StoreRecovery.port(null,null));
        assertThrows(Exception.class,()->StoreRecovery.port(54321,10));
    }
    @Test public void erasingGateBlocksCreationAndJoinClearsOnlyAfterSuccess() throws Exception {
        assertFalse(StoreRecovery.canCreate(false,true));assertTrue(StoreRecovery.canJoin(false));
        assertTrue(StoreRecovery.canCreate(false,false));assertFalse(StoreRecovery.canJoin(true));
        boolean[] marker={true};
        var failed=new java.util.concurrent.FutureTask<Object>(()->{throw new IllegalStateException();});failed.run();
        assertThrows(Exception.class,()->StoreRecovery.acceptJoined(failed,()->marker[0]=false));assertTrue(marker[0]);
        var cancelled=new java.util.concurrent.FutureTask<Object>(()->null);cancelled.cancel(false);
        assertThrows(Exception.class,()->StoreRecovery.acceptJoined(cancelled,()->marker[0]=false));assertTrue(marker[0]);
        var pending=new java.util.concurrent.FutureTask<Object>(()->null);
        assertThrows(Exception.class,()->StoreRecovery.acceptJoined(pending,()->marker[0]=false));assertTrue(marker[0]);
        pending.run();StoreRecovery.acceptJoined(pending,()->marker[0]=false);assertFalse(marker[0]);
    }
    static class Disk implements StoreRecovery.EraseTarget {
        boolean pending,key=true,records=true,complete,initial;int step,crash=-1;boolean abrupt;
        void checkpoint(){if(step++==crash){if(abrupt)throw new AssertionError("simulated process death");throw new IllegalStateException("simulated stop");}}
        public boolean pending(){return pending;}
        public void markPending(){pending=true;checkpoint();}
        public void stop(){checkpoint();}
        public void deleteKey(){key=false;checkpoint();}
        public void deleteRecords(){records=false;checkpoint();}
        public void markComplete(){if(!initial)complete=true;checkpoint();}
        public void wipeMemory(){checkpoint();}
        public void clearPending(){pending=false;checkpoint();}
    }
    @Test public void eraseResumesAfterEveryStepWithoutReadingBrokenSettingsOrEnvelope() throws Exception {
        for(int at=0;at<7;at++) {
            Disk disk=new Disk();disk.crash=at;
            assertThrows(Exception.class,()->StoreRecovery.erase(disk));
            disk.crash=-1;StoreRecovery.resume(disk);
            assertFalse(disk.pending);assertFalse(disk.key);assertFalse(disk.records);assertTrue(disk.complete);
        }
        Disk control=new Disk();StoreRecovery.erase(control);
        assertFalse(control.key);assertFalse(control.records);assertTrue(control.complete);
    }
    @Test public void noPendingMarkerDoesNotEraseAnything() throws Exception {
        Disk disk=new Disk();StoreRecovery.resume(disk);
        assertTrue(disk.key);assertTrue(disk.records);assertFalse(disk.complete);assertEquals(0,disk.step);
    }
    @Test public void newCreationCommitsOnlyAfterEnvelopeAndCompletionMarker()throws Exception {
        Disk disk=new Disk();disk.complete=true;
        StoreRecovery.create(disk,()->{assertTrue(disk.pending);assertTrue(disk.complete);disk.records=true;},()->disk.complete=false);
        assertTrue(disk.key);assertTrue(disk.records);assertFalse(disk.complete);assertFalse(disk.pending);
        Disk failed=new Disk();failed.complete=true;
        assertThrows(Exception.class,()->StoreRecovery.create(failed,()->{throw new java.io.IOException("fixed failure");},()->failed.complete=false));
        assertFalse(failed.key);assertFalse(failed.records);assertTrue(failed.complete);assertFalse(failed.pending);
    }
    @Test public void interruptedNewCreationIsErasedAtEveryUncommittedBoundary()throws Exception {
        for(int at=0;at<3;at++) {
            Disk disk=new Disk();disk.complete=true;disk.crash=at;disk.abrupt=true;
            assertThrows(AssertionError.class,()->StoreRecovery.create(disk,()->{disk.records=true;disk.checkpoint();},()->{disk.complete=false;disk.checkpoint();}));
            assertTrue(disk.pending);disk.crash=-1;StoreRecovery.resume(disk);
            assertFalse(disk.key);assertFalse(disk.records);assertTrue(disk.complete);assertFalse(disk.pending);
        }
    }

    @Test public void failedCreationCleanupKeepsPendingUntilNextStartup()throws Exception {
        Disk disk=new Disk();disk.complete=true;disk.crash=2;
        assertThrows(Exception.class,()->StoreRecovery.create(disk,()->{throw new java.io.IOException("fixed failure");},()->disk.complete=false));
        assertTrue(disk.pending);assertTrue(disk.complete);
        disk.crash=-1;StoreRecovery.resume(disk);
        assertFalse(disk.key);assertFalse(disk.records);assertFalse(disk.pending);assertTrue(disk.complete);
    }

    @Test public void firstCreationReturnsToInitialStateAtEveryBoundary()throws Exception {
        for(int at=0;at<4;at++) {
            Disk disk=new Disk();disk.initial=true;disk.crash=at;disk.abrupt=true;
            assertThrows(AssertionError.class,()->StoreRecovery.create(disk,()->{disk.records=true;disk.checkpoint();},disk::checkpoint));
            disk.crash=-1;StoreRecovery.resume(disk);
            assertFalse(disk.complete);
            if(at<3){assertFalse(disk.key);assertFalse(disk.records);}else{assertTrue(disk.key);assertTrue(disk.records);}
            assertFalse(disk.pending);
        }
    }

    @Test public void joinedCommitRecoversAtEveryBoundaryWithAndWithoutEraseHistory()throws Exception {
        for(boolean initial:new boolean[]{false,true})for(int at=0;at<4;at++) {
            Disk disk=new Disk();disk.initial=initial;disk.complete=!initial;disk.crash=at;disk.abrupt=true;
            var done=new java.util.concurrent.FutureTask<Object>(()->null);done.run();
            assertThrows(AssertionError.class,()->StoreRecovery.acceptJoined(done,disk,
                    ()->{disk.records=true;disk.checkpoint();},()->{disk.complete=false;disk.checkpoint();}));
            disk.crash=-1;StoreRecovery.resume(disk);
            assertFalse(disk.pending);
            if(at<3){assertFalse(disk.key);assertFalse(disk.records);assertEquals(!initial,disk.complete);}
            else{assertTrue(disk.key);assertTrue(disk.records);assertFalse(disk.complete);}
        }
    }

    @Test public void eraseRecoveryTakesPriorityWhenBothMarkersRemain()throws Exception {
        Disk erased=new Disk(),initial=new Disk();erased.pending=true;initial.pending=true;initial.initial=true;
        StoreRecovery.resume(erased,initial);
        assertTrue(erased.complete);assertFalse(erased.key);assertFalse(erased.records);
        assertFalse(erased.pending);assertFalse(initial.pending);
        assertEquals(1,initial.step);
    }

    @Test public void firstCreationFailureDoesNotInventEraseHistory()throws Exception {
        Disk disk=new Disk();disk.initial=true;
        assertThrows(Exception.class,()->StoreRecovery.create(disk,()->{throw new java.io.IOException();},()->{}));
        assertFalse(disk.complete);assertFalse(disk.key);assertFalse(disk.records);assertFalse(disk.pending);
    }

    @Test public void failedInitialCleanupRetriesWithoutInventingEraseHistory()throws Exception {
        Disk disk=new Disk();disk.initial=true;disk.crash=2;
        assertThrows(Exception.class,()->StoreRecovery.create(disk,()->{throw new java.io.IOException();},()->{}));
        assertTrue(disk.pending);assertFalse(disk.complete);
        disk.crash=-1;StoreRecovery.resume(disk);
        assertFalse(disk.key);assertFalse(disk.records);assertFalse(disk.complete);assertFalse(disk.pending);
    }

}
