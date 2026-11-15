// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.time.*;
import java.security.SecureRandom;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ExternalStateStorageTest {
    static class Disk extends StateEnvelopeTest.MemoryTarget implements SyncStateStorage.Source {
        public boolean exists(){return value!=null;}public byte[] read(){return value.clone();}
    }
    static ExternalStateStorage storage(Disk disk){return new ExternalStateStorage(new StateEnvelope(new StateEnvelopeTest.TestCipher()),disk,disk);}
    @Test public void fullMarksUseSameEnvelopeAndMissingCorruptOrWrongScopeStops()throws Exception {
        var disk=new Disk();var clock=LanControllerHarness.CLOCK;
        try(var group=LanGroup.create(54321,clock,new SecureRandom());var other=LanGroup.create(54322,clock,new SecureRandom())){
            var store=storage(disk);var marks=store.load(group);for(int n=0;n<65536;n++)assertTrue(marks.add("external-"+n));
            group.syncInitialized=true;store.save(group,marks);assertEquals(ExternalMarks.MAX_ENVELOPE_BYTES,disk.value.length);
            assertTrue(store.load(group).full());assertThrows(Exception.class,()->store.load(other));
            byte[] good=disk.value;disk.value=null;assertThrows(Exception.class,()->store.load(group));
            disk.value=good.clone();disk.value[disk.value.length-1]^=1;assertThrows(Exception.class,()->store.load(group));
            disk.value=good;assertTrue(store.load(group).full());
        }
    }
    @Test public void failedExternalSaveKeepsOldMarksAndCanRetry()throws Exception {
        var disk=new Disk();try(var group=LanGroup.create(54321,LanControllerHarness.CLOCK,new SecureRandom())){
            var store=storage(disk);var marks=store.load(group);group.syncInitialized=true;marks.add("private-mark");disk.fail=true;
            assertThrows(Exception.class,()->store.save(group,marks));disk.fail=false;assertFalse(store.load(group).contains("private-mark"));
            store.save(group,marks);assertTrue(store.load(group).contains("private-mark"));
        }
    }
    @Test public void enlargedSyncEnvelopeHasExactLimitWithoutEnlargingNormalState()throws Exception {
        var regular=new StateEnvelope(new StateEnvelopeTest.TestCipher());var sync=regular.withMaximum(StateEnvelope.SYNC_MAX_BYTES);
        assertThrows(Exception.class,()->regular.seal(new byte[StateEnvelope.MAX_BYTES]));
        byte[] maximum=new byte[4194266];byte[] wire=sync.seal(maximum);assertEquals(4194304,wire.length);assertArrayEquals(maximum,sync.open(wire));
        assertThrows(Exception.class,()->sync.seal(new byte[4194267]));assertThrows(Exception.class,()->regular.open(wire));
    }
}
