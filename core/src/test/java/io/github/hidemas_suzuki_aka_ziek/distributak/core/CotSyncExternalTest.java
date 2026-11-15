// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.security.SecureRandom;
import java.time.*;
import java.util.concurrent.atomic.AtomicLong;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CotSyncExternalTest {
    static SyncState full(){
        var base=SyncSchema.SyncSnapshot.newBuilder().setPurpose("distributak-sync-state-v1").setGroupId(SyncWire.bytes(new byte[32])).setLocalId(SyncWire.bytes(CotRecordTest.id(1)));
        for(int i=0;i<4096;i++)base.addOrigins(SyncSchema.SyncOrigin.newBuilder().setUid(String.format("own-%04d",i)).setKind(SyncState.Origin.LOCAL_CREATED.ordinal()));
        return SyncState.decode(base.build().toByteArray(),new byte[32],CotRecordTest.id(1));
    }
    static final class Disk {
        SyncState state;ExternalMarks marks;
        CotSync open(){return new CotSync(CotRecordTest.id(1),state,Clock.fixed(Instant.ofEpochMilli(CotRecordTest.NOW),ZoneOffset.UTC),new AtomicLong()::get,
            next->state=SyncState.decode(next.encode(),new byte[32],CotRecordTest.id(1)),(p,s,w)->true,r->{},new SecureRandom(),0,marks,
            next->marks=ExternalMarks.decode(next.encode(),new byte[32],CotRecordTest.id(1)));}
    }
    @Test void syncFullCanStillMarkAnExistingOwnUidAsExternalAndRestartCannotSendIt(){
        var disk=new Disk();disk.state=full();disk.marks=new ExternalMarks(new byte[32],CotRecordTest.id(1));
        try(var sync=disk.open()){
            sync.external("own-0000");sync.flush();assertTrue(disk.marks.contains("own-0000"));assertEquals(4096,disk.state.uidCount());
            assertFalse(sync.publish("own-0000",CotRecordTest.xml("own-0000",CotRecordTest.NOW+60000),SyncState.Origin.LOCAL_CREATED));
        }
        try(var restored=disk.open()){assertFalse(restored.remove("own-0000"));assertFalse(restored.remove("own-0001"));}
    }
    @Test void fullExternalRegistryAllowsKnownMarksAndExistingUpdatesButStopsForUnrecordedExternal(){
        var disk=new Disk();disk.state=SyncStateTest.state();disk.state.origin("existing",SyncState.Origin.LOCAL_POSITION);
        disk.marks=new ExternalMarks(new byte[32],CotRecordTest.id(1));for(int i=0;i<65536;i++)disk.marks.add("outside-"+i);
        try(var sync=disk.open()){
            sync.external("outside-0");assertFalse(sync.isClosed());assertTrue(sync.remove("existing"));
            assertFalse(sync.publish("new",CotRecordTest.xml("new",CotRecordTest.NOW+60000),SyncState.Origin.LOCAL_CREATED));
            assertThrows(CotSync.ExternalCapacityException.class,()->sync.external("unrecorded"));assertTrue(sync.isClosed());
            assertEquals(65536,disk.marks.size());assertEquals(SyncState.Origin.LOCAL_POSITION,disk.state.origin("existing"));
        }
    }
}
