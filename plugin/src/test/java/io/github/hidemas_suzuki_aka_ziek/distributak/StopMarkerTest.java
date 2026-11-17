// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class StopMarkerTest {
    static final class Disk implements StopMarker.Region {
        byte[] bytes;
        int writes,syncs,failWrites,failSyncs;
        boolean failAllocation;
        final List<Long> waits=new ArrayList<>();
        public byte[] read(){return bytes==null?null:bytes.clone();}
        public void allocate()throws IOException{
            if(failAllocation)throw new IOException("injected allocation failure");
            if(bytes==null)bytes=new byte[256];
        }
        public void write(int offset,byte[] value)throws IOException{
            writes++;if(failWrites-->0)throw new IOException("injected write failure");
            System.arraycopy(value,0,bytes,offset,value.length);
        }
        public void sync()throws IOException{syncs++;if(failSyncs-->0)throw new IOException("injected sync failure");}
        StopMarker marker(){return new StopMarker(this,waits::add);}
    }
    static StopMarker.Target target(long seq){return new StopMarker.Target(seq,3,new byte[32],new byte[32],1);}
    static void checksum(byte[] bytes,int offset){
        byte[] digest=Crypto.blake2s(Arrays.copyOfRange(bytes,offset,offset+96));
        System.arraycopy(digest,0,bytes,offset+96,32);
    }
    @Test public void initialClearAllocatesAndSynchronizesExactly256Bytes()throws Exception{
        var d=new Disk();d.marker().initialize(target(1));assertEquals(256,d.bytes.length);
        assertTrue(d.syncs>=2);assertEquals(StopMarker.Status.CLEAR,d.marker().inspect().status());
    }
    @Test public void slotLayoutAndChecksumAreFixed()throws Exception{
        var d=new Disk();d.marker().initialize(target(7));var in=ByteBuffer.wrap(d.bytes);
        assertEquals(0x4454534d,in.getInt());assertEquals(1,in.get());assertEquals(0,in.get());
        assertEquals(1,in.get());assertEquals(0,in.get());assertEquals(1,in.getLong());
        assertEquals(7,in.getLong());assertEquals(3,in.getLong());
        assertArrayEquals(Crypto.blake2s(Arrays.copyOf(d.bytes,96)),Arrays.copyOfRange(d.bytes,96,128));
        assertEquals(2,ByteBuffer.wrap(d.bytes,136,8).getLong());
    }
    @Test public void activeAndClearOverwriteSameAllocatedArray()throws Exception{
        var d=new Disk();var m=d.marker();m.initialize(target(1));byte[] original=d.bytes;
        m.active(target(2));assertSame(original,d.bytes);assertEquals(StopMarker.Status.ACTIVE,m.inspect().status());
        m.clear(target(2));assertSame(original,d.bytes);assertEquals(StopMarker.Status.CLEAR,m.inspect().status());
        assertEquals(2,m.inspect().target().saveSeq());
    }
    @Test public void firstWriteFailureWaits100MillisThenRetries()throws Exception{
        var d=new Disk();var m=d.marker();m.initialize(target(1));d.failWrites=1;m.active(target(2));
        assertEquals(List.of(100L),d.waits);assertEquals(StopMarker.Status.ACTIVE,m.inspect().status());
    }
    @Test public void twoFailuresAllowThirdAttemptAndWaitTwice()throws Exception{
        var d=new Disk();var m=d.marker();m.initialize(target(1));d.failWrites=2;m.active(target(2));
        assertEquals(List.of(100L,100L),d.waits);assertEquals(2,m.inspect().target().saveSeq());
    }
    @Test public void threeFailuresStopWithoutFourthAttemptOrFinalWait()throws Exception{
        var d=new Disk();var m=d.marker();m.initialize(target(1));int before=d.writes;d.failWrites=3;
        assertThrows(IOException.class,()->m.active(target(2)));assertEquals(3,d.writes-before);
        assertEquals(List.of(100L,100L),d.waits);assertEquals(StopMarker.Status.CLEAR,m.inspect().status());
    }
    @Test public void synchronizationFailureIsRetriedEvenAfterSuccessfulWrite()throws Exception{
        var d=new Disk();var m=d.marker();m.initialize(target(1));d.failSyncs=2;m.active(target(2));
        assertEquals(List.of(100L,100L),d.waits);assertEquals(StopMarker.Status.ACTIVE,m.inspect().status());
    }
    @Test public void allClearSyncFailuresReturnFailure()throws Exception{
        var d=new Disk();var m=d.marker();m.initialize(target(1));m.active(target(2));d.failSyncs=3;
        assertThrows(IOException.class,()->m.clear(target(2)));assertEquals(List.of(100L,100L),d.waits);
    }
    @Test public void partialActiveNeverFallsBackToOldClear()throws Exception{
        var d=new Disk();var m=d.marker();m.initialize(target(1));byte[] old=d.bytes.clone();m.active(target(2));
        System.arraycopy(old,128,d.bytes,128,128);
        assertEquals(StopMarker.Status.ACTIVE,m.inspect().status());assertEquals(2,m.inspect().target().saveSeq());
    }
    @Test public void partialClearStillRequiresCommittedCandidateEvidence()throws Exception{
        var d=new Disk();var m=d.marker();m.initialize(target(1));m.active(target(2));byte[] active=d.bytes.clone();m.clear(target(2));
        System.arraycopy(active,128,d.bytes,128,128);
        assertEquals(StopMarker.Status.ACTIVE,m.inspect().status());assertEquals(2,m.inspect().target().saveSeq());
    }
    @Test public void clearAfterPartialActivePreservesTheOnlyActiveUntilOtherSlotIsSynced()throws Exception{
        var d=new Disk();var m=d.marker();m.initialize(target(1));byte[] initial=d.bytes.clone();m.active(target(2));
        System.arraycopy(initial,128,d.bytes,128,128);
        byte[] before=d.bytes.clone();m.clear(target(2));byte[] completed=d.bytes.clone();
        int first=ByteBuffer.wrap(completed,8,8).getLong()<ByteBuffer.wrap(completed,136,8).getLong()?0:128;
        d.bytes=before;System.arraycopy(completed,first,d.bytes,first,128);
        assertEquals(StopMarker.Status.ACTIVE,m.inspect().status());assertEquals(2,m.inspect().target().saveSeq());
    }
    @Test public void conflictingClearTargetsAreNotNormalStartup()throws Exception{
        var d=new Disk();var m=d.marker();m.initialize(target(1));byte[] old=d.bytes.clone();m.active(target(2));m.clear(target(2));
        System.arraycopy(old,0,d.bytes,0,128);assertEquals(StopMarker.Status.INVALID,m.inspect().status());
    }
    @Test public void missingTruncatedOrExtendedRegionIsInvalid()throws Exception{
        var d=new Disk();assertEquals(StopMarker.Status.INVALID,d.marker().inspect().status());
        for(int length:new int[]{0,128,255,257}){d.bytes=new byte[length];assertEquals(StopMarker.Status.INVALID,d.marker().inspect().status());}
    }
    @Test public void fileRegionAllowsOnlyMissingOrZeroInitialAllocationForMigration()throws Exception{
        var path=Files.createTempFile("dtak-marker-test-",".bin");
        try{
            var region=new StopMarker.FileRegion(path.toFile(),()->{});var marker=new StopMarker(region,millis->{});
            var target=target(1);
            for(int length:new int[]{0,1,128,255,256,257,1024}){
                Files.write(path,new byte[length]);
                assertEquals(StopMarker.Status.INVALID,marker.inspect().status());
                assertEquals(length<=StopMarker.BYTES,marker.canInitializeMigration(target.requiredVersion(),target.revocationDigest()));
                if(length<=StopMarker.BYTES){
                    marker.initializeMigration(target);assertEquals(StopMarker.Status.CLEAR,marker.inspect().status());
                    assertEquals(StopMarker.BYTES,Files.size(path));
                }else assertThrows(IOException.class,()->marker.initializeMigration(target));
                if(length>0){
                    byte[] nonzero=new byte[length];nonzero[length-1]=1;Files.write(path,nonzero);
                    assertFalse(marker.canInitializeMigration(target.requiredVersion(),target.revocationDigest()));
                    assertThrows(IOException.class,()->marker.initializeMigration(target));assertArrayEquals(nonzero,Files.readAllBytes(path));
                }
            }
            Files.delete(path);assertEquals(StopMarker.Status.INVALID,marker.inspect().status());
            assertTrue(marker.canInitializeMigration(target.requiredVersion(),target.revocationDigest()));
            marker.initializeMigration(target);assertEquals(StopMarker.Status.CLEAR,marker.inspect().status());
        }finally{Files.deleteIfExists(path);}
    }
    @Test public void loneClearMigrationRejectsDifferentVersion()throws Exception{
        rejectLoneClearMismatch(true);
    }
    @Test public void loneClearMigrationRejectsDifferentRevocationDigest()throws Exception{
        rejectLoneClearMismatch(false);
    }
    private void rejectLoneClearMismatch(boolean version)throws Exception{
        for(int offset:new int[]{0,StopMarker.SLOT_BYTES}){
            var disk=new Disk();var marker=disk.marker();var original=target(1);marker.initializeMigration(original);
            disk.bytes[offset]^=1;byte[] before=disk.bytes.clone();int writes=disk.writes,syncs=disk.syncs;
            assertEquals(StopMarker.Status.INVALID,marker.inspect().status());
            byte[] digest=original.revocationDigest();if(!version)digest[0]^=1;
            var different=new StopMarker.Target(original.saveSeq(),original.requiredVersion()+(version?1:0),
                    original.stateDigest(),digest,original.reason());
            assertFalse(marker.canInitializeMigration(different.requiredVersion(),different.revocationDigest()));
            assertThrows(IOException.class,()->marker.initializeMigration(different));
            assertArrayEquals(before,disk.bytes);assertEquals(writes,disk.writes);assertEquals(syncs,disk.syncs);
        }
    }
    @Test public void corruptChecksumAndUnknownFieldsAreRejected()throws Exception{
        var d=new Disk();var m=d.marker();m.initialize(target(1));byte[] valid=d.bytes.clone();
        for(int offset:new int[]{0,4,5,6,7,96}){
            d.bytes=valid.clone();d.bytes[offset]=(byte)99;if(offset<96)checksum(d.bytes,0);
            assertEquals(StopMarker.Status.INVALID,m.inspect().status());
        }
    }
    @Test public void negativeAndOverflowingSequencesAreRejected()throws Exception{
        var d=new Disk();var m=d.marker();m.initialize(target(1));byte[] valid=d.bytes.clone();
        for(int offset:new int[]{8,16,24}){
            d.bytes=valid.clone();ByteBuffer.wrap(d.bytes,offset,8).putLong(-1);checksum(d.bytes,0);
            assertEquals(StopMarker.Status.INVALID,m.inspect().status());
        }
        d.bytes=valid.clone();ByteBuffer.wrap(d.bytes,136,8).putLong(Long.MAX_VALUE);checksum(d.bytes,128);
        assertThrows(IOException.class,()->m.active(target(2)));
    }
    @Test public void initializationFailureCannotBeMistakenForMigrationSuccess()throws Exception{
        var d=new Disk();d.failAllocation=true;assertThrows(IOException.class,()->d.marker().initialize(target(1)));
        assertEquals(StopMarker.Status.INVALID,d.marker().inspect().status());
    }
    @Test public void targetArraysAreDefensivelyCopied(){
        byte[] state=new byte[32],union=new byte[32];var t=new StopMarker.Target(1,2,state,union,1);
        state[0]=1;union[0]=1;t.stateDigest()[0]=2;t.revocationDigest()[0]=2;
        assertEquals(0,t.stateDigest()[0]);assertEquals(0,t.revocationDigest()[0]);
    }
    @Test public void realFileIsPreallocatedAndUpdatedWithoutReplacement()throws Exception{
        var path=Files.createTempFile("dtak-marker-test-",".bin");
        try{
            var m=new StopMarker(new StopMarker.FileRegion(path.toFile(),()->{
                try(var channel=java.nio.channels.FileChannel.open(path.getParent(),java.nio.file.StandardOpenOption.READ)){channel.force(true);}
            }),millis->{});m.initialize(target(1));
            Object before=Files.readAttributes(path,java.nio.file.attribute.BasicFileAttributes.class).fileKey();
            m.active(target(2));m.clear(target(2));
            assertEquals(256,Files.size(path));assertEquals(before,Files.readAttributes(path,java.nio.file.attribute.BasicFileAttributes.class).fileKey());
            assertEquals(StopMarker.Status.CLEAR,m.inspect().status());
        }finally{Files.delete(path);}
    }
}
