// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.ByteString;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

class SyncFragmentsTest {
    static byte[] token(int n) { byte[] id=new byte[16];id[0]=(byte)n;return id; }
    static byte[] message() {
        long stale=CotRecordTest.NOW+60000;
        String xml=new String(CotRecordTest.xml("test",stale),StandardCharsets.UTF_8)
                .replace("<detail/>","<detail><remarks>"+"x".repeat(60000)+"</remarks></detail>");
        return SyncWire.encode(CotRecord.record("test",CotRecordTest.NOW,CotRecordTest.id(1),stale,xml.getBytes(StandardCharsets.UTF_8),1));
    }
    static byte[] change(byte[] wire,java.util.function.Consumer<SyncSchema.SyncFragment.Builder> update) {
        var envelope=SyncWire.parse(wire);var fragment=envelope.getFragment().toBuilder();update.accept(fragment);
        return envelope.toBuilder().setFragment(fragment).build().toByteArray();
    }
    @Test void largeRecordReassemblesOutOfOrderAndEachFrameFitsTheExistingDataBudget() {
        var clock=new AtomicLong();var layer=new SyncFragments(clock::get);
        byte[] message=message();var frames=new ArrayList<>(SyncFragments.split(message,token(1)));
        assertTrue(frames.size()>1);for(byte[] frame:frames)assertTrue(frame.length<=1176);
        Collections.reverse(frames);SyncFragments.Result complete=null;
        for(byte[] frame:frames) { var result=layer.accept(CotRecordTest.id(2),token(2),frame);if(result!=null)complete=result; }
        assertNotNull(complete);assertArrayEquals(message,complete.message());assertEquals(0,layer.pendingCount());
        complete.close();layer.close();
    }
    @Test void inventoryAndRequestAlsoPassThroughTheSameFragmentLayer() {
        var inventory=SyncSchema.SyncInventory.newBuilder().setSnapshotId(ByteString.copyFrom(token(1))).setLast(true);
        for(int n=0;n<64;n++)inventory.addEntries(SyncSchema.SyncInventoryEntry.newBuilder().setUid("x".repeat(250)+n)
                .setVersion(SyncSchema.SyncVersion.newBuilder().setWallMillis(CotRecordTest.NOW).setEudId(ByteString.copyFrom(CotRecordTest.id(1))))
                .setHash(ByteString.copyFrom(new byte[32])));
        var request=SyncSchema.SyncRequest.newBuilder().setSnapshotId(inventory.getSnapshotId()).addAllWanted(inventory.getEntriesList());
        for(byte[] wire:List.of(SyncWire.envelope().setInventory(inventory).build().toByteArray(),SyncWire.envelope().setRequest(request).build().toByteArray())) {
            var layer=new SyncFragments(()->0);SyncFragments.Result complete=null;
            for(byte[] frame:SyncFragments.split(wire,token(1)))complete=layer.accept(CotRecordTest.id(2),token(2),frame);
            assertNotNull(complete);assertArrayEquals(wire,complete.message());complete.close();layer.close();
        }
    }
    @Test void smallMessagesStaySingleAndCannotExceedTheLogicalLimit() {
        byte[] small=SyncWire.ack(CotRecordTest.record(CotRecordTest.NOW,1,1));
        assertArrayEquals(small,SyncFragments.split(small,token(1)).get(0));
        assertThrows(IllegalArgumentException.class,()->SyncFragments.split(new byte[73729],token(1)));
        var layer=new SyncFragments(()->0);
        assertThrows(IllegalArgumentException.class,()->layer.accept(CotRecordTest.id(2),token(2),new byte[1177]));
    }
    @Test void duplicatePiecesDoNotExtendTheTenSecondDeadline() {
        var clock=new AtomicLong();var layer=new SyncFragments(clock::get);var frames=SyncFragments.split(message(),token(1));
        assertNull(layer.accept(CotRecordTest.id(2),token(2),frames.get(0)));
        clock.set(9_000_000_000L);assertNull(layer.accept(CotRecordTest.id(2),token(2),frames.get(0)));
        clock.set(10_000_000_000L);layer.expire();assertEquals(0,layer.pendingCount());assertEquals(0,layer.reservedBytes());
        SyncFragments.Result result=null;
        for(int n=1;n<frames.size();n++)result=layer.accept(CotRecordTest.id(2),token(2),frames.get(n));
        assertNull(result);
    }
    @Test void differentPeerOrSessionCannotSupplyMissingPieces() {
        var layer=new SyncFragments(()->0);var frames=SyncFragments.split(message(),token(1));
        assertNull(layer.accept(CotRecordTest.id(2),token(2),frames.get(0)));
        for(int n=1;n<frames.size();n++)assertNull(layer.accept(CotRecordTest.id(3),token(2),frames.get(n)));
        for(int n=1;n<frames.size();n++)assertNull(layer.accept(CotRecordTest.id(2),token(3),frames.get(n)));
        assertEquals(3,layer.pendingCount());
    }
    @Test void rejectsInvalidHeaderBeforeAllocatingAndDoesNotEvictExistingTransfers() {
        var layer=new SyncFragments(()->0);byte[] first=SyncFragments.split(message(),token(1)).get(0);
        assertThrows(IllegalArgumentException.class,()->layer.accept(CotRecordTest.id(2),token(2),change(first,b->b.setTotalBytes(Integer.MAX_VALUE))));
        assertEquals(0,layer.reservedBytes());
        layer.accept(CotRecordTest.id(2),token(2),first);
        layer.accept(CotRecordTest.id(2),token(2),change(first,b->b.setTransferId(ByteString.copyFrom(token(3)))));
        int reserved=layer.reservedBytes();
        assertThrows(IllegalArgumentException.class,()->layer.accept(CotRecordTest.id(2),token(2),change(first,b->b.setTransferId(ByteString.copyFrom(token(4))))));
        assertEquals(2,layer.pendingCount());assertEquals(reserved,layer.reservedBytes());
        layer.close();assertEquals(0,layer.reservedBytes());
    }
    @Test void globalTransferCountIsBoundedAcrossPeers() {
        var layer=new SyncFragments(()->0);byte[] first=SyncFragments.split(message(),token(1)).get(0);
        for(int n=0;n<8;n++)layer.accept(CotRecordTest.id(n),token(2),first);
        assertEquals(8,layer.pendingCount());assertTrue(layer.reservedBytes()<=576*1024);
        assertThrows(IllegalArgumentException.class,()->layer.accept(CotRecordTest.id(9),token(2),first));
    }
    @Test void inconsistentOrChangedPiecesDiscardTheTransferWithoutDelivering() {
        var layer=new SyncFragments(()->0);var frames=SyncFragments.split(message(),token(1));byte[] first=frames.get(0);
        layer.accept(CotRecordTest.id(2),token(2),first);
        assertThrows(IllegalArgumentException.class,()->layer.accept(CotRecordTest.id(2),token(2),change(first,b->b.setDigest(ByteString.copyFrom(new byte[32])))));
        assertEquals(0,layer.pendingCount());
        layer.accept(CotRecordTest.id(2),token(2),first);
        assertThrows(IllegalArgumentException.class,()->layer.accept(CotRecordTest.id(2),token(2),change(first,b->{byte[] bytes=b.getPayload().toByteArray();bytes[0]^=1;b.setPayload(ByteString.copyFrom(bytes));})));
        assertEquals(0,layer.pendingCount());
    }
    @Test void alteredPayloadCannotPassTheWholeMessageDigest() {
        var layer=new SyncFragments(()->0);var frames=new ArrayList<>(SyncFragments.split(message(),token(1)));
        frames.set(0,change(frames.get(0),b->{byte[] bytes=b.getPayload().toByteArray();bytes[0]^=1;b.setPayload(ByteString.copyFrom(bytes));}));
        for(int n=0;n<frames.size()-1;n++)assertNull(layer.accept(CotRecordTest.id(2),token(2),frames.get(n)));
        assertThrows(IllegalArgumentException.class,()->layer.accept(CotRecordTest.id(2),token(2),frames.get(frames.size()-1)));
        assertEquals(0,layer.pendingCount());
    }
    @Test void completedTransfersReplayOnlySavedRepliesOncePerSecondAndValidateHeaders() {
        var clock=new AtomicLong();var layer=new SyncFragments(clock::get);var frames=SyncFragments.split(message(),token(1));
        SyncFragments.Result result=null;for(byte[] frame:frames)result=layer.accept(CotRecordTest.id(2),token(2),frame);
        assertNotNull(result);byte[] ack=SyncWire.ack(SyncWire.decodeRecord(result.message()));
        layer.remember(result,List.of(ack));result.close();
        assertNull(layer.accept(CotRecordTest.id(2),token(2),frames.get(0)));
        clock.set(1_000_000_000L);var repeated=layer.accept(CotRecordTest.id(2),token(2),frames.get(0));
        assertNotNull(repeated);assertNull(repeated.message());assertArrayEquals(ack,repeated.replies().get(0));repeated.close();
        assertNull(layer.accept(CotRecordTest.id(2),token(2),frames.get(1)));
        assertEquals(0,layer.pendingCount());
        assertThrows(IllegalArgumentException.class,()->layer.accept(CotRecordTest.id(2),token(2),change(frames.get(0),b->b.setDigest(ByteString.copyFrom(new byte[32])))));
        clock.set(10_000_000_000L);layer.expire();assertEquals(0,layer.completedCount());
        assertNull(layer.accept(CotRecordTest.id(2),token(2),frames.get(0)));assertEquals(1,layer.pendingCount());
    }
    @Test void persistenceWaitKeepsOnlyAReceiptAfterThePlaintextResultIsClosed() {
        var clock=new AtomicLong();var layer=new SyncFragments(clock::get);var frames=SyncFragments.split(message(),token(1));
        SyncFragments.Result result=null;for(byte[] frame:frames)result=layer.accept(CotRecordTest.id(2),token(2),frame);
        assertNotNull(result);var receipt=layer.receipt(result);byte[] ack=SyncWire.ack(SyncWire.decodeRecord(result.message()));
        result.close();layer.remember(receipt,List.of(ack));clock.set(1_000_000_000L);
        try(var replay=layer.accept(CotRecordTest.id(2),token(2),frames.get(0))){assertArrayEquals(ack,replay.replies().get(0));}
    }
}
