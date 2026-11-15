// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.ByteString;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyncInventoryTest {
    @Test void fourThousandNinetySixEntriesAndPageSixtyThreePassButPageSixtyFourFails(){
        var offer=offer(4096);assertEquals(64,offer.pageCount());var receiver=new SyncInventory.Receiver();
        for(int page=0;page<64;page++)receiver.accept(offer.page(page),entry->false);
        assertTrue(receiver.complete());assertEquals(4096,receiver.entries().size());
        var last=SyncWire.parse(offer.page(63));byte[] tooFar=last.toBuilder().setInventory(last.getInventory().toBuilder().setPage(64)).build().toByteArray();
        assertThrows(IllegalArgumentException.class,()->new SyncInventory.Receiver().accept(tooFar,e->false));
        assertThrows(IllegalArgumentException.class,()->offer.page(64));
    }
    static SyncInventory.Offer offer(int count) {
        var state=SyncStateTest.state();
        for(int n=0;n<count;n++)state.put(CotRecord.tombstone("item-"+n,CotRecordTest.NOW,CotRecordTest.id(1),0),CotRecordTest.NOW);
        return SyncInventory.offer(state,SyncFragmentsTest.token(1),CotRecordTest.NOW);
    }
    @Test void absenceCannotBeDecidedUntilEveryPageIncludingTheMiddleHasArrived() {
        var offer=offer(129);var receiver=new SyncInventory.Receiver();
        receiver.accept(offer.page(2),entry->true);receiver.accept(offer.page(0),entry->true);
        assertFalse(receiver.complete());assertThrows(IllegalStateException.class,()->receiver.knows("item-64"));
        receiver.accept(offer.page(1),entry->true);assertTrue(receiver.complete());assertEquals(129,receiver.entries().size());
        assertTrue(receiver.knows("item-64"));assertFalse(receiver.knows("absent"));
    }
    @Test void duplicatePagesReturnTheOriginalRequestEvenIfLocalStateHasChanged() {
        var offer=offer(64);var receiver=new SyncInventory.Receiver();
        byte[] first=receiver.accept(offer.page(0),entry->true);
        assertArrayEquals(first,receiver.accept(offer.page(0),entry->false));
        assertEquals(64,SyncWire.parse(first).getRequest().getWantedCount());
    }
    @Test void duplicateUidsAndInconsistentLastFlagsCannotChangeAnAcceptedInventory() {
        var offer=offer(65);var receiver=new SyncInventory.Receiver();receiver.accept(offer.page(0),entry->false);
        var second=SyncWire.parse(offer.page(1));
        var firstEntry=SyncWire.parse(offer.page(0)).getInventory().getEntries(0);
        byte[] duplicated=second.toBuilder().setInventory(second.getInventory().toBuilder().setEntries(0,firstEntry)).build().toByteArray();
        int bytes=receiver.retainedBytes();assertThrows(IllegalArgumentException.class,()->receiver.accept(duplicated,entry->true));
        assertFalse(receiver.complete());assertEquals(bytes,receiver.retainedBytes());
        receiver.accept(offer.page(1),entry->false);assertTrue(receiver.complete());
        byte[] changedLast=second.toBuilder().setInventory(second.getInventory().toBuilder().setLast(false)).build().toByteArray();
        assertThrows(IllegalArgumentException.class,()->receiver.accept(changedLast,entry->true));
    }
    @Test void lastPageCannotExcludeAnAlreadyReceivedHigherPage() {
        var offer=offer(65);var receiver=new SyncInventory.Receiver();
        receiver.accept(offer.page(1),entry->false);
        var zero=SyncWire.parse(offer.page(0));
        byte[] earlyLast=zero.toBuilder().setInventory(zero.getInventory().toBuilder().setLast(true)).build().toByteArray();
        assertThrows(IllegalArgumentException.class,()->receiver.accept(earlyLast,entry->true));
    }
    @Test void requestsMustMatchTheOfferedSnapshotPageVersionAndHash() {
        var offer=offer(65);var receiver=new SyncInventory.Receiver();byte[] request=receiver.accept(offer.page(0),entry->true);
        assertEquals(64,offer.request(request).size());
        var envelope=SyncWire.parse(request);var wanted=envelope.getRequest();
        byte[] wrongPage=envelope.toBuilder().setRequest(wanted.toBuilder().setPage(1)).build().toByteArray();
        assertThrows(IllegalArgumentException.class,()->offer.request(wrongPage));
        byte[] wrongHash=envelope.toBuilder().setRequest(wanted.toBuilder().setWanted(0,wanted.getWanted(0).toBuilder().setHash(ByteString.copyFrom(new byte[32])))).build().toByteArray();
        assertThrows(IllegalArgumentException.class,()->offer.request(wrongHash));
    }
    @Test void recordsAtHopSixteenAndExpiredRecordsAreNotAdvertised() {
        var state=SyncStateTest.state();state.put(CotRecordTest.record(CotRecordTest.NOW,1,16),CotRecordTest.NOW);
        assertEquals(0,SyncWire.parse(SyncInventory.offer(state,SyncFragmentsTest.token(1),CotRecordTest.NOW).page(0)).getInventory().getEntriesCount());
    }
    @Test void byteQuotaIsCheckedBeforeTheFirstPageChangesState() {
        var receiver=new SyncInventory.Receiver();
        assertThrows(IllegalArgumentException.class,()->receiver.accept(offer(64).page(0),entry->true,1));
        assertEquals(0,receiver.retainedBytes());assertFalse(receiver.complete());
    }
    @Test void changingTheSnapshotCannotRestartTheSameExchange() {
        var receiver=new SyncInventory.Receiver();var offer=offer(65);receiver.accept(offer.page(0),entry->true);
        var other=SyncWire.parse(offer.page(1));byte[] changed=other.toBuilder().setInventory(other.getInventory().toBuilder()
                .setSnapshotId(ByteString.copyFrom(SyncFragmentsTest.token(2)))).build().toByteArray();
        assertThrows(IllegalArgumentException.class,()->receiver.accept(changed,entry->true));assertFalse(receiver.complete());
    }
}
