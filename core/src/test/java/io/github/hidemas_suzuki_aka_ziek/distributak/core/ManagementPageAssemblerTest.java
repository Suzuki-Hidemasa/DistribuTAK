// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtId;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.TransferResources;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementPageAssembler.Status.*;

class ManagementPageAssemblerTest {
    static final class Time extends Clock {
        long now=1000;
        public ZoneId getZone(){return ZoneOffset.UTC;}
        public Clock withZone(ZoneId zone){return this;}
        public Instant instant(){return Instant.ofEpochMilli(now);}
    }
    final Time time=new Time();
    final byte[] group=new byte[32],peer=ManagementPageTest.bytes(32,1),session=new byte[16];
    final TransferResources resources=new TransferResources();
    final ManagementPageAssembler assembler=new ManagementPageAssembler(group,time,resources);
    List<ManagementPage> pages(int size){return ManagementPage.split(ManagementPage.Kind.REVOCATION,new byte[16],group,ManagementPageTest.bytes(size,2),65536);}
    ManagementPageAssembler.Result receive(ManagementPage page){return assembler.receive(peer,session,1,page);}
    ManagementPage change(ManagementPage p,ManagementPage.Kind kind,byte[] operation,byte[] g,byte[] digest,int total,int index,int count,byte[] data,int entries){
        return new ManagementPage(kind,operation,g,digest,total,index,count,data,entries);
    }
    @Test void rosterPruningDoesNotDiscardAnAnnouncementWaitingForItsDependency() {
        var assembler=new ManagementPageAssembler(group,time,resources,true);
        var page=ManagementPage.split(ManagementPage.Kind.ANNOUNCEMENT,new byte[16],group,new byte[100],0).get(0);
        try(var completed=assembler.receive(peer,session,1,page).completed()){
            assertNotNull(completed);assembler.retryAnnouncement(peer,session,1,page,completed.data(),time.millis());
        }
        assembler.pruneRosterSummaryRetries((p,s,g)->false);
        try(var completed=assembler.receive(peer,session,1,page).completed()){assertNotNull(completed);}
    }
    @Test void outOfOrderPagesYieldExactlyTheWholeObjectAndNeverAPartialValue() {
        var pages=pages(2050);
        assertEquals(INCOMPLETE,receive(pages.get(2)).status());assertEquals(2050,resources.reservedBytes());
        assertNull(receive(pages.get(0)).completed());
        assertEquals(DUPLICATE,receive(pages.get(2)).status());
        var result=receive(pages.get(1));assertEquals(COMPLETE,result.status());
        var completed=result.completed();assertArrayEquals(ManagementPageTest.bytes(2050,2),completed.data());
        assertEquals(ManagementPage.Kind.REVOCATION,completed.kind());assertEquals(65536,completed.totalEntries());
        assertArrayEquals(group,completed.group());assertArrayEquals(new byte[16],completed.operationId());
        assertArrayEquals(pages.get(0).objectDigest(),completed.objectDigest());
        completed.data()[0]^=1;assertArrayEquals(ManagementPageTest.bytes(2050,2),completed.data());
        assertEquals(0,resources.reservedBytes());assertEquals(0,resources.active());assertEquals(0,assembler.active());
        assembler.clear();assertEquals(0,resources.reservedBytes());
    }
    @Test void conflictingContentsForTheSameIndexDiscardTheEntireAssemblyAndReleaseOnce() {
        var p=pages(2050).get(0);assertEquals(INCOMPLETE,receive(p).status());
        byte[] different=p.data();different[0]^=1;
        var conflict=change(p,p.kind(),p.operationId(),p.group(),p.objectDigest(),p.totalBytes(),0,p.pageCount(),different,p.totalEntries());
        var corrupt=receive(conflict);assertEquals(CORRUPT,corrupt.status());assertNull(corrupt.ack());assertEquals(0,assembler.active());
        assertEquals(0,resources.reservedBytes());assembler.forget(peer);assembler.clear();
        assertEquals(0,resources.reservedBytes());assertEquals(0,resources.active());
    }
    @Test void everyMetadataOrSessionMismatchIsRefusedWithoutReplacingTheOriginal() {
        var all=pages(2050);var p=all.get(1);assertEquals(INCOMPLETE,receive(all.get(0)).status());
        var other=ManagementPageTest.bytes(32,9);
        for(var changed:List.of(
                change(p,ManagementPage.Kind.ROSTER,p.operationId(),group,p.objectDigest(),2050,1,3,p.data(),32),
                change(p,p.kind(),ManagementPageTest.bytes(16,9),group,p.objectDigest(),2050,1,3,p.data(),65536),
                change(p,p.kind(),p.operationId(),other,p.objectDigest(),2050,1,3,p.data(),65536),
                change(p,p.kind(),p.operationId(),group,other,2050,1,3,p.data(),65536),
                change(p,p.kind(),p.operationId(),group,p.objectDigest(),2051,1,3,p.data(),65536),
                change(p,p.kind(),p.operationId(),group,p.objectDigest(),4096,1,4,p.data(),65536),
                change(p,p.kind(),p.operationId(),group,p.objectDigest(),2050,1,3,p.data(),65535)))
            assertEquals(REJECTED,receive(changed).status());
        assertEquals(REJECTED,assembler.receive(peer,ManagementPageTest.bytes(16,8),1,p).status());
        assertEquals(REJECTED,assembler.receive(peer,session,2,p).status());
        assertEquals(2050,resources.reservedBytes());assertEquals(1,assembler.active());
        assertEquals(INCOMPLETE,receive(all.get(1)).status());assertEquals(COMPLETE,receive(all.get(2)).status());
        assertEquals(0,resources.reservedBytes());
    }
    @Test void aDigestMismatchNeverYieldsACompleteObject() {
        var p=pages(1).get(0);
        var wrong=change(p,p.kind(),p.operationId(),group,new byte[32],1,0,1,p.data(),p.totalEntries());
        var result=receive(wrong);assertEquals(CORRUPT,result.status());assertNull(result.completed());assertNull(result.ack());
        assertEquals(0,resources.active());assertEquals(0,resources.reservedBytes());
    }
    @Test void matchingDuplicatesRestartTheThirtySecondProgressDeadline() {
        var p=pages(2048).get(0);assertEquals(INCOMPLETE,receive(p).status());
        time.now+=29999;assertEquals(DUPLICATE,receive(p).status());
        time.now+=29999;assembler.poll();assertEquals(1,assembler.active());assertEquals(2048,resources.reservedBytes());
        time.now++;assembler.poll();assertEquals(0,assembler.active());assertEquals(0,resources.reservedBytes());
    }
    @Test void realProgressCannotExtendThe240SecondTotalDeadline() {
        var all=pages(64*1024);receive(all.get(0));
        for(int i=1;i<=9;i++){time.now+=25000;assertEquals(INCOMPLETE,receive(all.get(i)).status());}
        time.now+=14999;assembler.poll();assertEquals(1,assembler.active());
        time.now++;assembler.poll();assertEquals(0,assembler.active());assertEquals(0,resources.reservedBytes());
    }
    @Test void backwardClockForgetAndClearReleaseOnlyTheirOwnReservations() {
        var all=pages(2048);receive(all.get(0));time.now--;assembler.poll();
        assertEquals(0,assembler.active());assertEquals(0,resources.reservedBytes());
        var rejected=receive(all.get(0));assertEquals(REJECTED,rejected.status());assertNull(rejected.ack());
        assembler.forget(peer);assertEquals(INCOMPLETE,receive(all.get(0)).status());
        var external=resources.acquire(new DhtId(ManagementPageTest.bytes(32,99)),100);
        assertNotNull(external);assembler.clear();assembler.clear();
        assertEquals(100,resources.reservedBytes());assertEquals(1,resources.active());
        external.close();external.close();assertEquals(0,resources.reservedBytes());
        receive(all.get(0));assembler.forget(peer);assembler.forget(peer);assertEquals(0,resources.active());
    }
    @Test void onePerPeerTwoOverallAndEightMebibytesAreSharedAndNeverDoubleReserved() {
        var p=pages(2048).get(0);receive(p);
        var second=new ManagementPageAssembler(group,time,resources);
        assertEquals(REJECTED,second.receive(peer,session,1,p).status());
        assertEquals(INCOMPLETE,second.receive(ManagementPageTest.bytes(32,3),session,1,p).status());
        assertEquals(REJECTED,assembler.receive(ManagementPageTest.bytes(32,4),session,1,p).status());
        assertEquals(2,resources.active());assertEquals(4096,resources.reservedBytes());
        assembler.clear();second.clear();assertEquals(0,resources.active());
        var large=resources.acquire(new DhtId(peer),7L*1024*1024);assertNotNull(large);
        assertNull(resources.acquire(new DhtId(ManagementPageTest.bytes(32,3)),2L*1024*1024));
        assertEquals(1,resources.active());assertEquals(7L*1024*1024,resources.reservedBytes());
        large.close();large.close();assertEquals(0,resources.reservedBytes());
    }
}
