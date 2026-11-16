// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.TransferResources;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RosterSummaryCacheTest {
    final AtomicLong time=new AtomicLong();
    final Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return Instant.ofEpochMilli(time.get());}};
    final byte[] group=new byte[32],session=new byte[16],peer=new byte[32];
    final TransferResources resources=new TransferResources();
    final ManagementPageAssembler assembler=new ManagementPageAssembler(group,clock,resources,true);
    List<ManagementPage> pages(int operation,ManagementPage.Kind kind,int size){
        byte[] id=new byte[16];id[0]=(byte)operation;byte[] body=new byte[size];Arrays.fill(body,(byte)7);
        return ManagementPage.split(kind,id,group,body,0);
    }
    void hold(byte[] sender,List<ManagementPage> pages){
        for(var page:pages){var result=assembler.receive(sender,session,1,page);
            if(result.completed()!=null)try(var completed=result.completed()){
                byte[] body=completed.data();try{assembler.retryRosterSummary(sender,session,1,page,body,time.get());}finally{Crypto.wipe(body);}
            }
        }
    }
    List<byte[]> retained()throws Exception{
        var field=ManagementPageAssembler.class.getDeclaredField("completed");field.setAccessible(true);
        var values=(Collection<?>)field.get(assembler);var bodies=new ArrayList<byte[]>();
        for(var record:values){var body=record.getClass().getDeclaredField("summaryBody");body.setAccessible(true);var value=(byte[])body.get(record);if(value!=null)bodies.add(value);}
        return bodies;
    }
    @Test void eightRecordLimitAndOneSummaryPerPeerPreserveOtherKindAssembly()throws Exception{
        var first=pages(1,ManagementPage.Kind.ROSTER_SUMMARY,65536);hold(peer,first);byte[] original=retained().get(0);
        assertEquals(ManagementPageAssembler.Status.REJECTED,assembler.receive(peer,session,1,pages(2,ManagementPage.Kind.ROSTER_SUMMARY,2049).get(0)).status());
        assertSame(original,retained().get(0));assertEquals(0,resources.reservedBytes());
        assertEquals(ManagementPageAssembler.Status.INCOMPLETE,assembler.receive(peer,session,1,pages(3,ManagementPage.Kind.REVOCATION,2049).get(0)).status());
        for(int n=1;n<=8;n++){byte[] other=new byte[32];other[0]=(byte)n;hold(other,pages(1,ManagementPage.Kind.ROSTER_SUMMARY,2049));}
        assertEquals(8,retained().size());assertArrayEquals(new byte[original.length],original);
        assembler.clear();assertTrue(retained().isEmpty());assertEquals(0,resources.reservedBytes());
    }
    @Test void retransmissionsKeepOriginalProgressDeadlineAndCheckExactPage()throws Exception{
        var pages=pages(1,ManagementPage.Kind.ROSTER_SUMMARY,2049);hold(peer,pages);byte[] body=retained().get(0);var last=pages.get(pages.size()-1);
        byte[] changed=last.data();changed[0]^=1;
        var wrong=new ManagementPage(last.kind(),last.operationId(),last.group(),last.objectDigest(),last.totalBytes(),last.pageIndex(),last.pageCount(),changed,last.totalEntries());
        assertEquals(ManagementPageAssembler.Status.REJECTED,assembler.receive(peer,session,1,wrong).status());
        time.set(29999);try(var completed=assembler.receive(peer,session,1,last).completed()){
            assertNotNull(completed);byte[] copy=completed.data();try{assembler.retryRosterSummary(peer,session,1,last,copy,time.get());}finally{Crypto.wipe(copy);}
        }
        time.set(30000);assembler.poll();assertArrayEquals(new byte[body.length],body);
        assertEquals(ManagementPageAssembler.Status.REJECTED,assembler.receive(peer,session,1,last).status());
    }
    @Test void totalDeadlineStillStartsAtFirstPage()throws Exception{
        var pages=pages(1,ManagementPage.Kind.ROSTER_SUMMARY,2049);
        assembler.receive(peer,session,1,pages.get(0));
        for(int n=20000;n<=220000;n+=20000){time.set(n);assembler.receive(peer,session,1,pages.get(0));}
        time.set(239000);
        for(int n=1;n<pages.size();n++){
            var page=pages.get(n);var result=assembler.receive(peer,session,1,page);
            if(result.completed()!=null)try(var completed=result.completed()){
                byte[] copy=completed.data();try{assembler.retryRosterSummary(peer,session,1,page,copy,time.get());}finally{Crypto.wipe(copy);}
            }
        }
        byte[] body=retained().get(0);time.set(240000);assembler.poll();assertArrayEquals(new byte[body.length],body);
    }
    @Test void successRejectionForgetCloseAndAuthorityLossWipeRetainedBody()throws Exception{
        for(int reason=0;reason<6;reason++){
            var pages=pages(reason+1,ManagementPage.Kind.ROSTER_SUMMARY,2049);hold(peer,pages);byte[] body=retained().get(0);var last=pages.get(pages.size()-1);
            switch(reason){
                case 0->assertNotNull(assembler.confirmAfter(peer,session,1,last,()->{}));
                case 1->assembler.reject(peer,session,1,last);
                case 2->assembler.forget(peer);
                case 3->assembler.clearRosterSummaryRetries();
                case 4->assembler.pruneRosterSummaryRetries((p,s,g)->false);
                default->assertThrows(IllegalStateException.class,()->assembler.pruneRosterSummaryRetries((p,s,g)->{throw new IllegalStateException();}));
            }
            assertArrayEquals(new byte[body.length],body);assembler.clear();
        }
    }
    @Test void bindingRecheckMayReleaseRecordsWithoutLeavingBodies()throws Exception{
        hold(peer,pages(1,ManagementPage.Kind.ROSTER_SUMMARY,2049));
        byte[] other=peer.clone();other[0]=1;hold(other,pages(1,ManagementPage.Kind.ROSTER_SUMMARY,2049));
        var bodies=retained();
        assembler.pruneRosterSummaryRetries((p,s,g)->{assembler.clear();return false;});
        for(var body:bodies)assertArrayEquals(new byte[body.length],body);
        assertTrue(retained().isEmpty());
    }
}
