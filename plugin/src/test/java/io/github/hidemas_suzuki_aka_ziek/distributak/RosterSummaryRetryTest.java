// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class RosterSummaryRetryTest {
    static List<ManagementPage> summary(RosterExchangeTest.Pair p){
        var entries=new ArrayList<MemberDirectory.Summary>();
        for(int n=0;n<32;n++)entries.add(new MemberDirectory.Summary(StoredUpdatesTest.key(n),StorageGroupTest.NOW,new byte[32]));
        var summary=new RosterMessage.Summary(32,new byte[32],new byte[0],entries);
        byte[] operation=new byte[16];operation[0]=88;
        return ManagementPage.split(ManagementPage.Kind.ROSTER_SUMMARY,operation,p.a.groupId,summary.encode(),32);
    }
    static ManagementPage busy(RosterExchangeTest.Pair p){
        byte[] operation=new byte[16];operation[0]=89;var body=new RosterMessage.Batch(List.of(),true);
        assertEquals(ManagementPageSender.Offer.ACCEPTED,p.ra.offerRoster(p.b.id(),ManagementPage.Kind.ROSTER,operation,body.encode(),0));
        p.ra.poll(List.of());var page=ManagementPage.decodeEnvelope(p.frames.remove().wire);p.frames.clear();return page;
    }
    static void free(RosterExchangeTest.Pair p,ManagementPage page){
        p.ra.receive(p.b.id(),p.sa.sessionId(p.b.id()),new ManagementPageAck(p.a.groupId,page.operationId(),page.objectDigest(),new int[]{0},true).envelope(),p.now);
    }
    static void receive(RosterExchangeTest.Pair p,ManagementPage page){p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);}
    static boolean complete(RosterExchangeTest.Pair p){return p.frames.stream().filter(f->ManagementEnvelopeFields.field(f.wire)==ManagementEnvelopeFields.PAGE_ACK)
            .map(f->ManagementPageAck.decodeEnvelope(f.wire)).anyMatch(ManagementPageAck::complete);}
    @Test public void retransmittingOnlyFinalSummaryPageRetriesBusyResponseAndCompletes()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            int saves=p.da.directorySaves;long revision=p.xa.directory().revision();
            var occupied=busy(p);var pages=summary(p);assertTrue(pages.size()>1);
            for(var page:pages){p.now+=1000;receive(p,page);}
            assertFalse(complete(p));p.frames.clear();free(p,occupied);p.now+=1000;
            receive(p,pages.get(pages.size()-1));assertTrue(complete(p));p.ra.poll(List.of());
            assertTrue(p.frames.stream().anyMatch(f->ManagementEnvelopeFields.field(f.wire)==ManagementEnvelopeFields.DIRECTORY_PAGE));
            assertEquals(saves,p.da.directorySaves);assertEquals(revision,p.xa.directory().revision());
        }
    }
    @Test public void finalPageRetriesDoNotExtendOriginalThirtySecondDeadline()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var occupied=busy(p);var pages=summary(p);
            for(var page:pages){p.now+=1000;receive(p,page);}long completed=p.now;
            p.frames.clear();p.now=completed+29999;receive(p,pages.get(pages.size()-1));assertFalse(complete(p));
            free(p,occupied);p.frames.clear();p.now=completed+30000;receive(p,pages.get(pages.size()-1));assertFalse(complete(p));
            p.ra.poll(List.of());assertTrue(p.frames.isEmpty());
        }
    }
    @Test public void retriedSummaryAckKeepsOriginalTotalDeadlineAfterRejectedOtherSummary()throws Exception{
        try(var p=new RosterExchangeTest.Pair(true)){
            busy(p);var pages=summary(p);p.now=1000;receive(p,pages.get(0));
            for(int n=21000;n<=221000;n+=20000){p.now=n;receive(p,pages.get(0));}
            p.now=240000;for(int n=1;n<pages.size();n++)receive(p,pages.get(n));
            assertFalse(complete(p));p.frames.clear();p.now=240500;p.ra.poll(List.of());
            var first=pages.get(0);byte[] operation=first.operationId();operation[0]^=1;
            var other=new ManagementPage(first.kind(),operation,first.group(),first.objectDigest(),first.totalBytes(),first.pageIndex(),first.pageCount(),first.data(),first.totalEntries());
            receive(p,other);p.now=240999;RosterReviewFixTest.fillAckBudget(p);
            receive(p,pages.get(pages.size()-1));assertTrue(p.frames.isEmpty());
            p.now=241999;p.xa.poll(List.of(p.b.id()));assertTrue(p.frames.isEmpty());
        }
    }
    @Test public void authorityLossAndCloseDiscardPendingSummaryEvenWhenAuthorityReturns()throws Exception{
        for(boolean close:new boolean[]{false,true})try(var p=new RosterExchangeTest.Pair()){
            var occupied=busy(p);var pages=summary(p);
            for(var page:pages){p.now+=1000;receive(p,page);}p.frames.clear();
            RosterExchange replacement=null;
            if(close){p.xa.close();replacement=new RosterExchange(p.a,p.sa,p.ca,p.deadlines,p.da,p.ra);}
            else{
                var bindings=p.a.state.administrators().bindings();var local=bindings.stream().filter(b->Crypto.equal(b.memberId(),p.a.id())).findFirst().orElseThrow();
                p.a.state.acceptAdministrators(AdminRecords.administrators(p.a.groupId,2,StorageGroupTest.NOW,List.of(local),p.a.administratorSecret),v->fail());
                p.xa.poll(List.of(p.b.id()));
                p.a.state.acceptAdministrators(AdminRecords.administrators(p.a.groupId,3,StorageGroupTest.NOW,bindings,p.a.administratorSecret),v->fail());
            }
            free(p,occupied);p.now+=1000;var last=pages.get(pages.size()-1);
            if(replacement==null)receive(p,last);else replacement.receive(p.b.id(),p.sa.sessionId(p.b.id()),last.envelope(),p.now);
            assertFalse(complete(p));if(replacement!=null)replacement.close();
        }
    }
}
