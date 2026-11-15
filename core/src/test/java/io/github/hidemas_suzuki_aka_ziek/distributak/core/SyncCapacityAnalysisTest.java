// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyncCapacityAnalysisTest {
    @Test void worstAcceptedUidsCatchUpWithinThirtySecondsWithEarlySaveAndSend()throws Exception {
        var time=new AtomicLong();var queue=new ArrayDeque<Message>();var nodes=new CotSync[2];
        var saved=new SyncState[]{initial(256),new SyncState(new byte[32],CotRecordTest.id(2))};
        var clock=Clock.fixed(Instant.ofEpochMilli(CotRecordTest.NOW),ZoneOffset.UTC);
        try{
            for(int n=0;n<2;n++){
                int index=n;nodes[n]=new CotSync(CotRecordTest.id(n+1),saved[n],clock,time::get,next->saved[index]=next,
                    (peer,session,wire)->{queue.add(new Message(index,peer[0]-1,session.clone(),wire.clone()));return true;},r->{},new SecureRandom(),0);
            }
            byte[] session=SyncFragmentsTest.token(1);nodes[0].connected(CotRecordTest.id(2),session);nodes[1].connected(CotRecordTest.id(1),session);
            for(int step=0;step<120&&saved[1].records().size()<4096;step++){
                time.set(step*250_000_000L);for(var node:nodes)node.poll();
                int handled=0;for(Message message;(message=queue.poll())!=null;){assertTrue(++handled<100000);nodes[message.to].receive(CotRecordTest.id(message.from+1),message.session,message.wire);}
            }
            assertEquals(4096,saved[1].records().size());assertTrue(time.get()<CotSync.CATCHUP_NANOS);
            for(var node:nodes)assertEquals(0,node.statistics().failed());
        } finally {for(var node:nodes)if(node!=null)node.close();}
    }
    static SyncState initial(int uidBytes)throws Exception {
        var base=SyncSchema.SyncSnapshot.parseFrom(new SyncState(new byte[32],CotRecordTest.id(1)).encode()).toBuilder();
        for(int n=0;n<4096;n++){
            String uid=String.format("%04d",n)+"x".repeat(uidBytes-4);
            var item=CotRecord.tombstone(uid,CotRecordTest.NOW,CotRecordTest.id(1),0);
            base.addRecords(SyncSchema.SyncStoredRecord.newBuilder().setEnvelope(SyncWire.parse(SyncWire.encode(item))).setTombstoneUntil(CotRecordTest.NOW+CotXml.MAX_STALE_MILLIS));
        }
        return SyncState.decode(base.build().toByteArray(),new byte[32],CotRecordTest.id(1));
    }
    @Test void report4096EntryInventoryBudgetsAndTimerCatchupWithCurrentLimits()throws Exception {
        var report=new StringBuilder("PC capacity analysis; current limits peer=8MiB total=32MiB; decoded baseline without spill\nuid_bytes,entries,page_wire_bytes,request_wire_bytes,offer_accounted,receiver_accounted,last_request_charge,refused_page\n");
        SyncState shortState=null;
        for(int length:new int[]{4,9,256}){
            var state=initial(length);if(length==4)shortState=state;
            var records=state.records();long pageBytes=0,requestBytes=0;int lastRequestCharge=0;
            var receiver=new SyncInventory.Receiver();int refused=-1;String offered;
            try{offered=Integer.toString(SyncInventory.offer(state,new byte[16],CotRecordTest.NOW).retainedBytes());}
            catch(IllegalArgumentException e){offered="REFUSED";}
            for(int page=0;page<64;page++){
                var inventory=SyncSchema.SyncInventory.newBuilder().setSnapshotId(SyncWire.bytes(new byte[16])).setPage(page).setLast(page==63);
                var request=SyncSchema.SyncRequest.newBuilder().setSnapshotId(SyncWire.bytes(new byte[16])).setPage(page);
                for(int n=page*64;n<(page+1)*64;n++){var entry=SyncWire.entry(records.get(n));inventory.addEntries(entry);request.addWanted(entry);}
                byte[] wire=SyncWire.envelope().setInventory(inventory).build().toByteArray(),reply=SyncWire.envelope().setRequest(request).build().toByteArray();
                pageBytes+=wire.length;requestBytes+=reply.length;lastRequestCharge=3*reply.length+128+8*64;
                if(refused<0)try{receiver.accept(wire,e->true);}catch(IllegalArgumentException e){refused=page;}
                assertTrue(receiver.retainedBytes()<=SyncInventory.PEER_BYTES);
            }
            report.append(length).append(",4096,").append(pageBytes).append(',').append(requestBytes).append(',').append(offered).append(',').append(receiver.retainedBytes()).append(',').append(lastRequestCharge).append(',').append(refused).append('\n');
        }
        var time=new AtomicLong();var queue=new ArrayDeque<Message>();var nodes=new CotSync[2];var saved=new SyncState[]{shortState,new SyncState(new byte[32],CotRecordTest.id(2))};
        var clock=Clock.fixed(Instant.ofEpochMilli(CotRecordTest.NOW),ZoneOffset.UTC);
        try {
            for(int n=0;n<2;n++){
                int index=n;
                nodes[n]=new CotSync(CotRecordTest.id(n+1),saved[n],clock,time::get,next->saved[index]=next,
                    (peer,session,wire)->{queue.add(new Message(index,peer[0]-1,session.clone(),wire.clone()));return true;},r->{},new SecureRandom(),0);
            }
            byte[] session=SyncFragmentsTest.token(1);nodes[0].connected(CotRecordTest.id(2),session);nodes[1].connected(CotRecordTest.id(1),session);
            for(int step=0;step<=120;step++){
                time.set(step*250_000_000L);for(var node:nodes)node.poll();
                for(Message message;(message=queue.poll())!=null;)nodes[message.to].receive(CotRecordTest.id(message.from+1),message.session,message.wire);
                for(var node:nodes){assertTrue(node.statistics().pending()<=32);assertTrue(node.statistics().pendingBytes()<=1024*1024);}
            }
            report.append("timer_only_250ms_at_30s_received=").append(saved[1].records().size()).append("/4096, sender_failed=").append(nodes[0].statistics().failed()).append(", receiver_failed=").append(nodes[1].statistics().failed()).append('\n');
        } finally {for(var node:nodes)if(node!=null)node.close();}
        Path path=Path.of("../../../../out/reviews/20261112-distributak-cot-sync/capacity-analysis-fix1.txt").toAbsolutePath().normalize();Files.createDirectories(path.getParent());Files.write(path,report.toString().getBytes(StandardCharsets.UTF_8));
    }
    private record Message(int from,int to,byte[] session,byte[] wire){@Override public String toString(){return "Capacity test message";}}
}
