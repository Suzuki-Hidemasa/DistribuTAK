// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecordTest.*;

class ManagedTransfersTest {
    final DhtId peer=DhtIdTest.id(70);
    final byte[] session=new byte[16],request=new byte[16];
    final AtomicLong now=new AtomicLong();
    final TransferResources resources=new TransferResources();
    final List<byte[]> acks=new ArrayList<>(),legacy=new ArrayList<>();
    final List<ManagedTransferContext> contexts=new ArrayList<>();
    final List<ManagedTransferResult> results=new ArrayList<>();
    ManagedTransferResult answer=ManagedTransferResult.ACCEPTED;
    boolean fail;
    final DhtTransfers receiver=new DhtTransfers(GROUP,(p,s,d)->{acks.add(d);return true;},now::get,new Random(1),
            (p,k,d)->legacy.add(d),(p,r)->true,DhtTransfers.Limits.defaults(),resources,new ManagedTransferSink(){
        public ManagedTransferResult accept(ManagedTransferContext context,ManagedDhtRecord record){
            assertEquals(1,acks.size());assertEquals(0,resources.active());
            contexts.add(context);assertEquals(record.key(),context.key());
            if(fail)throw new IllegalStateException("Sink failed");return answer;
        }
        public void completed(DhtId p,byte[] r,ManagedTransferResult result){
            assertEquals(peer,p);assertArrayEquals(request,r);results.add(result);
        }
    });
    DhtWire.Message piece(byte[] data,int index){
        return DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,request,DhtTransfers.digestOf(data),data.length,
                index,(data.length+1023)/1024,Arrays.copyOfRange(data,index*1024,Math.min(data.length,(index+1)*1024))));
    }
    void deliver(byte[] data){for(int i=0;i<(data.length+1023)/1024;i++){acks.clear();receiver.receive(peer,session,9,piece(data,i));}}
    @Test void onlyTheVerifiedWholeRecordReachesTheManagedSinkWithItsContext(){
        var record=revocationRecord(1,1,1,NOW,80);byte[] data=record.encode();
        receiver.receive(peer,session,9,piece(data,0));assertTrue(contexts.isEmpty());assertTrue(results.isEmpty());
        for(int i=1;i<(data.length+1023)/1024;i++){acks.clear();receiver.receive(peer,session,9,piece(data,i));}
        assertEquals(List.of(ManagedTransferResult.ACCEPTED),results);assertTrue(legacy.isEmpty());
        assertEquals(1,contexts.size());var ctx=contexts.get(0);
        assertEquals(peer,ctx.peer());assertEquals(9,ctx.generation());assertArrayEquals(session,ctx.sessionId());
        assertArrayEquals(request,ctx.requestId());assertEquals(record.key(),ctx.key());
        assertEquals(0,receiver.reservedBytes());
    }
    @Test void aDifferentGenerationCannotJoinAnAssemblyOrReceiveItsCompletedAck(){
        byte[] data=revocationRecord(1,1,1,NOW,40).encode();
        receiver.receive(peer,session,9,piece(data,0));acks.clear();
        receiver.receive(peer,session,10,piece(data,1));assertTrue(acks.isEmpty());assertTrue(contexts.isEmpty());
        deliver(data);assertEquals(1,contexts.size());acks.clear();
        receiver.receive(peer,session,10,piece(data,0));assertTrue(acks.isEmpty());
        receiver.receive(peer,session,9,piece(data,0));assertEquals(1,acks.size());
    }
    @Test void malformedOrBadlySignedWholeRecordsAreRejectedAfterDeliveryAck(){
        byte[] data=revocationRecord(1,1,1,NOW,0).encode();data[data.length-1]^=1;
        deliver(data);assertTrue(contexts.isEmpty());assertTrue(legacy.isEmpty());
        assertEquals(List.of(ManagedTransferResult.REJECTED),results);assertEquals(1,acks.size());assertEquals(0,resources.active());
    }
    @Test void sinkRejectionAndExceptionRemainSeparateFromDeliveryAndReleaseReservations(){
        answer=ManagedTransferResult.REJECTED;deliver(revocationRecord(1,1,1,NOW,0).encode());
        assertEquals(List.of(ManagedTransferResult.REJECTED),results);assertEquals(1,acks.size());
        receiver.clear();results.clear();fail=true;deliver(revocationRecord(2,2,1,NOW,0).encode());
        assertEquals(List.of(ManagedTransferResult.FAILED),results);assertEquals(0,resources.active());assertEquals(0,receiver.reservedBytes());
    }
    @Test void theLegacyEntryStillUsesOnlyTheLegacySink(){
        byte[] data=new byte[]{1,2,3};receiver.receive(peer,session,piece(data,0));
        assertEquals(1,legacy.size());assertArrayEquals(data,legacy.get(0));assertTrue(contexts.isEmpty());assertTrue(results.isEmpty());
    }
    @Test void allFiveManagedKindsUseTheNewSinkButDiscoveryNeverDoes(){
        var announcement=io.github.hidemas_suzuki_aka_ziek.distributak.core.KeyAnnouncement.issue(GROUP,secret(1),8,NOW,3,digest(4),digest(6),2,digest(5));
        var records=List.of(
                ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,GROUP,secret(1),admins(3,NOW,1,2),1,3,digest(5),NOW,null),
                revocationRecord(1,1,1,NOW,0),
                ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(1),wrapped(6,NOW,DhtIdTest.id(55).bytes()),1,3,digest(5),NOW,certificate()),
                ManagedDhtRecord.issue(DhtKeys.ADMIN_HISTORY,GROUP,secret(1),admins(2,NOW,1,2),1,2,digest(5),NOW,null),
                ManagedDhtRecord.issue(GROUP,secret(1),announcement,1,2,digest(5),NOW));
        for(var record:records){
            receiver.clear();deliver(record.encode());assertEquals(ManagedTransferResult.ACCEPTED,results.get(results.size()-1));
        }
        assertEquals(5,contexts.size());assertTrue(legacy.isEmpty());
        receiver.clear();deliver(DiscoveryRecordTest.record(1,1,NOW).encode());
        assertEquals(5,contexts.size());assertEquals(ManagedTransferResult.REJECTED,results.get(results.size()-1));
    }
}
