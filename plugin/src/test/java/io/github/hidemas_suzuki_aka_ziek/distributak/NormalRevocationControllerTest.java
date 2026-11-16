// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Test;
import static org.junit.Assert.*;

public class NormalRevocationControllerTest {
    static final class Pair implements AutoCloseable {
        final LanControllerHarness a,m;
        Pair()throws Exception{
            var disks=LanProofRenewalTest.legacyPair();
            for(var disk:disks){disk.enableSix();try(var group=disk.load(LanControllerHarness.CLOCK)){disk.save(group);}}
            a=new LanControllerHarness(disks[0],CotPort.NONE,()->0);
            m=new LanControllerHarness(disks[1],CotPort.NONE,()->0);
            long end=System.nanoTime()+5_000_000_000L;
            while(a.endpoint().sessionId(group(m).id())==null||m.endpoint().sessionId(group(a).id())==null){
                if(System.nanoTime()>end)throw new AssertionError("test session setup timed out");
                a.offset.addAndGet(100_000_000);m.offset.addAndGet(100_000_000);a.tick();m.tick();Thread.sleep(5);
            }
            a.drain();m.drain();
        }
        ManagementPage page(int operation){
            var admin=group(a);byte[] id=new byte[16];id[0]=(byte)operation;
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,admin.groupId,2,LanControllerHarness.CLOCK.millis(),List.of(StoredUpdatesTest.key(81)),admin.administratorSecret);
            return ManagementPage.split(ManagementPage.Kind.REVOCATION,id,admin.groupId,body.encode(),1).get(0);
        }
        void deliver(ManagementPage page)throws Exception{receiver(m).receive(group(a).id(),m.endpoint().sessionId(group(a).id()),page.envelope());}
        public void close(){a.close();m.close();}
    }
    static LanGroup group(LanControllerHarness h){try{return LanBehaviourWiringTest.group(h);}catch(Exception e){throw new AssertionError(e);}}
    static CorePersistenceCoordinator coordinator(LanControllerHarness h){try{return (CorePersistenceCoordinator)LanControllerHarness.field(h.controller,"persistence");}catch(Exception e){throw new AssertionError(e);}}
    static SyncInbox inbox(LanControllerHarness h)throws Exception{return (SyncInbox)LanControllerHarness.field(h.controller,"inbox");}
    static UdpEndpoint.Receiver receiver(LanControllerHarness h)throws Exception{
        var method=LanController.class.getDeclaredMethod("receiver",long.class);method.setAccessible(true);
        long epoch=((AtomicLong)LanControllerHarness.field(h.controller,"generation")).get();return (UdpEndpoint.Receiver)method.invoke(h.controller,epoch);
    }
    @Test public void normalReceptionCommitsVersionSixWithoutReplacingSession()throws Exception{
        try(var p=new Pair()){
            byte[] before=p.m.endpoint().sessionId(group(p.a).id());p.deliver(p.page(1));p.m.drain();
            assertEquals(2,group(p.m).state.revocations().version());assertArrayEquals(before,p.m.endpoint().sessionId(group(p.a).id()));
            assertEquals(StopMarker.Status.CLEAR,p.m.disk.stopMarker.marker().inspect().status());
            try(var loaded=p.m.disk.load(LanControllerHarness.CLOCK)){assertEquals(2,loaded.state.revocations().version());}
        }
    }
    @Test public void failedNormalSaveStopsAndRestartRequiresLimitedRecovery()throws Exception{
        LanControllerHarness.Disk disk;
        try(var p=new Pair()){
            disk=p.m.disk;disk.managementFiles.fail=true;p.deliver(p.page(1));p.m.drain();
            assertTrue(group(p.m).storageBlocked);assertNull(p.m.endpoint());assertTrue(p.m.ui.last.text.contains("保存がいっぱい"));
            assertNull(LanControllerHarness.field(p.m.controller,"dht"));assertNull(LanControllerHarness.field(p.m.controller,"sync"));
            assertEquals(StopMarker.Status.ACTIVE,disk.stopMarker.marker().inspect().status());disk.managementFiles.fail=false;
        }
        try(var restarted=new LanControllerHarness(disk)){
            assertEquals(CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS,coordinator(restarted).state());
            assertNull(LanControllerHarness.field(restarted.controller,"dht"));assertNull(LanControllerHarness.field(restarted.controller,"sync"));
        }
    }
    @Test public void persistingUsesSharedInboxAndDrainsOnlyAfterResume()throws Exception{
        try(var p=new Pair()){
            var page=p.page(1);var receiver=receiver(p.m);byte[] peer=group(p.a).id(),session=p.m.endpoint().sessionId(peer);var queue=inbox(p.m);
            coordinator(p.m).saveUnchanged(()->{
                for(int i=0;i<81;i++)receiver.receive(peer,session,page.envelope());
                assertEquals(80,queue.size());p.m.drain();assertEquals(80,queue.size());assertEquals(0,group(p.m).state.revocations().version());
            });
            p.m.tick();assertEquals(0,queue.size());assertEquals(2,group(p.m).state.revocations().version());
        }
    }
    @Test public void persistingDropsOtherPlaintextBeforeInbox()throws Exception{
        try(var p=new Pair()){
            var page=p.page(1);var receiver=receiver(p.m);byte[] peer=group(p.a).id(),session=p.m.endpoint().sessionId(peer);var queue=inbox(p.m);
            coordinator(p.m).saveUnchanged(()->{
                receiver.receive(peer,session,new byte[]{1,2,3});
                receiver.receive(peer,session,new ManagementPageAck(group(p.m).groupId,page.operationId(),page.objectDigest(),new int[]{0},true).envelope());
                receiver.receive(peer,session,new RevocationsRecoveryRequest(group(p.m).groupId,new byte[16],2,new byte[32]).envelope());
                assertEquals(0,queue.size());
            });
        }
    }
    @Test public void queuedPageExpiresFromCallbackTimeAndIsWiped()throws Exception{
        try(var p=new Pair()){
            p.deliver(p.page(1));var queue=inbox(p.m);
            var packet=queued(p.m).stream().filter(value->ManagementEnvelopeFields.field(value.wire)==ManagementEnvelopeFields.REVOCATION_PAGE).findFirst().orElseThrow();
            p.m.offset.addAndGet(30_000_000_000L);p.m.drain();
            assertEquals(0,group(p.m).state.revocations().version());assertArrayEquals(new byte[packet.wire.length],packet.wire);assertEquals(0,queue.size());
        }
    }
    static List<SyncInbox.Packet> queued(LanControllerHarness h)throws Exception{
        var field=SyncInbox.class.getDeclaredField("queue");field.setAccessible(true);
        var result=new ArrayList<SyncInbox.Packet>();for(Object packet:(java.util.ArrayDeque<?>)field.get(inbox(h)))result.add((SyncInbox.Packet)packet);return result;
    }
    @Test public void storageFailureWipesProcessedAndWaitingPlaintext()throws Exception{
        try(var p=new Pair()){
            p.deliver(p.page(1));p.deliver(p.page(2));var queued=queued(p.m).stream().filter(value->ManagementEnvelopeFields.field(value.wire)==ManagementEnvelopeFields.REVOCATION_PAGE).collect(java.util.stream.Collectors.toList());assertEquals(2,queued.size());
            p.m.disk.managementFiles.fail=true;p.m.drain();assertNull(p.m.endpoint());
            for(var packet:queued)assertArrayEquals(new byte[packet.wire.length],packet.wire);assertEquals(0,inbox(p.m).size());
        }
    }
    @Test public void closeWipesWaitingPlaintext()throws Exception{
        try(var p=new Pair()){
            p.deliver(p.page(1));var packet=queued(p.m).stream().filter(value->ManagementEnvelopeFields.field(value.wire)==ManagementEnvelopeFields.REVOCATION_PAGE).findFirst().orElseThrow();p.m.controller.close();p.m.drain();
            assertArrayEquals(new byte[packet.wire.length],packet.wire);assertEquals(0,inbox(p.m).size());
        }
    }
    @Test public void oldGenerationPacketIsDiscardedAndWiped()throws Exception{
        try(var p=new Pair()){
            assertTrue(inbox(p.m).offer(-1,group(p.a).id(),p.m.endpoint().sessionId(group(p.a).id()),p.page(1).envelope()));
            var packet=queued(p.m).get(0);p.m.tick();assertEquals(0,group(p.m).state.revocations().version());assertArrayEquals(new byte[packet.wire.length],packet.wire);
        }
    }

}
