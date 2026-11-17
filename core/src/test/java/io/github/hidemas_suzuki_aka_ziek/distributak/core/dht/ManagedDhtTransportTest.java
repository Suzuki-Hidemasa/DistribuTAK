// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.*;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcherTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecordTest.*;
import static org.junit.jupiter.api.Assertions.*;

class ManagedDhtTransportTest {
    static final class Pair {
        final Net net=new Net();final ManagedDhtStoreTest.Fixture left=new ManagedDhtStoreTest.Fixture(),right=new ManagedDhtStoreTest.Fixture();
        final Rig a=new Rig(net,new DhtId(left.state.administrators().binding(pub(1)).memberId()),new Random(1),GROUP);
        final Rig b=new Rig(net,DhtIdTest.id(80),new Random(2),GROUP);
        Pair(){net.rigs.put(a.id,a);net.rigs.put(b.id,b);a.dispatcher.configureManaged(left.store);b.dispatcher.configureManaged(right.store);net.connect(a,b);}
    }
    @Test void smallStoreAndValueUseExistingOperationsWithManagementSchemas(){
        var p=new Pair();var record=p.left.rev(1,0);var statuses=new ArrayList<DhtWire.StoreStatus>();
        assertTrue(p.a.dispatcher.storeManaged(p.b.contact(),record.encode(),statuses::add));p.net.pump();
        assertEquals(List.of(DhtWire.StoreStatus.ACCEPTED),statuses);assertEquals(1,p.right.delivered.size());
        var values=new ArrayList<ManagedDhtRecord>();assertTrue(p.a.dispatcher.findManagedFrom(p.b.contact(),record.key(),values::add));p.net.pump();
        assertEquals(1,values.size());assertNotNull(values.get(0));assertEquals(0,p.a.dispatcher.pendingCount());
        assertTrue(p.net.sent.stream().filter(x->x.message().op()==DhtWire.Op.STORE).allMatch(x->x.message().managed()));
    }
    @Test void largeStoreNeedsWholeRecordResultAndLargeValueSurvivesRpcTimeout(){
        var p=new Pair();var record=p.left.rev(1,100);assertEquals(ManagedDhtRecord.Transport.TRANSFER,record.transport());
        var statuses=new ArrayList<DhtWire.StoreStatus>();assertTrue(p.a.dispatcher.storeManaged(p.b.contact(),record.encode(),statuses::add));
        p.net.run(30);assertEquals(List.of(DhtWire.StoreStatus.ACCEPTED),statuses);assertEquals(1,p.right.delivered.size());
        var values=new ArrayList<ManagedDhtRecord>();assertTrue(p.a.dispatcher.findManagedFrom(p.b.contact(),record.key(),values::add));
        p.net.deliver(p.net.queue.poll());
        var first=p.net.queue.poll();assertEquals(DhtWire.Op.TRANSFER,first.message().op());p.net.deliver(first);
        p.net.advance(DhtLimits.RPC_NANOS+SECOND);p.net.run(30);
        assertEquals(1,values.size());assertNotNull(values.get(0));assertEquals(0,p.a.dispatcher.pendingCount());
    }
    @Test void valueBindingRejectsWrongSessionTargetAndLegacySchemaAndCompletesOnlyOnce(){
        var p=new Pair();var record=p.left.rev(1,0);p.right.store.accept(null,record,false);
        var values=new ArrayList<ManagedDhtRecord>();assertTrue(p.a.dispatcher.findManagedFrom(p.b.contact(),record.key(),values::add));
        var request=p.net.queue.poll();p.net.deliver(request);var reply=p.net.queue.poll();
        p.net.deliver(new Packet(p.b,p.a,OTHER_SESSION,reply.wire()));
        p.net.deliver(new Packet(p.b,p.a,SESSION,DhtWire.value(GROUP,reply.message().requestId(),record.key(),record.encode())));
        p.net.deliver(new Packet(p.b,p.a,SESSION,DhtWire.management(DhtWire.value(GROUP,reply.message().requestId(),DhtIdTest.id(70),record.encode()))));
        assertTrue(values.isEmpty());p.net.deliver(reply);p.net.deliver(reply);
        assertEquals(1,values.size());assertNotNull(values.get(0));
    }
    @Test void aGenerationChangeDropsThePendingCallbackAndRejectsDelayedTransfer(){
        var p=new Pair();var record=p.left.rev(1,100);p.right.store.accept(null,record,false);
        var values=new ArrayList<ManagedDhtRecord>();assertTrue(p.a.dispatcher.findManagedFrom(p.b.contact(),record.key(),values::add));
        p.net.deliver(p.net.queue.poll());p.a.network();p.net.run(30);
        assertEquals(1,values.size());assertNull(values.get(0));assertTrue(p.left.delivered.isEmpty());
    }
    @Test void unsolicitedValueAndUnboundStoreCannotMutateTheCache(){
        var p=new Pair();var record=p.left.rev(1,0);byte[] rid=new byte[16];
        p.a.dispatcher.receive(p.b.id.bytes(),SESSION,DhtWire.management(DhtWire.value(GROUP,rid,record.key(),record.encode())));
        p.a.dispatcher.receive(p.b.id.bytes(),SESSION,DhtWire.management(DhtWire.store(GROUP,rid,record.key(),record.encode())));
        assertTrue(p.left.delivered.isEmpty());assertEquals(0,p.left.store.size());
    }
}
