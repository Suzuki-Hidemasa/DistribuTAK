// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

class CotSyncCatchupTest {
    @Test void finalRequestLossForEmptyAndNonemptySinglePagesDoesNotFailEitherDirection(){
        for(boolean records:new boolean[]{false,true})for(boolean loss:new boolean[]{false,true})for(int from:new int[]{1,2}) {
            try(var mesh=new CotSyncTest.Mesh()) {
                var a=mesh.node(1);var b=mesh.node(2);var dropped=new AtomicBoolean();
                if(records){assertTrue(a.publish("from-a"));assertTrue(b.publish("from-b"));mesh.step(250);}
                mesh.drop=packet->loss&&packet.from()==from&&SyncWire.parse(packet.wire()).hasRequest()&&!dropped.getAndSet(true);
                mesh.connect(1,2);for(int n=0;n<140;n++)mesh.step(250);
                assertEquals(loss,dropped.get());
                assertEquals(0,a.sync.statistics().failed(),"first direction");assertEquals(0,b.sync.statistics().failed(),"second direction");
                assertEquals(0,a.sync.statistics().pending());assertEquals(0,b.sync.statistics().pending());
                if(records){assertNotNull(a.saved.get("from-b"));assertNotNull(b.saved.get("from-a"));}
            }
        }
    }
    @Test void oneThousandTwentyFourRecordsCatchUpThroughTheBoundedCursorWithoutLoss() {
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);
            for(int n=0;n<1024;n++){
                String uid="record-"+n;assertTrue(a.publish(uid));assertTrue(a.sync.remove(uid));
            }
            mesh.step(250);mesh.connect(1,2);
            for(int n=0;n<160;n++){
                mesh.step(250);assertTrue(a.sync.statistics().pending()<=32);assertTrue(a.sync.statistics().pendingBytes()<=1024*1024);
            }
            assertEquals(1024,b.saved.records().size());assertEquals(1024,b.received.size());
            assertEquals(0,a.sync.statistics().failed());assertEquals(0,b.sync.statistics().failed());
            assertEquals(0,a.sync.statistics().pending());assertEquals(0,b.sync.statistics().pending());
        }
    }
    @Test void eightPeersShareTheGlobalTwoHundredFiftySixMessageBudget() {
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1);for(int id=2;id<=9;id++)mesh.node(id);
            for(int n=0;n<128;n++){assertTrue(a.publish("record-"+n));assertTrue(a.sync.remove("record-"+n));}
            mesh.step(250);for(int id=2;id<=9;id++)mesh.connect(1,id);
            for(int n=0;n<112;n++){
                mesh.step(250);assertTrue(a.sync.statistics().pending()<=256);assertTrue(a.sync.statistics().pendingBytes()<=1024*1024);
            }
            for(int id=2;id<=9;id++){assertEquals(128,mesh.nodes.get(id).saved.records().size());assertEquals(128,mesh.nodes.get(id).received.size());}
            assertEquals(0,a.sync.statistics().failed());
        }
    }
    @Test void bothLargeInventoriesAndLargeRecordsFinishWhenOneDataPieceIsLost() {
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);var dropped=new AtomicBoolean();
            for(var node:new CotSyncTest.Node[]{a,b})for(int n=0;n<6;n++){
                String uid="x".repeat(240)+"-"+node.id+"-"+n;
                String xml=new String(CotRecordTest.xml(uid,CotRecordTest.NOW+60000),StandardCharsets.UTF_8)
                        .replace("<detail/>","<detail><remarks>"+"x".repeat(60000)+"</remarks></detail>");
                assertTrue(node.sync.publish(uid,xml.getBytes(StandardCharsets.UTF_8),SyncState.Origin.LOCAL_CREATED));
            }
            mesh.step(250);
            mesh.drop=packet->{var value=SyncWire.parse(packet.wire());return packet.from()==1&&value.hasFragment()
                    &&value.getFragment().getCount()>50&&value.getFragment().getIndex()==2&&!dropped.getAndSet(true);};
            mesh.connect(1,2);for(int n=0;n<112;n++)mesh.step(250);
            assertTrue(dropped.get());assertEquals(12,a.saved.records().size());assertEquals(12,b.saved.records().size());
            assertEquals(6,a.received.size());assertEquals(6,b.received.size());
            for(CotRecord item:a.saved.records())assertArrayEquals(item.xml(),b.saved.get(item.uid()).xml());
            assertEquals(0,a.sync.statistics().failed());assertEquals(0,b.sync.statistics().failed());
            assertEquals(0,a.sync.statistics().pending());assertEquals(0,b.sync.statistics().pending());
        }
    }
    @Test void unansweredRequestTimesOutAndTheSecondSideGetsItsOwnThirtySecondWindow() {
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);
            assertTrue(a.sync.publish("short",CotRecordTest.xml("short",CotRecordTest.NOW+700),SyncState.Origin.LOCAL_CREATED));
            assertTrue(b.publish("b-owned"));mesh.step(250);
            mesh.drop=packet->mesh.nanos.get()<1_000_000_000L&&SyncWire.parse(packet.wire()).hasRequest();
            mesh.connect(1,2);for(int n=0;n<132;n++)mesh.step(250);
            assertNull(b.saved.get("short"));assertNotNull(a.saved.get("b-owned"));
            assertEquals(1,b.sync.statistics().failed());
            a.sync.disconnected(CotRecordTest.id(2));b.sync.disconnected(CotRecordTest.id(1));mesh.drop=packet->false;
            assertTrue(a.publish("short"));mesh.step(250);mesh.connect(1,2);mesh.settle();assertNotNull(b.saved.get("short"));
        }
    }
    @Test void inventoryOrderUsesUnsignedIdsEvenWhenTheLargerNodeConnectsFirst() {
        try(var mesh=new CotSyncTest.Mesh()){
            var larger=mesh.node(255);mesh.node(1);assertTrue(larger.publish("large-id"));mesh.step(250);mesh.connect(255,1);
            int first=mesh.sent.stream().filter(packet->SyncWire.parse(packet.wire()).hasInventory()).findFirst().orElseThrow().from();
            assertEquals(1,first);mesh.settle();assertNotNull(mesh.nodes.get(1).saved.get("large-id"));
        }
    }
}
