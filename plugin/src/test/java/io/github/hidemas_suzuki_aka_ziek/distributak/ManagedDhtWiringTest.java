// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.net.InetSocketAddress;
import java.util.*;
import java.security.SecureRandom;
import org.junit.Test;
import static org.junit.Assert.*;

public class ManagedDhtWiringTest {
    static final class Frame {final boolean toB;final byte[] wire;Frame(boolean toB,byte[] wire){this.toB=toB;this.wire=wire;}}
    static final class Network implements AutoCloseable {
        final RosterExchangeTest.Pair p;final ManagedDhtExchange xa,xb;final LanDht a,b;
        final ArrayDeque<Frame> frames=new ArrayDeque<>();
        Network()throws Exception{
            p=new RosterExchangeTest.Pair();
            var network=SessionManager.class.getDeclaredMethod("forgetAllVolatile");network.setAccessible(true);network.invoke(p.sa);network.invoke(p.sb);
            xa=new ManagedDhtExchange(p.a,p.sa,p.ca,p.ua,p.wall,p.deadlines,()->p.now*1000000,new SecureRandom(),p.da);
            xb=new ManagedDhtExchange(p.b,p.sb,p.cb,p.ub,p.wall,p.deadlines,()->p.now*1000000,new SecureRandom(),p.db);
            a=new LanDht(config(true));b=new LanDht(config(false));
            a.dispatcherForTest().sessionStarted(p.b.id(),p.sa.sessionId(p.b.id()));
            b.dispatcherForTest().sessionStarted(p.a.id(),p.sb.sessionId(p.a.id()));pump();
        }
        LanDht.Config config(boolean left){
            var g=left?p.a:p.b;var s=left?p.sa:p.sb;var c=new LanDht.Config();
            c.groupId=g.groupId;c.self=new DhtId(g.id());c.ipv4=new byte[]{(byte)192,0,2,1};c.prefix=24;c.nanos=()->p.now*1000000;c.wall=p.wall;
            c.reserve=()->1;c.issuer=(v,t)->DiscoveryRecord.issue(g.groupId,g.identitySecret,Crypto.x25519Public(g.handshakeSecret),c.ipv4,50000,v,t);
            c.management=left?xa:xb;
            c.wire=new LanDht.Wire(){
                public byte[] sessionId(byte[] peer){return s.sessionId(peer);}
                public AuthenticatedPeer authenticated(byte[] peer,byte[] session){var v=s.verifiedSession(peer);return v!=null&&Crypto.equal(v.sessionId(),session)?AuthenticatedPeer.fromVerifiedSession(v):null;}
                public boolean send(byte[] peer,byte[] session,byte[] plain){frames.add(new Frame(left,plain.clone()));return true;}
                public boolean release(byte[] peer){return false;}
                public void start(byte[] peer,byte[] key,InetSocketAddress address){}
                public long nextGeneration(){return s.generation();}
            };return c;
        }
        void pump(){int count=0;while(!frames.isEmpty()){
            if(count++>10000)throw new AssertionError("Delivery loop");var f=frames.remove();
            if(f.toB)b.receive(p.a.id(),p.sb.sessionId(p.a.id()),f.wire);else a.receive(p.b.id(),p.sa.sessionId(p.b.id()),f.wire);
        }}
        public void close(){a.close();b.close();p.close();}
    }
    @Test public void initialJoinKeepsDiscoveryDhtAndManagementStartsOnReconnect()throws Exception{
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()){
            admin.create();member.beginJoin(admin);
            LanControllerHarness.until(()->member.ui.last.member&&admin.logs.contains("LAN_MEMBER_ISSUED"),admin,member);
            member.drain();var initial=(LanDht)LanControllerHarness.field(member.controller,"dht");
            assertNotNull(initial);assertTrue(initial.active());
            var config=(LanDht.Config)LanControllerHarness.field(initial,"cfg");assertNull(config.management);
            assertNull(LanControllerHarness.field(member.controller,"persistence"));
            assertNull(LanControllerHarness.field(member.controller,"recovery"));assertNull(LanControllerHarness.field(member.controller,"roster"));
            member.controller.disconnect();member.drain();member.controller.connect();member.drain();
            var connected=(LanDht)LanControllerHarness.field(member.controller,"dht");assertNotNull(connected);
            assertNotNull(((LanDht.Config)LanControllerHarness.field(connected,"cfg")).management);
        }
    }
    @Test public void realSessionBoundManagementStoreAndFetchReachDurableState()throws Exception{
        try(var n=new Network()){
            var t=new ManagedDhtExchangeTest();var r=t.rev(n.p,3,StoredUpdatesTest.key(240));var result=new ArrayList<DhtWire.StoreStatus>();
            assertTrue(n.a.publishManaged(new Contact(new DhtId(n.p.b.id())),r.encode(),result::add));n.pump();
            assertEquals(List.of(DhtWire.StoreStatus.ACCEPTED),result);assertEquals(3,n.p.b.state.revocations().version());
            var found=new ArrayList<ManagedDhtRecord>();assertTrue(n.a.findManaged(new Contact(new DhtId(n.p.b.id())),r.key(),found::add));n.pump();assertNotNull(found.get(0));
            n.a.close();assertEquals(0,n.xa.store().size());assertEquals(0,n.xa.budget().count());
        }
    }
    @Test public void managementTransferSharesThePageAssemblyReservationAndReleasesOnClose()throws Exception{
        try(var n=new Network();var lease=n.xb.resources().acquire(new DhtId(n.p.a.id()),1)){
            assertNotNull(lease);var entries=new ArrayList<byte[]>();for(int i=0;i<100;i++)entries.add(Crypto.blake2s(new byte[]{(byte)i}));
            var admins=n.p.a.state.administrators();var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,n.p.a.groupId,2,StorageGroupTest.NOW,entries,n.p.a.administratorSecret);
            var r=ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,n.p.a.groupId,n.p.a.administratorSecret,body,1,admins.version(),Crypto.blake2s(admins.signedBytes()),StorageGroupTest.NOW,null);
            assertTrue(n.a.publishManaged(new Contact(new DhtId(n.p.b.id())),r.encode(),status->{}));n.pump();
            assertEquals(0,n.p.b.state.revocations().version());lease.close();
            n.p.now+=1000;n.a.step();n.pump();assertEquals(2,n.p.b.state.revocations().version());
        }
    }
    @Test public void malformedInputOnlyDropsOneMessageAndBothDhtSchemasKeepWorking()throws Exception{
        try(var n=new Network()){
            byte[] peer=n.p.a.id(),session=n.p.sb.sessionId(peer);
            for(byte schema:new byte[]{2,3}){
                assertTrue(n.b.receive(peer,session,new byte[]{8,schema,0x4a}));
                assertTrue(n.b.active());assertTrue(n.xb.allowed());
            }
            var record=new ManagedDhtExchangeTest().rev(n.p,3,StoredUpdatesTest.key(241));var statuses=new ArrayList<DhtWire.StoreStatus>();
            assertTrue(n.a.publishManaged(new Contact(new DhtId(n.p.b.id())),record.encode(),statuses::add));n.pump();
            assertEquals(List.of(DhtWire.StoreStatus.ACCEPTED),statuses);
            var found=new ArrayList<ManagedDhtRecord>();assertTrue(n.a.findManaged(new Contact(new DhtId(n.p.b.id())),record.key(),found::add));n.pump();
            assertEquals(1,found.size());assertNotNull(found.get(0));
            var discovery=DiscoveryRecord.issue(n.p.a.groupId,n.p.a.identitySecret,Crypto.x25519Public(n.p.a.handshakeSecret),new byte[]{(byte)192,0,2,1},50000,1,n.p.wall.millis());
            byte[] request=new byte[16];request[0]=1;
            assertTrue(n.b.receive(peer,session,DhtWire.store(n.p.a.groupId,request,discovery.key(),discovery.encode())));
            var stored=DhtWire.parse(n.frames.remove().wire);assertFalse(stored.managed());assertEquals(DhtWire.StoreStatus.ACCEPTED,stored.status());
            request[0]=2;assertTrue(n.b.receive(peer,session,DhtWire.findValue(n.p.a.groupId,request,discovery.key())));
            var value=DhtWire.parse(n.frames.remove().wire);assertFalse(value.managed());assertEquals(DhtWire.Op.VALUE,value.op());
            assertArrayEquals(discovery.encode(),value.record());assertTrue(n.b.active());
        }
    }

}
