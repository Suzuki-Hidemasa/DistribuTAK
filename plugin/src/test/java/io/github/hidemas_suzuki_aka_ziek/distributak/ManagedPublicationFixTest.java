// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ManagedPublicationFixTest {
    private record Frame(Node from,byte[] peer,byte[] wire){}
    private static final class Node {
        LanGroup group;SessionManager sessions;CorePersistenceCoordinator coordinator;ManagedDhtExchange exchange;LanDht dht;
        final Set<DhtId> received=new HashSet<>();
    }
    private static final class Network implements AutoCloseable {
        final RosterExchangeTest.Pair p=new RosterExchangeTest.Pair(true);
        final List<Node> nodes=new ArrayList<>();final ArrayDeque<Frame> frames=new ArrayDeque<>();
        final List<AdminRecords.Record> certificates=new ArrayList<>();final Node root;Node blocked;
        Network()throws Exception{this(0);}
        Network(long publicationDelay)throws Exception{
            root=new Node();root.group=p.a;root.sessions=p.sa;root.coordinator=p.ca;
            root.exchange=new ManagedRoundTwoTest().exchange(p);nodes.add(root);
            var forget=SessionManager.class.getDeclaredMethod("forgetAllVolatile");forget.setAccessible(true);forget.invoke(p.sa);
            for(int i=0;i<20;i++){
                var node=new Node();node.group=p.da.load(p.wall);node.group.identitySecret=StoredUpdatesTest.key(150+i);
                node.group.handshakeSecret=StoredUpdatesTest.key(180+i);node.group.administratorSecret=new byte[0];
                node.group.certificate=StoredUpdatesTest.peer(p.a,150+i,180+i,StorageGroupTest.NOW);certificates.add(node.group.certificate);
                node.group.management=null;node.group.managementGeneration=0;
                var disk=new LanControllerHarness.Disk(54323+i);disk.enableSix();disk.save(node.group);
                node.sessions=node.group.sessions(p.wall,()->0);forget.invoke(node.sessions);node.sessions.rememberPeer(p.a.certificate);p.sa.rememberPeer(node.group.certificate);
                var second=node.sessions.receive(p.sa.start(node.group.id()).packet());var third=p.sa.receive(second.outbound().get(0).packet());node.sessions.receive(third.outbound().get(0).packet());
                var union=new RevocationUnion(node.group.groupId,new AdminStateTrust(node.group.state));
                node.coordinator=new CorePersistenceCoordinator(node.group.state,node.sessions,union,p.wall,p.deadlines);
                node.exchange=new ManagedDhtExchange(node.group,node.sessions,node.coordinator,union,p.wall,p.deadlines,()->p.now*1000000,new SecureRandom(),disk);nodes.add(node);
            }
            var directory=new MemberDirectory(p.a.state);directory.saved(p.a.certificate);for(var cert:certificates)directory.saved(cert);
            p.da.saveDirectory(p.a,directory,Map.of());
            p.wallAdvance=publicationDelay;
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,root.exchange.rotation().manual(List.of(),certificates.subList(0,6),p.da.persistenceHooks(p.a)));
            for(var node:nodes)node.dht=new LanDht(config(node));
            for(var node:nodes.subList(1,nodes.size())){
                root.dht.dispatcherForTest().sessionStarted(node.group.id(),root.sessions.sessionId(node.group.id()));
                node.dht.dispatcherForTest().sessionStarted(root.group.id(),node.sessions.sessionId(root.group.id()));
            }
            pump();assertEquals(20,root.dht.managementPeers().size());
        }
        LanDht.Config config(Node node){
            var c=new LanDht.Config();var g=node.group;c.groupId=g.groupId;c.self=new DhtId(g.id());
            c.ipv4=new byte[]{(byte)192,0,2,1};c.prefix=24;c.nanos=()->p.now*1000000;c.wall=p.wall;c.reserve=()->1;
            c.issuer=(v,t)->DiscoveryRecord.issue(g.groupId,g.identitySecret,Crypto.x25519Public(g.handshakeSecret),c.ipv4,50000,v,t);c.management=node.exchange;
            c.wire=new LanDht.Wire(){
                public byte[] sessionId(byte[] peer){return node.sessions.sessionId(peer);}
                public AuthenticatedPeer authenticated(byte[] peer,byte[] session){var current=node.sessions.verifiedSession(peer);return current!=null&&Crypto.equal(current.sessionId(),session)?AuthenticatedPeer.fromVerifiedSession(current):null;}
                public boolean send(byte[] peer,byte[] session,byte[] wire){frames.add(new Frame(node,peer,wire.clone()));return true;}
                public boolean release(byte[] peer){return false;}
                public void start(byte[] peer,byte[] key,InetSocketAddress address){}
                public long nextGeneration(){return node.sessions.generation();}
            };return c;
        }
        void pump(){
            int count=0;
            while(!frames.isEmpty()){
                assertTrue(++count<50000);var f=frames.remove();var to=nodes.stream().filter(n->Crypto.equal(n.group.id(),f.peer())).findFirst().orElse(null);
                if(to==null)continue;
                if(f.from()==root&&to==blocked&&DhtWire.isDht(f.wire())){
                    var m=DhtWire.parse(f.wire());if(m.managed())continue;
                }
                if(f.from()==root&&DhtWire.isDht(f.wire())){
                    var m=DhtWire.parse(f.wire());if(m.managed()&&m.op()==DhtWire.Op.STORE)to.received.add(m.target());
                }
                to.dht.receive(f.from().group.id(),to.sessions.sessionId(f.from().group.id()),f.wire());
            }
        }
        Set<DhtId> expected(){
            var result=new HashSet<DhtId>();
            for(int k:new int[]{DhtKeys.LATEST_ADMINS,DhtKeys.LATEST_REVOCATIONS,DhtKeys.KEY_ANNOUNCEMENT})result.add(DhtKeys.derive(p.a.groupId,k,new byte[32]));
            result.add(DhtKeys.derive(p.a.groupId,DhtKeys.ADMIN_HISTORY,DhtKeys.adminHistorySubject(1)));
            for(var cert:certificates.subList(0,6))result.add(DhtKeys.derive(p.a.groupId,DhtKeys.WRAPPED_KEY,Crypto.blake2s(cert.field(0))));return result;
        }
        void cycle(){root.dht.step();pump();p.now+=100;}
        public void close(){for(var n:nodes){if(n.dht!=null)n.dht.close();if(n!=root){n.sessions.close();n.group.close();}}p.close();}
    }
    @Test public void twentyPeersReceiveAllSixWrapsAcrossDispatcherCapacityBoundaries()throws Exception{
        try(var n=new Network()){
            var expected=n.expected();
            for(var peer:n.nodes.subList(1,9))for(int i=0;i<8;i++)assertTrue(n.root.dht.findManaged(new Contact(new DhtId(peer.group.id())),DhtKeys.derive(n.p.a.groupId,DhtKeys.ADMIN_HISTORY,DhtKeys.adminHistorySubject(200+i)),ignored->{}));
            assertEquals(64,n.root.dht.dispatcherForTest().pendingCount());
            n.root.dht.step();assertEquals(0L,field(n.root.exchange,"nextPublish"));n.pump();
            for(int i=0;i<300;i++){n.cycle();if(!(boolean)field(n.root.exchange,"publishing"))break;}
            for(var peer:n.nodes.subList(1,n.nodes.size()))for(var target:expected)assertNotNull(peer.exchange.store().get(target));
            assertTrue(n.root.dht.active());
        }
    }
    @Test public void saturatedPeerDoesNotPreventTheOtherNineteenFromFinishing()throws Exception{
        try(var n=new Network()){
            n.blocked=n.nodes.get(1);var expected=n.expected();
            for(int i=0;i<8;i++)assertTrue(n.root.dht.findManaged(new Contact(new DhtId(n.blocked.group.id())),DhtKeys.derive(n.p.a.groupId,DhtKeys.ADMIN_HISTORY,DhtKeys.adminHistorySubject(200+i)),ignored->{}));
            for(int i=0;i<300;i++){n.cycle();if(!(boolean)field(n.root.exchange,"publishing"))break;}
            for(var peer:n.nodes.subList(2,n.nodes.size()))for(var target:expected)assertNotNull(peer.exchange.store().get(target));
            assertTrue(n.blocked.received.isEmpty());
        }
    }
    private static Object field(Object value,String name)throws Exception{
        var f=value.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(value);
    }
    @Test public void nextHourStartsOnlyAfterEveryPublicationCursorFinishes()throws Exception{
        try(var n=new Network()){
            n.root.dht.step();assertEquals(0L,field(n.root.exchange,"nextPublish"));
            var cursors=(List<?>)field(n.root.exchange,"publicationCursors");assertFalse(cursors.isEmpty());assertTrue(cursors.size()<=20);
            n.pump();
            for(int i=0;i<300&&(boolean)field(n.root.exchange,"publishing");i++)n.cycle();
            assertFalse((boolean)field(n.root.exchange,"publishing"));assertTrue(cursors.isEmpty());
            long next=(long)field(n.root.exchange,"nextPublish");assertTrue(next>=3600000);assertTrue(next<=n.p.now+3600000);
            n.cycle();assertEquals(next,field(n.root.exchange,"nextPublish"));
        }
    }
    @Test public void expiredCurrentRecordDiscardsTheCursorEvenWhenLaterRecordsAreNewer()throws Exception{
        try(var n=new Network(3600000)){
            for(var peer:n.nodes.subList(1,9))for(int i=0;i<8;i++)assertTrue(n.root.dht.findManaged(new Contact(new DhtId(peer.group.id())),DhtKeys.derive(n.p.a.groupId,DhtKeys.ADMIN_HISTORY,DhtKeys.adminHistorySubject(200+i)),ignored->{}));
            n.root.dht.step();n.pump();
            var previous=new ArrayList<>((List<?>)field(n.root.exchange,"publicationCursors"));assertFalse(previous.isEmpty());
            n.p.wallAdvance=86400000;n.root.dht.step();
            var current=(List<?>)field(n.root.exchange,"publicationCursors");
            for(var cursor:previous)assertFalse(current.contains(cursor));
            assertTrue(n.root.dht.active());
        }
    }
    @Test public void savedBasisChangeReplacesTheOldCursorsAndPublishesWithoutWaitingAnHour()throws Exception{
        try(var n=new Network()){
            n.root.dht.step();n.pump();
            var previous=new ArrayList<>((List<?>)field(n.root.exchange,"publicationCursors"));assertFalse(previous.isEmpty());
            assertTrue(n.p.ca.receiveAdministrators(new ManagedDhtExchangeTest().nextAdmins(n.p,true),n.p.da.persistenceHooks(n.p.a)));
            n.root.dht.step();n.pump();
            var current=(List<?>)field(n.root.exchange,"publicationCursors");assertTrue(current.size()<=20);
            for(var cursor:current)assertFalse(previous.contains(cursor));
            assertTrue(n.p.now<3600000);assertTrue(n.nodes.subList(1,n.nodes.size()).stream().anyMatch(node->node.group.state.administrators().version()==2));
        }
    }
    @Test public void expiredOrChangedPublicationBindingsDiscardTheirRemainingCursors()throws Exception{
        for(int change=0;change<3;change++)try(var n=new Network()){
            n.root.dht.step();assertFalse(((List<?>)field(n.root.exchange,"publicationCursors")).isEmpty());n.frames.clear();
            if(change==0)n.p.wallAdvance=86400000;
            else if(change==1){var forget=SessionManager.class.getDeclaredMethod("forgetAllVolatile");forget.setAccessible(true);forget.invoke(n.root.sessions);}
            else assertTrue(n.p.ca.receiveAdministrators(new ManagedDhtExchangeTest().nextAdmins(n.p,true),n.p.da.persistenceHooks(n.p.a)));
            n.root.dht.step();
            if(change<2)assertTrue(((List<?>)field(n.root.exchange,"publicationCursors")).isEmpty());
            for(var frame:n.frames)if(DhtWire.isDht(frame.wire())){
                var message=DhtWire.parse(frame.wire());
                if(message.managed()&&message.op()==DhtWire.Op.STORE){
                    var record=ManagedDhtRecord.verifyStructure(message.record(),n.p.a.groupId);
                    assertNotEquals(DhtKeys.KEY_ANNOUNCEMENT,record.kind());assertNotEquals(DhtKeys.WRAPPED_KEY,record.kind());
                }
            }
        }
    }

}
