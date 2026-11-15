// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import static org.junit.jupiter.api.Assertions.*;

class CotSyncEndpointTest {
    private record Input(byte[] peer,byte[] session,byte[] bytes){
        void clear(){Crypto.wipe(peer);Crypto.wipe(session);Crypto.wipe(bytes);}
        @Override public String toString(){return "Test input";}
    }
    private static final class Layer implements AutoCloseable {
        final SessionManagerTest.Node node;final UdpEndpoint endpoint;final CotSync sync;
        final InetSocketAddress address;
        final Queue<Input> input=new ConcurrentLinkedQueue<>();final List<CotRecord> imported=new ArrayList<>();
        SyncState saved;
        Layer(SessionManagerTest fixture,SessionManagerTest.Node node)throws Exception{
            this.node=node;var socket=new DatagramSocket(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),0));
            address=(InetSocketAddress)socket.getLocalSocketAddress();
            var io=new UdpEndpoint.SocketIo(socket){
                @Override public void send(byte[] wire,InetSocketAddress target)throws java.io.IOException{
                    if(!target.getAddress().isLoopbackAddress())throw new java.io.IOException("PC試験の宛先が違います");super.send(wire,target);
                }
            };
            endpoint=new UdpEndpoint(node.sessions,node.state,io,new UdpEndpoint.Receiver(){
                public void receive(byte[] peer,byte[] bytes){fail("session identity is required");}
                @Override public void receive(byte[] peer,byte[] session,byte[] bytes){
                    if(bytes.length!=0)input.add(new Input(peer.clone(),session.clone(),bytes.clone()));
                }
            },Duration.ofMillis(20));
            saved=new SyncState(fixture.group,node.id);
            sync=new CotSync(node.id,saved,fixture.time,System::nanoTime,
                    state->saved=SyncState.decode(state.encode(),fixture.group,node.id),endpoint::sendIfSession,imported::add,new SecureRandom(),0);
        }
        void link(Layer other){endpoint.rememberPeer(other.node.cert);endpoint.setPeerAddress(other.node.id,other.endpointAddress());}
        InetSocketAddress endpointAddress(){return address;}
        void poll(){
            for(var peer:endpoint.knownPeers()){
                byte[] id=Crypto.blake2s(peer.identityKey()),session=endpoint.sessionId(id);
                if(session!=null)sync.connected(id,session);else sync.disconnected(id);
            }
            for(Input item;(item=input.poll())!=null;)try{
                if(Arrays.equals(endpoint.sessionId(item.peer),item.session)){
                    sync.connected(item.peer,item.session);sync.receive(item.peer,item.session,item.bytes);
                }
            }finally{item.clear();}
            sync.poll();
        }
        public void close(){endpoint.close();sync.close();for(Input item;(item=input.poll())!=null;)item.clear();}
    }
    @Test void threeLoopbackEndpointsRelayLargeCotOverAuthenticatedEncryptedData()throws Exception{
        var fixture=new SessionManagerTest();
        try(var a=fixture.new Node(1);var b=fixture.new Node(2);var c=fixture.new Node(3);
            var first=new Layer(fixture,a);var middle=new Layer(fixture,b);var last=new Layer(fixture,c)){
            first.link(middle);middle.link(first);middle.link(last);last.link(middle);
            first.endpoint.start(b.id);middle.endpoint.start(c.id);
            drive(()->first.endpoint.isEstablished(b.id)&&middle.endpoint.isEstablished(a.id)
                    &&middle.endpoint.isEstablished(c.id)&&last.endpoint.isEstablished(b.id),first,middle,last);
            String now=fixture.time.instant().toString(),stale=fixture.time.instant().plusSeconds(60).toString();
            byte[] xml=("<event version=\"2.0\" uid=\"native-cot\" type=\"a-f-G\" time=\""+now+"\" start=\""+now+"\" stale=\""+stale
                    +"\" how=\"h-e\"><point lat=\"0\" lon=\"0\" hae=\"9999999\" ce=\"9999999\" le=\"9999999\"/><detail><remarks>"
                    +"x".repeat(60000)+"</remarks></detail></event>").getBytes(StandardCharsets.UTF_8);
            assertTrue(first.sync.publish("native-cot",xml,SyncState.Origin.LOCAL_CREATED));
            drive(()->last.saved.get("native-cot")!=null,first,middle,last);
            assertArrayEquals(xml,last.saved.get("native-cot").xml());assertEquals(1,middle.imported.size());assertEquals(1,last.imported.size());
            assertTrue(first.saved.get("native-cot").sameRecord(last.saved.get("native-cot")));
            assertEquals(1,first.endpoint.knownPeers().size());assertEquals(2,middle.endpoint.knownPeers().size());assertEquals(1,last.endpoint.knownPeers().size());
            assertEquals(0,first.endpoint.callbackFailures());assertEquals(0,middle.endpoint.callbackFailures());assertEquals(0,last.endpoint.callbackFailures());
        }
    }
    private static void drive(java.util.function.BooleanSupplier done,Layer... layers){
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);
        while(!done.getAsBoolean()){
            assertTrue(System.nanoTime()<end,"loopback synchronization must finish");
            for(Layer layer:layers)layer.poll();LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
        }
    }
}
