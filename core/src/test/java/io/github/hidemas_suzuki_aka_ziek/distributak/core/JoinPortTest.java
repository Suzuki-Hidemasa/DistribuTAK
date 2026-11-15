// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class JoinPortTest {
    @Test void requestFitsAndQueriesDoNotChangeHandshake() {
        var f=new JoinHandshakeTest();
        try(var invitation=f.invitation();var admin=f.admin(invitation);var joiner=f.joiner(invitation);var material=f.material()) {
            assertNull(admin.issuedCertificate());assertFalse(joiner.isClosed());
            byte[] request=joiner.request();assertEquals(369,request.length);
            byte[] plain=f.requestPlain(request);assertEquals(280,plain.length);Crypto.wipe(plain);
            try(var packet=JoinMessages.packet(request,false)) { assertArrayEquals(packet.invitation,admin.invitationId()); }
            byte[] id=admin.invitationId();id[0]^=1;assertFalse(Arrays.equals(id,admin.invitationId()));
            try(var joined=joiner.receive(admin.respond(request,f.adminX,f.f.a,material))) {
                assertArrayEquals(joined.certificate().encode(),admin.issuedCertificate().encode());
            }
            assertTrue(joiner.isClosed());admin.close();assertNull(admin.issuedCertificate());
        }
    }
    @Test void framesAndReassemblyHandleBoundsReorderAndDuplicates() {
        byte[] id=key(1),transfer=new byte[16],raw=new byte[JoinHandshake.MAX_RESPONSE_BYTES];
        new Random(1).nextBytes(raw);
        var assembly=new JoinWire.Assembly(raw.length);
        for(int n=assembly.count()-1;n>=0;n--) {
            byte[] data=JoinWire.data(id,transfer,raw,n);
            var frame=JoinWire.decode(data);assertTrue(data.length<=1232);
            assertTrue(assembly.add(frame));assertFalse(assembly.add(frame));
        }
        assertEquals(14365,assembly.count());assertTrue(assembly.complete());assertArrayEquals(raw,assembly.bytes());
        byte[] held=assembly.bytes();assembly.close();SecretAssertions.zero(held);
        assertThrows(IllegalArgumentException.class,()->new JoinWire.Assembly(raw.length+1));
        byte[] fetch=JoinWire.fetch(id,transfer,raw.length,0);assertEquals(1232,fetch.length);
        assertEquals(JoinWire.FETCH,JoinWire.decode(fetch).kind());
        assertThrows(IllegalArgumentException.class,()->JoinWire.decode(Arrays.copyOf(fetch,1233)));
        fetch[5]=1;assertThrows(IllegalArgumentException.class,()->JoinWire.decode(fetch));
    }
    @ParameterizedTest @ValueSource(strings={"127.0.0.1","::1"})
    void invitationToSamePortSessionWithLossReorderAndDuplicates(String host) throws Exception {
        var f=new JoinHandshakeTest();var inboxA=new LinkedBlockingQueue<byte[]>();var inboxB=new LinkedBlockingQueue<byte[]>();
        try(var socketA=new DatagramSocket(new InetSocketAddress(host,0));var socketB=new DatagramSocket(new InetSocketAddress(host,0))) {
            int originalPort=socketB.getLocalPort();
            try(var invitation=new Invitation(InetAddress.getByName(host).getAddress(),socketA.getLocalPort(),Crypto.x25519Public(f.adminX),f.f.ap,f.secret, f.f.group);
                var parsed=InvitationUrl.decode(InvitationUrl.encode(invitation));var administrator=f.admin(invitation)) {
                var state=new AdminState(f.f.group,f.f.ap,f.f.clock,new InMemoryAdminRecordStore());
                state.join(f.chain(),AdminRecords.signAnchor(f.chain().get(0),f.f.a),f.f.revocations(0,f.f.now,List.of(),f.f.a));
                byte[] identity=key(80),pub=Crypto.x25519Public(f.adminX);
                var adminCert=AdminRecords.certificate(f.f.group,Crypto.ed25519Public(identity),pub,SignaturePurpose.identityProof(identity,f.f.group,pub),f.f.now,f.f.a);
                var sessions=new SessionManager(state,adminCert,f.adminX,f.groupKey,0,f.f.clock,System::nanoTime,256);
                var issued=new AtomicReference<UdpEndpoint.AdminJoined>();var calls=new AtomicInteger();
                var providerSecrets=new ArrayList<byte[]>();var borrowed=new AtomicReference<JoinHandshake.Materials>();
                // 返事は数十断片。1枚を欠落させ、2枚を入れ替え、重複も差し込む。
                var faults=new JoinFaultIo(socketA);
                try(var a=new UdpEndpoint(sessions,state,faults,(peer,plain)->{if(plain.length>0)inboxA.add(plain.clone());},Duration.ofMillis(20));
                    var b=new UdpEndpoint(socketB,(peer,plain)->{if(plain.length>0)inboxB.add(plain.clone());})) {
                    a.registerInvitation(administrator,()->{
                        calls.incrementAndGet();byte[] x=f.adminX.clone(),s=f.f.a.clone();providerSecrets.add(x);providerSecrets.add(s);
                        List<byte[]> revoked=new ArrayList<>();for(int i=0;i<1200;i++) revoked.add(AdminRecordsFix1Test.id(i));
                        var materials=new JoinHandshake.Materials(f.chain(),f.f.revocations(0,f.f.now,revoked,f.f.a),0,f.groupKey);
                        borrowed.set(materials);return new UdpEndpoint.JoinMaterials(x,s,materials);
                    },result->{issued.set(result);a.rememberPeer(result.certificate());a.setPeerAddress(Crypto.blake2s(result.identityKey()),result.address());});
                    try(var joiner=f.joiner(parsed)) {
                        var ready=b.join(parsed,joiner,joined->{
                            byte[] groupKey=joined.groupKey();
                            try { return new SessionManager(joined.state(),joined.certificate(),f.f.handshake,groupKey,joined.groupKeyVersion(),f.f.clock,System::nanoTime,256); }
                            finally { Crypto.wipe(groupKey); }
                        });
                        ready.get(10,TimeUnit.SECONDS);
                        assertEquals(originalPort,socketB.getLocalPort());assertNotNull(issued.get());assertEquals(1,calls.get());
                        for(byte[] secret:providerSecrets) SecretAssertions.zero(secret);
                        SecretAssertions.zero(SecretAssertions.bytes(borrowed.get(),"groupKey"));
                        byte[] adminId=Crypto.blake2s(Crypto.ed25519Public(identity)),joinId=Crypto.blake2s(Crypto.ed25519Public(f.f.identity));
                        b.rememberPeer(adminCert);b.setPeerAddress(adminId,(InetSocketAddress)socketA.getLocalSocketAddress());b.start(adminId);
                        UdpEndpointTest.await(()->a.isEstablished(joinId)&&b.isEstablished(adminId));
                        assertTrue(a.send(joinId,new byte[]{4}));assertArrayEquals(new byte[]{4},inboxB.poll(5,TimeUnit.SECONDS));
                        assertTrue(b.send(adminId,new byte[]{5}));assertArrayEquals(new byte[]{5},inboxA.poll(5,TimeUnit.SECONDS));
                        assertTrue(faults.fragments.get()>30);assertTrue(faults.dropped);assertTrue(faults.reordered);
                    }
                }
            }
        }
    }
    static class JoinFaultIo extends UdpEndpoint.SocketIo {
        final AtomicInteger fragments=new AtomicInteger();boolean dropped,reordered;byte[] held;
        JoinFaultIo(DatagramSocket socket) { super(socket); }
        @Override public synchronized void send(byte[] wire,InetSocketAddress target) throws java.io.IOException {
            if(JoinWire.isJoin(wire) && JoinWire.decode(wire).kind()==JoinWire.DATA) {
                int n=JoinWire.decode(wire).index();fragments.incrementAndGet();
                if(n==0&&!dropped) { dropped=true;return; }
                if(n==1&&!reordered) { held=wire.clone();return; }
                if(n==2&&held!=null) { super.send(wire,target);super.send(held,target);Crypto.wipe(held);held=null;reordered=true;return; }
                super.send(wire,target);super.send(wire,target);return;
            }
            super.send(wire,target);
        }
    }
}
