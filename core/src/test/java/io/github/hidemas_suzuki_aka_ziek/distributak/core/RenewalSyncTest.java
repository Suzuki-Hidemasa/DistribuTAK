// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.JoinPortLimitsTest.SOURCE;
class RenewalSyncTest {
    final SessionManagerTest f=new SessionManagerTest();
    CotSync sync(SessionManagerTest.Node node,CotSync.Sender sender) {
        return new CotSync(node.id,new SyncState(f.group,node.id),f.time,()->f.time.nanos,state->{},sender,item->{},new SecureRandom(),0);
    }
    List<Integer> fields(byte[] wire) throws java.io.IOException {
        var input=com.google.protobuf.CodedInputStream.newInstance(wire);var result=new ArrayList<Integer>();
        for(int tag;(tag=input.readTag())!=0;) { result.add(tag>>>3);input.skipField(tag); }return result;
    }
    @Test void fieldEightAloneIsSentAgainWithSameBytesAndValidatedBeforeNotification() throws Exception {
        var io=new JoinPortLimitsTest.MemoryIo();var memberIo=new JoinPortLimitsTest.MemoryIo();
        try(var admin=f.new Node(31);var member=f.new Node(2)) {
            f.time.millis=member.cert.expiresAt()-AdminRecords.CERTIFICATE_LIFETIME_MILLIS/3;
            // 自己更新を保存してから、通常のセッション管理へ渡す順を再現する。
            var own=admin.state.renewOwnCertificate(admin.cert,admin.secret,f.admin,f.admin);admin.sessions.updateLocalCertificate(own);
            f.connect(admin,member);
            try(var endpoint=new UdpEndpoint(admin.sessions,admin.state,io,(id,p)->{},Duration.ofDays(1));
                var receiver=new UdpEndpoint(member.sessions,member.state,memberIo,(id,p)->{},Duration.ofDays(1));
                var outgoing=sync(admin,endpoint::sendIfSession);var incoming=sync(member,receiver::sendIfSession)) {
                endpoint.setPeerAddress(member.id,SOURCE);receiver.setPeerAddress(admin.id,SOURCE);
                List<AdminRecords.Record> accepted=new ArrayList<>();outgoing.certificateRenewals(endpoint,c->fail());incoming.certificateRenewals(receiver,accepted::add);
                var saved=admin.state.issueCertificateRenewal(member.cert,member.cert.field(2),f.admin,RenewalMessage.Reason.AUTO_RENEWAL,null);
                byte[] delivery=SyncWire.renewal(saved.encode());
                outgoing.connected(member.id,endpoint.sessionId(member.id));incoming.connected(admin.id,receiver.sessionId(admin.id));
                while(!io.output.isEmpty())member.sessions.receive(io.take().wire());
                assertTrue(endpoint.sendIfSession(member.id,endpoint.sessionId(member.id),delivery));byte[] first=member.sessions.receive(io.take().wire()).plaintext();
                var envelope=SyncWire.parse(first);assertTrue(envelope.hasRenewal());
                assertEquals(List.of(1,8),fields(first));
                assertEquals(List.of(1),fields(envelope.getRenewal().toByteArray()));
                incoming.receive(admin.id,receiver.sessionId(admin.id),first);assertEquals(1,accepted.size());
                assertArrayEquals(member.cert.encode(),SessionManagerTest.field(member.sessions,"localCertificate") instanceof AdminRecords.Record r ? r.encode() : null);
                f.time.millis++;assertTrue(endpoint.sendIfSession(member.id,endpoint.sessionId(member.id),delivery));
                byte[] second=member.sessions.receive(io.take().wire()).plaintext();assertArrayEquals(first,second);
                assertArrayEquals(member.cert.encode(),admin.sessions.peerCertificate(member.id).encode());
                byte[] bad=accepted.get(0).encode();bad[bad.length-1]^=1;
                long rejected=incoming.statistics().rejected();incoming.receive(admin.id,receiver.sessionId(admin.id),SyncWire.renewal(bad));
                assertEquals(rejected+1,incoming.statistics().rejected());assertEquals(1,accepted.size());assertFalse(incoming.isClosed());
                member.sessions.updateLocalCertificate(accepted.get(0));incoming.receive(admin.id,receiver.sessionId(admin.id),first);assertEquals(1,accepted.size());
            }
        }
    }
    @Test void renewalCannotMixWithCotOrUnknownNestedFields() {
        try(var member=f.new Node(2)) {
            byte[] wire=SyncWire.renewal(member.cert.encode());
            assertThrows(IllegalArgumentException.class,()->SyncWire.parse(Crypto.concat(wire,new byte[]{34,0})));
            assertThrows(IllegalArgumentException.class,()->SyncWire.parse(new byte[]{8,1,66,2,16,1}));
            assertThrows(IllegalArgumentException.class,()->SyncWire.parse(new byte[]{8,1,74,0}));
        }
    }
    @Test void legacyR18RejectsOnlyRenewalAndUdpContinuesWithCotData() throws Exception {
        var io=new JoinPortLimitsTest.MemoryIo();var rejected=new AtomicLong();var delivered=new LinkedBlockingQueue<CotRecord>();
        try(var a=f.new Node(31);var b=f.new Node(2)) {
            f.connect(a,b);
            try(var cot=new CotSync(b.id,new SyncState(f.group,b.id),f.time,()->f.time.nanos,s->{},(id,session,wire)->true,delivered::add,new SecureRandom(),0)) {
                cot.connected(a.id,b.sessions.sessionId(a.id));
                var handler=new UdpEndpoint.Receiver() {
                    public void receive(byte[] id,byte[] plain){fail();}
                    public void receive(byte[] id,byte[] session,byte[] plain) {
                        try { LegacyR18SyncWire.parse(plain);cot.receive(id,session,plain);cot.flush(); }
                        catch(IllegalArgumentException|SecurityException e){rejected.incrementAndGet();}
                    }
                };
                try(var endpoint=new UdpEndpoint(b.sessions,b.state,io,handler,Duration.ofDays(1))) {
                    byte[] renewal=SyncWire.renewal(b.cert.encode());assertThrows(IllegalArgumentException.class,()->LegacyR18SyncWire.parse(renewal));
                    io.inject(a.sessions.send(b.id,renewal).get(0).packet(),SOURCE);UdpEndpointTest.await(()->rejected.get()==1);
                    assertEquals(UdpEndpoint.CloseReason.RUNNING,endpoint.closeReason());assertTrue(endpoint.isEstablished(a.id));
                    byte[] xml=CotRecordTest.xml("legacy",f.time.millis+60000);
                    var item=CotRecord.record("legacy",f.time.millis,a.id,f.time.millis+60000,xml,1);
                    io.inject(a.sessions.send(b.id,SyncWire.encode(item)).get(0).packet(),SOURCE);
                    assertNotNull(delivered.poll(3,TimeUnit.SECONDS));assertEquals(UdpEndpoint.CloseReason.RUNNING,endpoint.closeReason());
                }
            }
        }
    }
}
