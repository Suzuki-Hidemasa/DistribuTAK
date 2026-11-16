// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;
import java.time.*;
import java.util.Arrays;
public class RenewalFirstProgressTest {
    static boolean initiator(UdpEndpoint endpoint,byte[] id)throws Exception {
        var sessions=(SessionManager)LanControllerHarness.field(endpoint,"sessions");
        synchronized(sessions) {
            var method=SessionManager.class.getDeclaredMethod("peer",byte[].class);method.setAccessible(true);
            Object peer=method.invoke(sessions,id),active=LanControllerHarness.field(peer,"active");
            return active!=null&&(boolean)LanControllerHarness.field(active,"initiator");
        }
    }
    static LanControllerHarness.Disk[] savedPair(boolean adopted,boolean modern)throws Exception {
        var disks=LanProofRenewalTest.legacyPair();long issued=LanControllerHarness.CLOCK.millis()+10L*86_400_000;
        var issuedClock=Clock.fixed(Instant.ofEpochMilli(issued),ZoneOffset.UTC);
        try(var a=disks[0].load(issuedClock);var m=disks[1].load(issuedClock)) {
            byte[] x=StoredUpdatesTest.key(80),y=StoredUpdatesTest.key(81);
            boolean smaller=AdminRecords.compareBytes(Crypto.x25519Public(x),Crypto.x25519Public(y))<0;
            a.handshakeSecret=smaller?x:y;m.handshakeSecret=smaller?y:x;
            var ca=AdminRecords.certificate(a.groupId,Crypto.ed25519Public(a.identitySecret),Crypto.x25519Public(a.handshakeSecret),
                    SignaturePurpose.identityProof(a.identitySecret,a.groupId,Crypto.x25519Public(a.handshakeSecret)),a.certificate.issuedAt(),a.administratorSecret);
            var cm=AdminRecords.certificate(m.groupId,Crypto.ed25519Public(m.identitySecret),Crypto.x25519Public(m.handshakeSecret),
                    SignaturePurpose.identityProof(m.identitySecret,m.groupId,Crypto.x25519Public(m.handshakeSecret)),m.certificate.issuedAt(),a.administratorSecret);
            ca=LegacyRecords.record(ca,a.identitySecret,a.administratorSecret);cm=LegacyRecords.record(cm,m.identitySecret,a.administratorSecret);
            LegacyRecords.install(a,ca,cm,a.administratorSecret,issuedClock);LegacyRecords.install(m,cm,ca,a.administratorSecret,issuedClock);
            var fresh=AdminRecords.certificate(m.groupId,cm.field(0),cm.field(1),SignaturePurpose.identityProof(m.identitySecret,m.groupId,cm.field(1)),issued,a.administratorSecret);
            if(!modern)fresh=LegacyRecords.record(fresh,m.identitySecret,a.administratorSecret);
            byte[] pending;
            if(modern) {
                var request=RenewalMessage.request(cm,new byte[16],a.urlAdmin,RenewalMessage.Reason.AUTO_RENEWAL,null);
                pending=RenewalMessage.delivery(request,fresh.encode()).pendingValue();
            }else {a.state.trustStoredLegacyCertificate(fresh);pending=fresh.encode();}
            a.rememberRenewal(m.id(),pending);disks[0].save(a);
            if(adopted) {m.certificate=fresh;m.state.trustStoredLegacyCertificate(fresh);m.renewalCount=1;}
            disks[1].save(m);
        }
        return disks;
    }
    @Test public void simultaneousSmallerAdministratorConfirmsAdoptedLegacyPending()throws Exception {progress(true,false,true);}
    @Test public void simultaneousSmallerAdministratorDiscardsUnusedLegacyPendingAndMigrates()throws Exception {progress(false,false,true);}
    @Test public void administratorAloneStartsAndConfirmsAdoptedLegacyPending()throws Exception {progress(true,false,false);}
    @Test public void administratorAloneStartsAndDiscardsUnusedLegacyPending()throws Exception {progress(false,false,false);}
    @Test public void restartedAdministratorSeesNewCertificateInSecondButWaitsForFirst()throws Exception {progress(true,true,false);}
    @Test public void restartedAdministratorCanDeliverStillUnusedSavedCertificate()throws Exception {progress(false,true,false);}
    static void receiveOnly(LanControllerHarness member,byte[] id)throws Exception {
        // 管理者がいない間に失われた初回FIRSTを片付け、待ち受けだけの順序を固定する。
        var sessions=(SessionManager)LanControllerHarness.field(member.endpoint(),"sessions");
        synchronized(sessions) {
            var peerMethod=SessionManager.class.getDeclaredMethod("peer",byte[].class);peerMethod.setAccessible(true);Object peer=peerMethod.invoke(sessions,id);
            var drop=SessionManager.class.getDeclaredMethod("dropPending",peer.getClass());drop.setAccessible(true);drop.invoke(sessions,peer);
            var attempt=peer.getClass().getDeclaredField("attempt");attempt.setAccessible(true);attempt.set(peer,null);
            var exhausted=peer.getClass().getDeclaredField("exhausted");exhausted.setAccessible(true);exhausted.setBoolean(peer,true);
        }
    }
    void progress(boolean adopted,boolean modern,boolean simultaneous)throws Exception {
        var disks=savedPair(adopted,modern);var wall=new LanAutomaticRenewalTest.Wall();wall.now.addAndGet(20L*86_400_000);
        try(var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            byte[] administrator;try(var saved=disks[0].load(wall)){administrator=saved.id();}
            if(!simultaneous)receiveOnly(member,administrator);
            var gate=FirstPacketGate.install(member.endpoint());
            try{
            try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall)) {
            byte[] a=LanBehaviourWiringTest.group(admin).id(),m=LanBehaviourWiringTest.group(member).id();
            LanProofRenewalTest.until(()->admin.endpoint().isEstablished(m)&&member.endpoint().isEstablished(a),admin,member);
            try{
                assertTrue(initiator(admin.endpoint(),m));assertNull(admin.endpoint().authenticatedFirstCertificate(m));
                assertNotNull(LanBehaviourWiringTest.group(admin).pendingRenewal(m));
                assertEquals(1,LanBehaviourWiringTest.group(admin).peerCertificate.format());
            }finally{gate.release();}
            // 試験からメンバーのstartを呼ばない。製品の処理だけでFIRSTと保存の確定を進める。
            LanProofRenewalTest.until(()->LanBehaviourWiringTest.group(admin).pendingRenewal(m)==null
                    &&(adopted||LanBehaviourWiringTest.group(member).certificate.format()==2),admin,member);
            assertNotNull(admin.endpoint().authenticatedFirstCertificate(m));
            assertEquals(1,LanBehaviourWiringTest.group(member).renewalCount);
            assertTrue(Arrays.equals(LanBehaviourWiringTest.group(member).certificate.encode(),LanBehaviourWiringTest.group(admin).peerCertificate.encode()));
            assertFalse(disks[0].erased);assertFalse(disks[1].erased);
            }
            }finally{gate.release();}
        }
    }
    static final class FirstTap {
        final java.util.concurrent.atomic.AtomicInteger count=new java.util.concurrent.atomic.AtomicInteger();
        final boolean drop;
        FirstTap(UdpEndpoint endpoint,boolean drop)throws Exception {
            this.drop=drop;var field=UdpEndpoint.class.getDeclaredField("io");field.setAccessible(true);
            var original=(UdpEndpoint.DatagramIo)field.get(endpoint);
            field.set(endpoint,new UdpEndpoint.DatagramIo(){
                public UdpEndpoint.Datagram receive()throws java.io.IOException{return original.receive();}
                public void send(byte[] wire,java.net.InetSocketAddress target)throws java.io.IOException {
                    boolean first=false;try{first=SessionPacket.decode(wire).kind()==SessionPacket.FIRST;}catch(RuntimeException ignored){}
                    if(first){count.incrementAndGet();if(FirstTap.this.drop)return;}original.send(wire,target);
                }
                public void close(){original.close();}
            });
        }
    }
    static void endpointTick(LanControllerHarness node)throws Exception {
        var method=UdpEndpoint.class.getDeclaredMethod("tick");method.setAccessible(true);method.invoke(node.endpoint());node.tick();
    }
    @Test public void failedMemberFirstStopsAfterOneNinetySecondAttempt()throws Exception {
        var disks=savedPair(true,false);var wall=new LanAutomaticRenewalTest.Wall();wall.now.addAndGet(20L*86_400_000);
        try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall);var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            byte[] a=LanBehaviourWiringTest.group(admin).id(),m=LanBehaviourWiringTest.group(member).id();
            LanProofRenewalTest.until(()->admin.endpoint().isEstablished(m)&&member.endpoint().isEstablished(a),admin,member);
            var tap=new FirstTap(member.endpoint(),true);
            for(int i=0;i<20;i++) {
                admin.offset.addAndGet(5_000_000_000L);member.offset.addAndGet(5_000_000_000L);
                endpointTick(member);endpointTick(admin);
            }
            int completed=tap.count.get();assertTrue(completed>1);assertTrue(completed<=18);
            for(int i=0;i<2;i++) {
                admin.offset.addAndGet(5_000_000_000L);member.offset.addAndGet(5_000_000_000L);
                endpointTick(member);endpointTick(admin);
            }
            assertEquals(completed,tap.count.get());assertNotNull(LanBehaviourWiringTest.group(admin).pendingRenewal(m));
        }
    }
    @Test public void memberInitiatedSessionDoesNotStartAnotherFirst()throws Exception {
        var disks=LanProofRenewalTest.legacyPair();
        // 管理者を止めた状態でメンバーだけを送り手にし、その後管理者を受け手として開く。
        try(var member=new LanControllerHarness(disks[1]);var admin=new LanControllerHarness(disks[0])) {
            byte[] a=LanBehaviourWiringTest.group(admin).id(),m=LanBehaviourWiringTest.group(member).id();
            LanProofRenewalTest.until(()->admin.endpoint().isEstablished(m)&&member.endpoint().isEstablished(a),admin,member);
            // 既存の確立した接続でメンバーのFIRSTを1回通し、送り手を固定する。
            member.offset.addAndGet(5_000_000_000L);member.endpoint().start(a);
            LanProofRenewalTest.until(()->initiator(member.endpoint(),a)&&!initiator(admin.endpoint(),m),admin,member);
            var tap=new FirstTap(member.endpoint(),false);byte[] session=member.endpoint().sessionId(a);
            member.offset.addAndGet(10_000_000_000L);admin.offset.addAndGet(10_000_000_000L);
            for(int i=0;i<5;i++){endpointTick(member);endpointTick(admin);}
            assertEquals(0,tap.count.get());assertTrue(Arrays.equals(session,member.endpoint().sessionId(a)));
        }
    }
    @Test public void conditionalStartRejectsSessionChangedBetweenQueryAndStart()throws Exception {
        for(boolean local:new boolean[]{true,false}) {
            var disks=savedPair(true,false);var wall=new LanAutomaticRenewalTest.Wall();wall.now.addAndGet(20L*86_400_000);
            try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall);var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
                byte[] a=LanBehaviourWiringTest.group(admin).id(),m=LanBehaviourWiringTest.group(member).id();
                LanProofRenewalTest.until(()->admin.endpoint().isEstablished(m)&&member.endpoint().isEstablished(a),admin,member);
                byte[] observed=member.endpoint().sessionId(a);assertTrue(member.endpoint().isPeerInitiatedSession(a,observed));
                // 読み口のあとに別の握手を完了させ、古い判断で開始しようとする順を固定する。
                wall.now.addAndGet(1000);member.offset.addAndGet(5_000_000_000L);admin.offset.addAndGet(5_000_000_000L);
                if(local)member.endpoint().start(a);else admin.endpoint().start(m);
                LanProofRenewalTest.until(()->!Arrays.equals(observed,member.endpoint().sessionId(a))
                        &&Arrays.equals(member.endpoint().sessionId(a),admin.endpoint().sessionId(m)),admin,member);
                var tap=new FirstTap(member.endpoint(),false);assertFalse(member.endpoint().start(a,observed));assertEquals(0,tap.count.get());
            }
        }
    }
}
