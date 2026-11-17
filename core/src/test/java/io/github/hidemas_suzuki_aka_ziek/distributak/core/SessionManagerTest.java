// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class SessionManagerTest {
    static class Time extends Clock {
        long millis=10_000_000_000L,nanos;
        public ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(ZoneId zone) { return this; }
        public Instant instant() { return Instant.ofEpochMilli(millis); }
        public long millis() { return millis; }
        void advance(long seconds) { nanos+=Duration.ofSeconds(seconds).toNanos();millis+=seconds*1000; }
    }
    final Time time=new Time();
    final byte[] group=key(30),admin=key(31),psk=key(32);
    class Node implements AutoCloseable {
        final byte[] identity,secret,id;
        final AdminState state;
        AdminRecords.Record cert;
        final SessionManager sessions;
        Node(int n) { this(n,256); }
        Node(int n,int limit) { this(n,limit,time.millis()); }
        Node(int n,int limit,long issuedAt) {
            identity=key(n);secret=key(n+10);id=Crypto.blake2s(Crypto.ed25519Public(identity));
            state=new AdminState(group,Crypto.ed25519Public(admin),time,new InMemoryAdminRecordStore());
            var admins=AdminRecords.list(ADMINS,group,0,time.millis(),List.of(Crypto.ed25519Public(admin)),admin);
            state.bootstrap(admins,AdminRecords.signAnchor(admins,admin));
            state.acceptRevocations(AdminRecords.list(REVOCATIONS,group,0,time.millis(),List.of(),admin));
            cert=certificate(secret,issuedAt);
            sessions=new SessionManager(state,cert,secret,psk,0,time,()->time.nanos,limit);
        }
        AdminRecords.Record certificate(byte[] handshake,long issued) {
            byte[] pub=Crypto.x25519Public(handshake);
            return AdminRecords.certificate(group,Crypto.ed25519Public(identity),pub,SignaturePurpose.identityProof(identity,group,pub),issued,admin);
        }
        void remember(Node other) { sessions.rememberPeer(other.cert); }
        public void close() { sessions.close(); }
    }
    void connect(Node a,Node b) {
        a.remember(b);b.remember(a);
        var second=b.sessions.receive(a.sessions.start(b.id).packet());
        var confirm=a.sessions.receive(second.outbound().get(0).packet());
        assertFalse(b.sessions.isEstablished(a.id));
        b.sessions.receive(confirm.outbound().get(0).packet());
        assertTrue(a.sessions.isEstablished(b.id));assertTrue(b.sessions.isEstablished(a.id));
    }
    byte[] data(Node a,Node b,int value) {
        var sent=a.sessions.send(b.id,new byte[]{(byte)value});
        return sent.get(sent.size()-1).packet();
    }
    static Object field(Object object,String name) throws Exception {
        var field=object.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(object);
    }
    Object peerState(Node node,Node remote) throws Exception {
        return ((Map<?,?>)field(node.sessions,"peers")).get(org.bouncycastle.util.encoders.Hex.toHexString(remote.id));
    }
    NoiseTransport active(Node node,Node remote) throws Exception {
        return (NoiseTransport)field(field(peerState(node,remote),"active"),"transport");
    }
    List<byte[]> secrets(Node node,Node remote) throws Exception {
        var result=new ArrayList<byte[]>();Object peer=peerState(node,remote);
        for(String slot:List.of("active","candidate")) {
            Object c=field(peer,slot);
            if(c!=null) { Object t=field(c,"transport");result.add((byte[])field(t,"sending"));result.add((byte[])field(t,"receiving")); }
        }
        Object pending=field(peer,"pending");
        if(pending!=null) {
            Object noise=field(field(pending,"handshake"),"noise");
            for(String name:List.of("s","e","psk","ck","k")) { byte[] value=(byte[])field(noise,name);if(value!=null) result.add(value); }
        }
        assertTrue(result.stream().anyMatch(bytes->!Arrays.equals(bytes,new byte[bytes.length])));
        return result;
    }
    void wiped(List<byte[]> values) { for(byte[] value:values) assertArrayEquals(new byte[value.length],value); }
    @Test void establishOffsetsAndLossReorderingDuplicateTamper() {
        try(var a=new Node(1);var b=new Node(2)) {
            connect(a,b);assertEquals(Duration.ZERO,a.sessions.peerClockOffset(b.id));
            byte[] p0=data(a,b,0),p1=data(a,b,1),p2=data(a,b,2);
            assertArrayEquals(new byte[]{2},b.sessions.receive(p2).plaintext());
            assertArrayEquals(new byte[]{0},b.sessions.receive(p0).plaintext());
            assertThrows(SecurityException.class,()->b.sessions.receive(p2));
            byte[] bad=p1.clone();bad[bad.length-1]^=1;
            assertThrows(SecurityException.class,()->b.sessions.receive(bad));
            assertArrayEquals(new byte[]{1},b.sessions.receive(p1).plaintext());
        }
    }
    @Test void timedRekeyKeepsOldUntilConfirmedAndSwitches() throws Exception {
        try(var a=new Node(1);var b=new Node(2)) {
            connect(a,b);var aOld=secrets(a,b);var bOld=secrets(b,a);
            time.advance(119);assertTrue(a.sessions.poll().isEmpty());
            time.advance(1);var retry=a.sessions.poll();assertEquals(1,retry.size());
            assertTrue(a.sessions.isEstablished(b.id));
            var reply=b.sessions.receive(retry.get(0).packet());
            assertTrue(b.sessions.isEstablished(a.id));
            assertArrayEquals(new byte[]{5},b.sessions.receive(data(a,b,5)).plaintext());
            var confirmation=a.sessions.receive(reply.outbound().get(0).packet());
            wiped(aOld);assertFalse(active(b,a).isClosed());
            b.sessions.receive(confirmation.outbound().get(0).packet());
            wiped(bOld);
            assertArrayEquals(new byte[]{6},b.sessions.receive(data(a,b,6)).plaintext());
        }
    }
    @Test void groupRotationAndNoProofDoesNotReplaceOld() throws Exception {
        try(var a=new Node(1);var b=new Node(2);var c=new Node(3)) {
            connect(a,b);connect(a,c);var aOld=secrets(a,b);var bOld=secrets(b,a);var cOld=secrets(a,c);
            a.sessions.rotateGroupKey(key(40),1);b.sessions.rotateGroupKey(key(40),1);
            var request=a.sessions.poll().get(0);var reply=b.sessions.receive(request.packet());
            assertArrayEquals(new byte[]{7},b.sessions.receive(data(a,b,7)).plaintext());
            var confirm=a.sessions.receive(reply.outbound().get(0).packet());
            wiped(aOld);assertFalse(active(b,a).isClosed());
            b.sessions.receive(confirm.outbound().get(0).packet());
            wiped(bOld);assertTrue(a.sessions.isEstablished(c.id));
            assertArrayEquals(new byte[]{8},a.sessions.receive(data(b,a,8)).plaintext());
            time.advance(179);time.nanos+=999_999_999L;a.sessions.refresh();assertTrue(a.sessions.isEstablished(c.id));
            time.nanos++;a.sessions.refresh();assertFalse(a.sessions.isEstablished(c.id));wiped(cOld);
            assertTrue(a.sessions.isEstablished(b.id));
        }
    }
    @Test void managementPauseUsesTheExistingRotationDeadline() throws Exception {
        try(var a=new Node(1);var b=new Node(2)) {
            connect(a,b);
            var method=SessionManager.class.getMethod("hasRotatingSessions");
            assertEquals(false,method.invoke(a.sessions));a.sessions.rotateGroupKey(key(40),1);
            assertEquals(true,method.invoke(a.sessions));time.advance(179);
            a.sessions.rotateGroupKey(key(41),2);assertEquals(true,method.invoke(a.sessions));
            time.advance(1);assertEquals(false,method.invoke(a.sessions));
        }
    }
    @Test void rotationDeadlineAndTransportAgeBoundary() throws Exception {
        try(var a=new Node(1);var b=new Node(2)) {
            connect(a,b);var old=secrets(a,b);a.sessions.rotateGroupKey(key(40),1);
            time.advance(179);a.sessions.refresh();assertTrue(a.sessions.isEstablished(b.id));
            time.advance(1);a.sessions.refresh();assertFalse(a.sessions.isEstablished(b.id));wiped(old);
        }
        time.nanos=0;
        try(var a=new Node(1);var b=new Node(2)) {
            connect(a,b);time.advance(180);a.sessions.refresh();assertTrue(a.sessions.isEstablished(b.id));
            time.advance(1);a.sessions.refresh();assertFalse(a.sessions.isEstablished(b.id));
        }
    }
    @Test void failuresAndCloseAllDoNotDamageOtherPeer() throws Exception {
        try(var a=new Node(1);var b=new Node(2);var c=new Node(3)) {
            connect(a,b);connect(a,c);time.advance(1);
            var first=a.sessions.start(b.id).packet();var reply=b.sessions.receive(first).outbound().get(0).packet();
            var attempt=secrets(a,b);
            reply[reply.length-1]^=1;
            assertThrows(SecurityException.class,()->a.sessions.receive(reply));
            assertFalse(a.sessions.isHandshaking(b.id));
            wiped(attempt.subList(2,attempt.size()));
            assertArrayEquals(new byte[]{9},c.sessions.receive(data(a,c,9)).plaintext());
            a.sessions.close();assertFalse(a.sessions.isEstablished(b.id));assertFalse(a.sessions.isEstablished(c.id));
            assertThrows(IllegalStateException.class,()->a.sessions.start(b.id));
            assertThrows(IllegalStateException.class,()->a.sessions.receive(first));
        }
    }
    @Test void immediateRevocationExpiryAndKeyChangeAreIsolated() throws Exception {
        for(int cause=0;cause<3;cause++) {
            time.nanos=0;
            try(var a=new Node(1);var b=new Node(2,256,cause==1 ? time.millis()-AdminRecords.CERTIFICATE_LIFETIME_MILLIS+1000 : time.millis());var c=new Node(3)) {
                connect(a,b);connect(a,c);
                a.sessions.start(b.id);var old=secrets(a,b);
                if(cause==0) a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,group,1,time.millis(),List.of(b.id),admin));
                if(cause==1) time.advance(1);
                if(cause==2) {
                    time.advance(1);a.sessions.rememberPeer(b.certificate(key(50),time.millis()));
                }
                a.sessions.refresh();assertFalse(a.sessions.isEstablished(b.id));assertTrue(a.sessions.isEstablished(c.id));
                assertFalse(a.sessions.isHandshaking(b.id));wiped(old);
                assertArrayEquals(new byte[]{1},c.sessions.receive(data(a,c,1)).plaintext());
            }
        }
    }
    @Test void retryFiveSecondsLostResponseLostConfirmationAndTimeout() throws Exception {
        try(var a=new Node(1);var b=new Node(2)) {
            a.remember(b);b.remember(a);
            byte[] first=a.sessions.start(b.id).packet();
            b.sessions.receive(first); // 2通目を落とす。
            time.advance(4);assertTrue(a.sessions.poll().isEmpty());
            time.advance(1);var retry=a.sessions.poll();assertEquals(1,retry.size());assertArrayEquals(first,retry.get(0).packet());
            byte[] second=b.sessions.receive(retry.get(0).packet()).outbound().get(0).packet();
            a.sessions.receive(second); // 確認を落とす。重なった2通目で別のnonceの確認を返す。
            assertFalse(b.sessions.isEstablished(a.id));
            time.advance(5);
            var responseRetry=b.sessions.poll();assertEquals(1,responseRetry.size());
            assertArrayEquals(second,responseRetry.get(0).packet());
            b.sessions.receive(a.sessions.receive(responseRetry.get(0).packet()).outbound().get(0).packet());
            assertArrayEquals(new byte[]{1},b.sessions.receive(data(a,b,1)).plaintext());
            time.advance(1);a.sessions.start(b.id);var pending=secrets(a,b);
            // active の鍵は消さず、pending の鍵だけが90秒で消える。
            var pendingOnly=pending.subList(2,pending.size());
            time.advance(89);assertTrue(a.sessions.isHandshaking(b.id));
            time.advance(1);assertTrue(a.sessions.poll().isEmpty());assertFalse(a.sessions.isHandshaking(b.id));wiped(pendingOnly);
            time.advance(1);assertTrue(a.sessions.poll().isEmpty());
            assertTrue(a.sessions.isEstablished(b.id));
        }
    }
    @Test void unconfirmedCandidateTimesOutAndWipesWithoutReplacingOld() throws Exception {
        try(var a=new Node(1);var b=new Node(2)) {
            connect(a,b);time.advance(1);
            b.sessions.receive(a.sessions.start(b.id).packet());
            var keys=secrets(b,a);var candidate=keys.subList(2,keys.size());
            time.advance(89);assertTrue(b.sessions.isHandshaking(a.id));assertTrue(b.sessions.isEstablished(a.id));
            time.advance(1);b.sessions.refresh();assertFalse(b.sessions.isHandshaking(a.id));wiped(candidate);
            assertArrayEquals(new byte[]{1},b.sessions.receive(data(a,b,1)).plaintext());
        }
    }
    @Test void simultaneousStartConvergesInBothDeliveryOrdersIncludingLateLosingFirst() throws Exception {
        for(int order=0;order<3;order++) {
            try(var a=new Node(1);var b=new Node(2)) {
                a.remember(b);b.remember(a);
                byte[] af=a.sessions.start(b.id).packet(),bf=b.sessions.start(a.id).packet();
                Node low=AdminRecords.compareBytes(Crypto.x25519Public(a.secret),Crypto.x25519Public(b.secret))<0 ? a : b;
                Node high=low==a ? b : a;
                byte[] lf=low==a ? af : bf,hf=low==a ? bf : af;
                if(order==0) assertTrue(low.sessions.receive(hf).outbound().isEmpty());
                var reply=high.sessions.receive(lf).outbound().get(0).packet();
                if(order==1) assertTrue(low.sessions.receive(hf).outbound().isEmpty());
                var confirmation=low.sessions.receive(reply).outbound().get(0).packet();
                high.sessions.receive(confirmation);
                if(order==2) {
                    var late=low.sessions.receive(hf).outbound();assertEquals(1,late.size());
                    assertThrows(SecurityException.class,()->high.sessions.receive(late.get(0).packet()));
                    assertTrue(low.sessions.isHandshaking(high.id));assertFalse(high.sessions.isHandshaking(low.id));
                } else { assertFalse(a.sessions.isHandshaking(b.id));assertFalse(b.sessions.isHandshaking(a.id)); }
                assertArrayEquals(new byte[]{3},b.sessions.receive(data(a,b,3)).plaintext());
                assertArrayEquals(new byte[]{4},a.sessions.receive(data(b,a,4)).plaintext());
                if(order==2) {
                    time.advance(90);low.sessions.refresh();assertFalse(low.sessions.isHandshaking(high.id));
                    assertArrayEquals(new byte[]{5},high.sessions.receive(data(low,high,5)).plaintext());
                }
            }
        }
    }
    @Test void messageCountRekeysAndExactUpperLimitThenZeroes() throws Exception {
        try(var a=new Node(1);var b=new Node(2)) {
            connect(a,b);NoiseTransport t=active(a,b);
            var sent=NoiseTransport.class.getDeclaredField("sent");sent.setAccessible(true);
            sent.setLong(t,NoiseTransport.REKEY_MESSAGES-1);assertTrue(a.sessions.poll().isEmpty());
            assertArrayEquals(new byte[]{1},b.sessions.receive(data(a,b,1)).plaintext());
            var rekey=a.sessions.poll();assertEquals(1,rekey.size());assertTrue(a.sessions.isEstablished(b.id));
            var reply=b.sessions.receive(rekey.get(0).packet());b.sessions.receive(a.sessions.receive(reply.outbound().get(0).packet()).outbound().get(0).packet());
            assertTrue(t.isClosed());
            t=active(a,b);sent.setLong(t,NoiseTransport.REJECT_AFTER);var old=secrets(a,b);
            assertArrayEquals(new byte[]{2},b.sessions.receive(data(a,b,2)).plaintext());
            assertThrows(SecurityException.class,()->data(a,b,3));assertFalse(a.sessions.isEstablished(b.id));wiped(old);
        }
    }
    @Test void badFirstDoesNotCommitTimestampOrDamageAnEstablishedPeer() throws Exception {
        try(var a=new Node(1);var b=new Node(2);var c=new Node(3)) {
            connect(b,c);a.remember(b);byte[] first=a.sessions.start(b.id).packet(),bad=first.clone();bad[bad.length-1]^=1;
            assertThrows(SecurityException.class,()->b.sessions.receive(bad));assertFalse(b.sessions.isHandshaking(a.id));
            assertArrayEquals(new byte[]{1},c.sessions.receive(data(b,c,1)).plaintext());
            var reply=b.sessions.receive(first);b.sessions.receive(a.sessions.receive(reply.outbound().get(0).packet()).outbound().get(0).packet());
            assertArrayEquals(new byte[]{2},b.sessions.receive(data(a,b,2)).plaintext());
        }
    }
    @Test void replayTimestampSurvivesRekeyTimeoutAndExpiryButCloseAllowsFreshManager() {
        try(var a=new Node(1);var b=new Node(2)) {
            a.remember(b);byte[] first=a.sessions.start(b.id).packet();
            var second=b.sessions.receive(first);b.sessions.receive(a.sessions.receive(second.outbound().get(0).packet()).outbound().get(0).packet());
            time.advance(91);
            assertThrows(SecurityException.class,()->b.sessions.receive(first));
            time.advance(91);b.sessions.refresh();assertFalse(b.sessions.isEstablished(a.id));
            assertThrows(SecurityException.class,()->b.sessions.receive(first));
            b.sessions.close();
            try(var rejoined=new SessionManager(b.state,b.cert,b.secret,psk,0,time,()->time.nanos,256)) {
                assertEquals(1,rejoined.receive(first).outbound().size());
            }
        }
    }
    @Test void allKeysIncludingPendingAndCandidateAreZeroedOnClose() throws Exception {
        try(var a=new Node(1);var b=new Node(2);var c=new Node(3);var d=new Node(4)) {
            connect(a,b);a.remember(c);a.sessions.start(c.id);d.remember(a);a.sessions.receive(d.sessions.start(a.id).packet());
            var all=new ArrayList<byte[]>();all.addAll(secrets(a,b));all.addAll(secrets(a,c));all.addAll(secrets(a,d));
            all.add((byte[])field(a.sessions,"localSecret"));all.add((byte[])field(a.sessions,"psk"));
            a.sessions.close();wiped(all);assertTrue(a.sessions.poll().isEmpty());
            assertThrows(IllegalStateException.class,()->a.sessions.start(b.id));
            assertThrows(IllegalStateException.class,()->a.sessions.receive(data(b,a,1)));
            // 呼び出し元の配列は書き換えない。
            assertArrayEquals(key(11),a.secret);assertArrayEquals(key(32),psk);
        }
    }
    @Test void capacityBoundAndMalformedPacketHavePositiveControls() {
        try(var a=new Node(1,2);var b=new Node(2);var c=new Node(3)) {
            connect(a,b);assertThrows(IllegalStateException.class,()->a.remember(c));
            c.remember(a);assertThrows(SecurityException.class,()->a.sessions.receive(c.sessions.start(a.id).packet()));
            byte[] valid=data(b,a,7);
            for(int position:new int[]{0,7,24,32,valid.length-1}) {
                byte[] bad=valid.clone();bad[position]^=1;
                assertThrows(RuntimeException.class,()->a.sessions.receive(bad));
            }
            assertThrows(IllegalArgumentException.class,()->a.sessions.receive(new byte[SessionPacket.MAX_SIZE+1]));
            assertArrayEquals(new byte[]{7},a.sessions.receive(valid).plaintext());
            byte[] max=new byte[SessionPacket.MAX_PLAINTEXT];
            var packet=a.sessions.send(b.id,max).get(0).packet();assertEquals(SessionPacket.MAX_SIZE,packet.length);
            assertArrayEquals(max,b.sessions.receive(packet).plaintext());
            assertThrows(IllegalArgumentException.class,()->a.sessions.send(b.id,new byte[max.length+1]));
        }
    }
    /** 上限で断った例外。握手側が包むので、固定の文は原因の側にある。どちらにも端末の番号を出さない。 */
    private static void assertRefusedByLimit(SecurityException refused,Node peer) {
        assertEquals("相手の数が上限に達しています",refused.getCause().getMessage());
        String hex=org.bouncycastle.util.encoders.Hex.toHexString(peer.id);
        assertFalse(refused.getMessage().contains(hex));assertFalse(refused.getCause().getMessage().contains(hex));
    }
    private int peerCount(Node node) throws Exception { return ((Map<?,?>)field(node.sessions,"peers")).size(); }
    /** 登録していない端末どうしの握手。a が受ける側（a は b を登録しない）。 */
    private void connectVolatile(Node a,Node b) {
        b.remember(a);
        var second=a.sessions.receive(b.sessions.start(a.id).packet());
        var confirm=b.sessions.receive(second.outbound().get(0).packet());
        a.sessions.receive(confirm.outbound().get(0).packet());
        assertTrue(a.sessions.isEstablished(b.id));assertTrue(b.sessions.isEstablished(a.id));
    }
    /** 登録（保存した相手・予約）が無い端末では、揮発の相手が台数-1 まで入れる（【メモの決定 2】(f)）。 */
    @Test void withoutRegistrationVolatilePeersFillAllSlots() {
        try(var a=new Node(1,4);var b=new Node(2);var c=new Node(3);var d=new Node(4);var e=new Node(5)) {
            b.remember(a);c.remember(a);d.remember(a);e.remember(a);
            assertNotNull(a.sessions.receive(b.sessions.start(a.id).packet()));
            assertNotNull(a.sessions.receive(c.sessions.start(a.id).packet()));
            assertNotNull(a.sessions.receive(d.sessions.start(a.id).packet()));
            var refused=assertThrows(SecurityException.class,()->a.sessions.receive(e.sessions.start(a.id).packet()));
            assertRefusedByLimit(refused,e);
        }
    }
    /** 保存した相手が登録されていれば、1 枠を空けておく。揮発は台数-2 まで。 */
    @Test void registeredStoredPeerKeepsOneSlotFree() throws Exception {
        try(var a=new Node(1,4);var b=new Node(2);var c=new Node(3);var d=new Node(4);var e=new Node(5)) {
            a.remember(e);
            b.remember(a);c.remember(a);d.remember(a);e.remember(a);
            assertNotNull(a.sessions.receive(b.sessions.start(a.id).packet()));
            assertNotNull(a.sessions.receive(c.sessions.start(a.id).packet()));
            var refused=assertThrows(SecurityException.class,()->a.sessions.receive(d.sessions.start(a.id).packet()));
            assertRefusedByLimit(refused,d);
            // すでにいる揮発の相手を保存した相手に切り替えても数は増えない。
            a.remember(b);assertEquals(3,peerCount(a));
            // 保存した相手の e は入れる。
            assertNotNull(a.sessions.receive(e.sessions.start(a.id).packet()));
        }
    }
    /** 台数 129（自分＋128 台。LanGroup.MAX_PEERS=128 と同じ）。保存した相手の 1 枠を残して、揮発の相手は 127 台まで。 */
    @Test void aGroupOf129ReservesOneSlotAndAdmitsOneHundredTwentySevenVolatilePeers() {
        var nodes=new ArrayList<Node>();
        try(var a=new Node(1,129);var stored=new Node(2)) {
            a.remember(stored);stored.remember(a);
            for(int n=3;n<=130;n++){var node=new Node(n);nodes.add(node);node.remember(a);}
            for(int i=0;i<127;i++)assertNotNull(a.sessions.receive(nodes.get(i).sessions.start(a.id).packet()),"volatile peer "+i);
            var last=nodes.get(127);
            var refused=assertThrows(SecurityException.class,()->a.sessions.receive(last.sessions.start(a.id).packet()));
            assertRefusedByLimit(refused,last);
            // 保存した相手には 1 枠が空いている。
            assertNotNull(a.sessions.receive(stored.sessions.start(a.id).packet()));
            assertEquals(128,peerCount(a));
        } catch(Exception e) {
            throw new AssertionError(e);
        } finally {
            for(var node:nodes)node.close();
        }
    }
    @Test void reservedFlagKeepsOneSlotFreeEvenBeforeStoredPeerArrives() {
        try(var a=new Node(1,3);var b=new Node(2);var c=new Node(3);var d=new Node(4)) {
            b.remember(a);c.remember(a);d.remember(a);
            a.sessions.setStoredSlotReserved(true);
            byte[] firstC=c.sessions.start(a.id).packet();
            assertNotNull(a.sessions.receive(b.sessions.start(a.id).packet()));
            assertThrows(SecurityException.class,()->a.sessions.receive(firstC));
            a.sessions.setStoredSlotReserved(false);
            assertNotNull(a.sessions.receive(firstC));
            assertThrows(SecurityException.class,()->a.sessions.receive(d.sessions.start(a.id).packet()));
        }
    }
    @Test void groupOfTwoRefusesUnregisteredPeersOnlyWhenStoredPeerIsRegistered() {
        try(var a=new Node(1,2);var b=new Node(2);var c=new Node(3)) {
            a.remember(b);b.remember(a);c.remember(a);
            assertThrows(SecurityException.class,()->a.sessions.receive(c.sessions.start(a.id).packet()));
            assertNotNull(a.sessions.receive(b.sessions.start(a.id).packet()));
        }
    }
    @Test void rememberingVolatilePeerMovesItToStoredWithoutCountingTwice() throws Exception {
        try(var a=new Node(1,5);var b=new Node(2);var c=new Node(3);var d=new Node(4);var e=new Node(5);var f=new Node(6)) {
            b.remember(a);c.remember(a);d.remember(a);e.remember(a);f.remember(a);
            a.sessions.receive(b.sessions.start(a.id).packet());a.sessions.receive(c.sessions.start(a.id).packet());
            a.sessions.receive(d.sessions.start(a.id).packet());
            assertEquals(3,peerCount(a));
            a.remember(b);assertEquals(3,peerCount(a));
            // b が保存の枠に移ったので登録がある。揮発の c・d・e で台数-1 の 4 台から 1 枠を空けた 3 台まで。
            assertNotNull(a.sessions.receive(e.sessions.start(a.id).packet()));
            assertThrows(SecurityException.class,()->a.sessions.receive(f.sessions.start(a.id).packet()));
            assertTrue(a.sessions.forgetVolatile(c.id));
            assertFalse(a.sessions.forgetVolatile(b.id));
            assertEquals(3,peerCount(a));
        }
    }
    /**
     * 揮発の相手で枠が埋まっているとき、保存する相手を入れるために、認証のパケットを最後に受けてから一番長い 1 台を手放す。
     * 表に入った順（b が先頭）ではなく、最後に認証を受けた時刻で決める。b は確認 DATA を受けたので最も新しい。
     */
    @Test void fullOfVolatilePeersReleasesThePeerWhoseAuthenticatedPacketIsOldest() throws Exception {
        try(var a=new Node(1,4);var b=new Node(2);var c=new Node(3);var d=new Node(4);var f=new Node(6)) {
            b.remember(a);c.remember(a);d.remember(a);
            var secondB=a.sessions.receive(b.sessions.start(a.id).packet());time.advance(1);
            byte[] firstC=c.sessions.start(a.id).packet();
            a.sessions.receive(firstC);time.advance(1);
            a.sessions.receive(d.sessions.start(a.id).packet());time.advance(1);
            var confirmB=b.sessions.receive(secondB.outbound().get(0).packet());
            a.sessions.receive(confirmB.outbound().get(0).packet());time.advance(1);
            assertTrue(a.sessions.isEstablished(b.id));assertEquals(3,peerCount(a));
            var keysC=secrets(a,c);
            assertDoesNotThrow(()->a.remember(f));
            wiped(keysC);
            assertNull(peerState(a,c));assertFalse(a.sessions.hasPeer(c.id));
            assertNotNull(peerState(a,b));assertNotNull(peerState(a,d));assertNotNull(peerState(a,f));
            assertEquals(3,peerCount(a));assertTrue(a.sessions.isEstablished(b.id));
            // 保存した f は揮発ではない。手放した c の古い 1 通目は、時刻の記録が残っているので受けない。
            assertFalse(a.sessions.isUnregistered(f.id));assertFalse(a.sessions.forgetVolatile(f.id));
            assertThrows(SecurityException.class,()->a.sessions.receive(firstC));
        }
    }
    /** 手放すのは揮発の相手だけ。保存した相手は、表に入った時刻が一番古くても残す。 */
    @Test void releaseSkipsStoredPeersEvenWhenTheyAreOldest() throws Exception {
        try(var a=new Node(1,4);var b=new Node(2);var c=new Node(3);var e=new Node(5);var f=new Node(6)) {
            a.remember(e);time.advance(1);
            b.remember(a);c.remember(a);
            a.sessions.receive(b.sessions.start(a.id).packet());time.advance(1);
            a.sessions.receive(c.sessions.start(a.id).packet());time.advance(1);
            assertEquals(3,peerCount(a));
            a.remember(f);
            assertNull(peerState(a,b));assertNotNull(peerState(a,c));assertNotNull(peerState(a,e));assertNotNull(peerState(a,f));
            assertEquals(3,peerCount(a));
        }
    }
    /** すでにいる揮発の相手を保存するときは、枠が埋まっていても誰も手放さない。 */
    @Test void rememberingAnExistingVolatilePeerWhenFullReleasesNobody() throws Exception {
        try(var a=new Node(1,4);var b=new Node(2);var c=new Node(3);var d=new Node(4)) {
            b.remember(a);c.remember(a);d.remember(a);
            a.sessions.receive(b.sessions.start(a.id).packet());time.advance(1);
            a.sessions.receive(c.sessions.start(a.id).packet());time.advance(1);
            a.sessions.receive(d.sessions.start(a.id).packet());
            a.remember(d);
            assertNotNull(peerState(a,b));assertNotNull(peerState(a,c));assertNotNull(peerState(a,d));
            assertEquals(3,peerCount(a));assertFalse(a.sessions.isUnregistered(d.id));
        }
    }
    /** 保存した相手だけで枠が埋まっているときは、これまでどおり断る。誰も手放さない。 */
    @Test void fullOfStoredPeersStillRefusesAnotherStoredPeer() throws Exception {
        try(var a=new Node(1,3);var b=new Node(2);var c=new Node(3);var d=new Node(4)) {
            a.remember(b);a.remember(c);
            var refused=assertThrows(IllegalStateException.class,()->a.remember(d));
            assertEquals("相手の数が上限に達しています",refused.getMessage());
            assertNotNull(peerState(a,b));assertNotNull(peerState(a,c));assertNull(peerState(a,d));
            assertEquals(2,peerCount(a));
        }
    }
    /** 上限で断ったあと 1 台消すと、新しい相手が入る。消した相手の鍵は 0 で埋める。 */
    @Test void forgettingVolatilePeerFreesSlotAndWipesKeys() throws Exception {
        try(var a=new Node(1,3);var b=new Node(2);var c=new Node(3);var d=new Node(4)) {
            connectVolatile(a,b);
            c.remember(a);d.remember(a);
            byte[] firstD=d.sessions.start(a.id).packet();
            a.sessions.receive(c.sessions.start(a.id).packet());
            assertThrows(SecurityException.class,()->a.sessions.receive(firstD));
            var keys=secrets(a,b);
            assertTrue(a.sessions.forgetVolatile(b.id));
            wiped(keys);
            assertNull(peerState(a,b));assertFalse(a.sessions.isEstablished(b.id));assertFalse(a.sessions.isHandshaking(b.id));
            assertNotNull(a.sessions.receive(firstD));
        }
    }
    /** 消したあとでも、1 通目の時刻の記録は残る。消した相手の古い 1 通目を送り直しても受けない。 */
    @Test void forgottenVolatilePeerOldFirstIsNotAcceptedAgain() {
        try(var a=new Node(1);var b=new Node(2)) {
            b.remember(a);
            byte[] first=b.sessions.start(a.id).packet();
            a.sessions.receive(first);
            assertTrue(a.sessions.forgetVolatile(b.id));
            assertThrows(SecurityException.class,()->a.sessions.receive(first));
        }
    }
    @Test void forgetVolatileLeavesStoredAndUnknownPeers() throws Exception {
        try(var a=new Node(1);var b=new Node(2);var c=new Node(3)) {
            connect(a,b);
            assertFalse(a.sessions.forgetVolatile(b.id));assertFalse(a.sessions.forgetVolatile(c.id));
            assertTrue(a.sessions.isEstablished(b.id));
            assertThrows(IllegalArgumentException.class,()->a.sessions.forgetVolatile(new byte[5]));
        }
    }
    /** ネットワークが変わったとき。揮発の相手は全部消え、保存した相手は残る。 */
    @Test void forgetAllVolatileKeepsStoredPeers() throws Exception {
        try(var a=new Node(1);var b=new Node(2);var c=new Node(3);var d=new Node(4)) {
            connect(a,b);connectVolatile(a,c);d.remember(a);a.sessions.receive(d.sessions.start(a.id).packet());
            assertEquals(3,peerCount(a));
            assertEquals(2,a.sessions.forgetAllVolatile());
            assertEquals(1,peerCount(a));assertTrue(a.sessions.isEstablished(b.id));
            assertEquals(1,((Map<?,?>)field(a.sessions,"routes")).size());
        }
    }
    /** きっかけ 2: 張れたセッションの鍵が期限を過ぎ、握手も進んでいなければ消える。 */
    @Test void volatilePeerWithExpiredSessionAndNoHandshakeIsForgotten() throws Exception {
        try(var a=new Node(1);var b=new Node(2)) {
            connectVolatile(a,b);
            time.advance(180);a.sessions.refresh();assertNotNull(peerState(a,b));
            time.advance(1);a.sessions.refresh();assertNull(peerState(a,b));
        }
    }
    @Test void volatilePeerWhoseHandshakeNeverFinishesIsForgottenAt90Seconds() throws Exception {
        try(var a=new Node(1);var b=new Node(2)) {
            b.remember(a);a.sessions.receive(b.sessions.start(a.id).packet());
            time.advance(89);a.sessions.refresh();assertNotNull(peerState(a,b));
            time.advance(1);a.sessions.refresh();assertNull(peerState(a,b));
            assertEquals(0,((Map<?,?>)field(a.sessions,"routes")).size());
        }
    }
    /** 同じ状態でも、保存した相手は消さない。 */
    @Test void storedPeerWithExpiredSessionIsKept() throws Exception {
        try(var a=new Node(1);var b=new Node(2)) {
            connect(a,b);time.advance(181);a.sessions.refresh();assertNotNull(peerState(a,b));
        }
    }
    /** きっかけ 3: 証明書の失効で揮発の相手の項目が消える。保存した相手は今までどおり invalid で残る。 */
    @Test void revokedVolatilePeerIsForgottenButStoredStays() throws Exception {
        try(var a=new Node(1);var b=new Node(2);var c=new Node(3)) {
            connectVolatile(a,b);connect(a,c);
            var keys=secrets(a,b);
            a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,group,1,time.millis(),List.of(b.id,c.id),admin));
            a.sessions.refresh();
            assertNull(peerState(a,b));wiped(keys);
            assertNotNull(peerState(a,c));assertFalse(a.sessions.isEstablished(c.id));
        }
    }
    @Test void continuousGroupRotationCannotExtendOriginalDeadline() {
        try(var a=new Node(1);var b=new Node(2)) {
            connect(a,b);a.sessions.rotateGroupKey(key(40),1);time.advance(179);a.sessions.rotateGroupKey(key(41),2);
            assertTrue(a.sessions.isEstablished(b.id));time.advance(1);assertFalse(a.sessions.isEstablished(b.id));
            assertThrows(IllegalArgumentException.class,()->a.sessions.rotateGroupKey(key(42),2));
        }
    }
    @Test void onlyRevokedPeerCanBeForgottenToFreeCapacityAndRemoveTimestamp() throws Exception {
        try(var a=new Node(1,2);var b=new Node(2);var c=new Node(3)) {
            a.remember(b);b.remember(a);
            byte[] first=b.sessions.start(a.id).packet();
            var second=a.sessions.receive(first);a.sessions.receive(b.sessions.receive(second.outbound().get(0).packet()).outbound().get(0).packet());
            assertThrows(SecurityException.class,()->a.sessions.forgetRevokedPeer(b.id));
            var guard=(TimestampReplayGuard)field(a.sessions,"replay");
            assertFalse(((Map<?,?>)field(guard,"newest")).isEmpty());
            a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,group,1,time.millis(),List.of(b.id),admin));
            a.sessions.forgetRevokedPeer(b.id);assertTrue(((Map<?,?>)field(guard,"newest")).isEmpty());
            assertThrows(SecurityException.class,()->a.sessions.receive(first));
            a.remember(c);c.remember(a);
            var reply=c.sessions.receive(a.sessions.start(c.id).packet());c.sessions.receive(a.sessions.receive(reply.outbound().get(0).packet()).outbound().get(0).packet());
            assertArrayEquals(new byte[]{1},c.sessions.receive(data(a,c,1)).plaintext());
        }
    }
}
