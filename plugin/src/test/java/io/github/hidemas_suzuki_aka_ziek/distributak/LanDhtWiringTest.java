// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.CotSync;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.AuthenticatedPeer;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtId;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtWire;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryRecord;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryStatus;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SessionManager;
import org.junit.Test;
import static org.junit.Assert.*;

/** DHT の配線（答え 196・197）の試験。偽の口で順序・時間・失敗を、2 台のハーネスで見つける道・画面・消去の順を確かめる。 */
public class LanDhtWiringTest {
    private static final long S=LanDht.SECOND;

    /** 偽の端点側。相手はいない。 */
    private static final class FakeWire implements LanDht.Wire {
        int generations;
        /** 対になった相手（本物の握手で作ったもの）。無ければ相手はいない。 */
        AuthenticatedPeer peer;
        byte[] session;
        final List<byte[]> sent=new ArrayList<>();
        @Override public byte[] sessionId(byte[] id){return peer!=null&&java.util.Arrays.equals(id,peer.id().bytes())?session:null;}
        @Override public AuthenticatedPeer authenticated(byte[] id,byte[] sessionId){
            return peer!=null&&java.util.Arrays.equals(id,peer.id().bytes())?peer:null;
        }
        @Override public boolean send(byte[] id,byte[] sessionId,byte[] plain){
            if(peer==null) {
                return false;
            }
            sent.add(plain.clone());
            return true;
        }
        final List<byte[]> released=new ArrayList<>();
        @Override public boolean release(byte[] id){released.add(id.clone());return true;}
        int started;
        @Override public void start(byte[] node,byte[] handshakeKey,InetSocketAddress address){
            // 相手がいないので、始めた回数だけ数える
            started++;
        }
        @Override public long nextGeneration(){
            generations++;
            return generations;
        }
    }

    private static final class Rig {
        final List<String> events=new CopyOnWriteArrayList<>();
        final List<String> logs=new CopyOnWriteArrayList<>();
        final List<Integer> bounds=new ArrayList<>();
        final AtomicLong nanos=new AtomicLong(1_000L*S);
        final AtomicLong wallMillis=new AtomicLong(1_800_000_000_000L);
        final FakeWire wire=new FakeWire();
        boolean failReserve;
        boolean rejoining;
        boolean issuerThrows;
        boolean storedThrows;
        long nextVersion=42;
        int jitterValue;
        LanDht dht;
        final byte[] group=new byte[32];
        final byte[] secret=new byte[32];
        final byte[] handshake;
        final byte[] ipv4={(byte)192,0,2,5};
        /** 対になった相手の番号（保存してある相手）。無ければ null。 */
        byte[] stored;

        Rig() {
            this(0);
        }

        Rig(int firstJitter) {
            jitterValue=firstJitter;
            java.util.Arrays.fill(group,(byte)1);
            java.util.Arrays.fill(secret,(byte)7);
            handshake=Crypto.x25519Public(secret);
            Clock wall=new Clock() {
                @Override public ZoneId getZone(){return ZoneId.of("UTC");}
                @Override public Clock withZone(ZoneId zone){return this;}
                @Override public Instant instant(){return Instant.ofEpochMilli(wallMillis.get());}
                @Override public long millis(){return wallMillis.get();}
            };
            LanDht.Config cfg=new LanDht.Config();
            cfg.groupId=group;
            cfg.self=DhtId.fromIdentityPublicKey(Crypto.ed25519Public(secret));
            cfg.ipv4=ipv4;
            cfg.prefix=24;
            cfg.wire=wire;
            cfg.nanos=nanos::get;
            cfg.wall=wall;
            cfg.jitter=new Random() {
                @Override public int nextInt(int bound){bounds.add(bound);return Math.min(jitterValue,bound-1);}
            };
            cfg.reserve=()->{
                events.add("reserve");
                if(failReserve) {
                    throw new IllegalStateException("version-store-secret-text");
                }
                long version=nextVersion;
                nextVersion=version+1;
                return version;
            };
            cfg.issuer=(version,signedAt)->{
                events.add("issue:"+version);
                if(issuerThrows) {
                    throw new IllegalStateException("totp-secret-text psk-secret-text");
                }
                return DiscoveryRecord.issue(group,secret,handshake,ipv4,4000,version,signedAt);
            };
            cfg.rejoining=()->rejoining;
            cfg.storedPeer=()->{
                if(storedThrows) {
                    throw new IllegalStateException("stored-peer-secret-text");
                }
                return stored;
            };
            cfg.log=logs::add;
            dht=new LanDht(cfg);
        }

        /** 本物の握手で作った相手を、偽の口の向こうの対の相手にする。 */
        void pair(AuthenticatedPeer peer) {
            wire.peer=peer;
            wire.session=new byte[16];
            java.util.Arrays.fill(wire.session,(byte)9);
            stored=peer.id().bytes();
        }
        /** 偽の口へ最後に送られたもの。 */
        DhtWire.Message lastSent() {
            return DhtWire.parse(wire.sent.get(wire.sent.size()-1));
        }
        /** 相手から来たことにして、DHT へ渡す。 */
        boolean deliver(byte[] wireBytes) {
            return dht.receive(wire.peer.id().bytes(),wire.session,wireBytes);
        }
        DiscoveryRecord signed(long version) {
            return DiscoveryRecord.issue(group,secret,handshake,ipv4,4000,version,wallMillis.get());
        }
        void at(long seconds){nanos.set(1_000L*S+seconds*S);}
        void step(long seconds){at(seconds);dht.step();}
        long count(String name){return events.stream().filter(name::equals).count();}
        long reserves(){return count("reserve");}
    }

    // ---- 偽の口: 版の予約・署名・公開の順 ----
    @Test public void reservesVersionBeforeSigning() {
        Rig rig=new Rig();
        rig.step(0);
        assertEquals(List.of("reserve","issue:42"),rig.events);
    }

    @Test public void reservationFailureSkipsSigningAndRetriesAfterOneMinute() {
        Rig rig=new Rig();
        rig.failReserve=true;
        rig.step(0);
        assertEquals(List.of("reserve"),rig.events);
        assertEquals(1,rig.dht.reserveFailures());
        assertTrue(rig.logs.contains("DHT_VERSION_RESERVE_FAILED"));
        rig.step(30);
        assertEquals(1,rig.reserves());
        rig.step(61);
        assertEquals(2,rig.reserves());
        assertEquals(2,rig.dht.reserveFailures());
        assertEquals(0,rig.events.stream().filter(e->e.startsWith("issue")).count());
        rig.failReserve=false;
        rig.step(125);
        assertEquals(List.of("reserve","reserve","reserve","issue:42"),rig.events);
        assertTrue(rig.dht.active());
    }

    @Test public void nothingIsReservedWhileRejoining() {
        Rig rig=new Rig();
        rig.rejoining=true;
        for(int t=0;t<10;t++) {
            rig.step(t);
        }
        assertTrue(rig.events.isEmpty());
        rig.rejoining=false;
        rig.step(10);
        assertEquals(List.of("reserve","issue:42"),rig.events);
    }

    @Test public void buttonDoesNothingDuringRejoinOrNegativeWallClock() {
        Rig rig=new Rig();
        rig.rejoining=true;
        assertEquals(LanDht.WAIT,rig.dht.press());
        rig.rejoining=false;
        rig.wallMillis.set(-5);
        assertEquals(LanDht.WAIT,rig.dht.press());
        assertTrue(rig.events.isEmpty());
        assertEquals(0,rig.dht.reserveFailures());
    }

    @Test public void buttonWithoutPeerReservesNothing() {
        Rig rig=new Rig();
        assertEquals(LanDht.NO_PEER,rig.dht.press());
        assertEquals(LanDht.NO_PEER,rig.dht.result());
        assertTrue(rig.events.isEmpty());
    }

    @Test public void negativeWallClockStopsPublishingButKeepsDht() {
        Rig rig=new Rig();
        rig.wallMillis.set(-1);
        rig.step(0);
        rig.step(400);
        assertTrue(rig.events.isEmpty());
        assertTrue(rig.dht.active());
        rig.wallMillis.set(1_800_000_000_000L);
        rig.step(401);
        assertEquals(List.of("reserve","issue:42"),rig.events);
    }

    @Test public void receiveIgnoresNonDhtPacketsAndNegativeWallClock() {
        Rig rig=new Rig();
        byte[] peer=new byte[32];
        byte[] session=new byte[32];
        assertFalse(rig.dht.receive(peer,session,new byte[]{1,2,3}));
        rig.wallMillis.set(-1);
        assertFalse("DHT の線でなければ負の時計でも false",rig.dht.receive(peer,session,new byte[]{1,2,3}));
        // 正しい DHT の線は、負の時計のあいだは何も書き換えずに捨てる。拒否ではない（true）
        assertTrue(rig.dht.receive(peer,session,DhtWire.ping(rig.group,new byte[16])));
        assertEquals(0,rig.dht.volatileCount());
        assertEquals(0,rig.wire.started);
    }

    // ---- ばらつき・周期・時計 ----
    @Test public void jitterIsDrawnBelowFiveMinutesAndDelaysFirstPublish() {
        Rig rig=new Rig();
        assertEquals(List.of(LanDht.JITTER_MILLIS+1,LanDht.JITTER_MILLIS+1),rig.bounds.subList(0,2));
        Rig maximum=new Rig(LanDht.JITTER_MILLIS);
        maximum.step(0);
        maximum.step(299);
        assertTrue(maximum.events.isEmpty());
        maximum.step(300);
        assertEquals(List.of("reserve","issue:42"),maximum.events);
    }

    @Test public void republishesEveryHour() {
        Rig rig=new Rig();
        rig.step(0);
        assertEquals(1,rig.reserves());
        rig.step(30*60);
        assertEquals(1,rig.reserves());
        rig.step(60*60+1);
        assertEquals(2,rig.reserves());
        assertEquals(List.of("reserve","issue:42","reserve","issue:43"),rig.events);
    }

    @Test public void monotonicClockGoingBackDropsWorkAndRestartsBase() {
        Rig rig=new Rig();
        rig.step(0);
        assertEquals(1,rig.wire.generations);
        rig.step(900);
        // 単調時計が戻った。世代を進め、起点を取り直す（最大のばらつきは次に引く）
        rig.jitterValue=LanDht.JITTER_MILLIS;
        rig.step(100);
        assertEquals(2,rig.wire.generations);
        assertEquals(1,rig.reserves());
        assertTrue(rig.dht.active());
    }

    // ---- 止める・失敗 ----
    @Test public void closeIsIdempotentAndStopsEverything() {
        Rig rig=new Rig();
        rig.dht.close();
        rig.dht.close();
        assertEquals(1,rig.logs.stream().filter("DHT_CLOSED"::equals).count());
        assertFalse(rig.dht.active());
        assertEquals(0,rig.dht.routingSize());
        assertEquals(LanDht.NO_PEER,rig.dht.press());
        assertFalse(rig.dht.receive(new byte[32],new byte[32],new byte[]{0x08,0x02,0x4A,0}));
        rig.step(5);
        assertTrue(rig.events.isEmpty());
    }

    @Test public void exceptionDisablesOnlyDhtWithoutLeakingText() {
        Rig rig=new Rig();
        rig.issuerThrows=true;
        rig.step(0);
        assertFalse(rig.dht.active());
        assertTrue(rig.logs.contains("DHT_FAILED"));
        for(String line:rig.logs) {
            assertFalse(line,line.contains("secret"));
        }
        rig.issuerThrows=false;
        rig.step(10);
        assertEquals(List.of("reserve","issue:42"),rig.events);
        assertEquals(LanDht.NO_PEER,rig.dht.press());
    }

    // ---- 2 台のハーネス ----
    private static String dhtText(LanControllerHarness h) {
        String t=h.ui.last.text;
        int i=t.indexOf("DHT");
        return i<0?"":t.substring(i);
    }

    private static void advance(LanControllerHarness a,LanControllerHarness m,int seconds) throws Exception {
        // 1 回に進める時間は DHT の要求の待ち時間（3 秒）より短くする。
        // 長く進めると、返事が届く前に待ちが期限切れになり、相手が「あり」から外れて試験が不安定になる。
        for(int s=0;s<seconds;s+=2) {
            a.offset.addAndGet(2L*S);
            m.offset.addAndGet(2L*S);
            for(int k=0;k<2;k++) {
                a.tick();
                m.tick();
                Thread.sleep(8);
            }
        }
    }

    private static void connected(LanControllerHarness admin,LanControllerHarness member) throws Exception {
        connectedWithoutWaiting(admin,member);
        advance(admin,member,360);
    }

    private static void connectedWithoutWaiting(LanControllerHarness admin,LanControllerHarness member) throws Exception {
        admin.create();
        member.beginJoin(admin);
        LanControllerHarness.until(()->member.ui.last.member&&admin.logs.contains("LAN_MEMBER_ISSUED"),admin,member);
        admin.controller.connect();
        admin.drain();
        LanControllerHarness.until(()->member.logs.stream().anyMatch(x->x.startsWith("LAN_ESTABLISHED"))&&admin.logs.stream().anyMatch(x->x.startsWith("LAN_ESTABLISHED")),admin,member);
    }

    private static void settle(LanControllerHarness admin,LanControllerHarness member) throws Exception {
        for(int i=0;i<40;i++) {
            admin.tick();
            member.tick();
            Thread.sleep(10);
        }
    }



    private static LanDht dhtOf(LanControllerHarness h) throws Exception {
        return (LanDht)LanControllerHarness.field(h.controller,"dht");
    }

    // ---- 揮発の相手の数のずれ（R-2）----
    /** 別の相手（Rig の外にいる、握手の相手になる）を NODES で教え、LanDht に握手を始めさせる。 */
    private static void startUnansweredHandshake(Rig rig) {
        DhtWire.Message ask=null;
        for(int t=1;t<10&&ask==null;t++) {
            rig.step(t);
            answerProbes(rig);
            for(int i=0;i<rig.wire.sent.size();i++) {
                DhtWire.Message m=DhtWire.parse(rig.wire.sent.get(i));
                if(m.op()==DhtWire.Op.FIND_NODE) {
                    ask=m;
                }
            }
        }
        assertNotNull("探しものが始まっている",ask);
        byte[] otherSecret=new byte[32];
        java.util.Arrays.fill(otherSecret,(byte)3);
        DhtWire.NodeContact other=new DhtWire.NodeContact(DhtId.fromIdentityPublicKey(Crypto.ed25519Public(otherSecret)),
            Crypto.x25519Public(otherSecret),new byte[]{(byte)192,0,2,9},4000);
        assertTrue(rig.deliver(DhtWire.nodes(rig.group,ask.requestId(),ask.target(),ask.page(),true,List.of(other))));
        for(int t=10;t<40&&rig.wire.started==0;t++) {
            rig.step(t);
        }
        assertTrue("握手を始めている",rig.wire.started>=1);
    }

    @Test public void volatileCountReturnsAfterAHandshakeEndsWithoutSession() throws Exception {
        Rig rig=new Rig(0);
        rig.pair(realPeer());
        startUnansweredHandshake(rig);
        assertEquals("始めた握手の相手を数える",1,rig.dht.volatileCount());
        // 相手が出てこないまま、試みの寿命（90 秒）が過ぎる
        for(int t=30;t<=130;t+=5) {
            rig.step(t);
        }
        assertEquals("握手がセッションなしで終わったら数は戻る",0,rig.dht.volatileCount());
    }

    @Test public void volatileCountDropsAPeerThatBecomesTheStoredPeer() throws Exception {
        AuthenticatedPeer peer=realPeer();
        Rig rig=new Rig(LanDht.JITTER_MILLIS);
        // 保存していない相手から DHT のパケットが来て、揮発の相手として数える
        rig.wire.peer=peer;
        rig.wire.session=new byte[16];
        java.util.Arrays.fill(rig.wire.session,(byte)9);
        assertTrue(rig.deliver(DhtWire.ping(rig.group,new byte[16])));
        assertEquals(1,rig.dht.volatileCount());
        // その相手が保存した相手になった（加入が認められた）。保存の相手は揮発ではない
        rig.stored=peer.id().bytes();
        rig.step(1);
        assertEquals("保存した相手は揮発の数から外れる",0,rig.dht.volatileCount());
    }

    @Test public void volatileCountDropsAPeerWhosePacketArrivesAfterItBecameStored() throws Exception {
        AuthenticatedPeer peer=realPeer();
        Rig rig=new Rig(LanDht.JITTER_MILLIS);
        rig.wire.peer=peer;
        rig.wire.session=new byte[16];
        java.util.Arrays.fill(rig.wire.session,(byte)9);
        assertTrue(rig.deliver(DhtWire.ping(rig.group,new byte[16])));
        assertEquals(1,rig.dht.volatileCount());
        // 1 歩も進めず、保存した相手になったあとの次のパケットだけで数から外れる
        rig.stored=peer.id().bytes();
        assertTrue(rig.deliver(DhtWire.ping(rig.group,new byte[16])));
        assertEquals(0,rig.dht.volatileCount());
    }

    // ---- DHT が無いときの DHT のパケット（L-3）----
    @Test public void dhtPacketWithoutDhtIsRejectedAndNeverReachesSync() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            connectedWithoutWaiting(admin,member);
            byte[] memberId=((LanGroup)LanControllerHarness.field(member.controller,"group")).id();
            byte[] adminId=((LanGroup)LanControllerHarness.field(admin.controller,"group")).id();
            // 360 秒進めると背景の公開とセッション更新が測定に混ざる。
            // 初回公開の前に両側を閉じ、DHT が止まったあとの受信だけを確かめる。
            var stop=LanController.class.getDeclaredMethod("stopDht");
            stop.setAccessible(true);
            for(var harness:List.of(admin,member)) {
                harness.work.execute(()->{
                    try {stop.invoke(harness.controller);}
                    catch(ReflectiveOperationException failure) {throw new AssertionError(failure);}
                });
                harness.drain();
                assertNull(dhtOf(harness));
            }
            // 接続成立時にすでに送られた DHT のパケットも、基準を取る前に処理する。
            settle(admin,member);
            var syncBefore=((CotSync)LanControllerHarness.field(member.controller,"sync")).statistics();
            long rejectBefore=(Long)LanControllerHarness.field(member.controller,"reject");
            byte[] adminSession=admin.endpoint().sessionId(memberId),memberSession=member.endpoint().sessionId(adminId);
            try {
                assertNotNull("送る側のセッションがある",adminSession);
                assertTrue("両側が同じセッションを使う",java.util.Arrays.equals(adminSession,memberSession));
                for(int i=0;i<3;i++) {
                    assertTrue(admin.endpoint().sendIfSession(memberId,adminSession,DhtWire.ping(new byte[32],new byte[16])));
                }
                // 拒否と数えられるか、同期の数が動くか（同期へ渡ってしまった）のどちらかまで待つ
                LanControllerHarness.until("DHT のパケットが処理される",()->{
                    var now=((CotSync)LanControllerHarness.field(member.controller,"sync")).statistics();
                    return (Long)LanControllerHarness.field(member.controller,"reject")>=rejectBefore+3
                        ||now.received()!=syncBefore.received()||now.rejected()!=syncBefore.rejected()||now.unknown()!=syncBefore.unknown();
                },admin,member);
                var syncAfter=((CotSync)LanControllerHarness.field(member.controller,"sync")).statistics();
                assertEquals("同期へは渡らない（受信）",syncBefore.received(),syncAfter.received());
                assertEquals("同期へは渡らない（拒否）",syncBefore.rejected(),syncAfter.rejected());
                assertEquals("同期へは渡らない（不明）",syncBefore.unknown(),syncAfter.unknown());
                assertEquals("DHT が無いので 3 件とも拒否と数える",rejectBefore+3,(long)(Long)LanControllerHarness.field(member.controller,"reject"));
            } catch(AssertionError failure) {
                throw new AssertionError(dhtRejectionDiagnostics(admin,member,adminId,memberId,adminSession,memberSession,rejectBefore),failure);
            } finally {
                Crypto.wipe(adminSession);Crypto.wipe(memberSession);
            }
        }
    }

    /** 値は出さず、拒否の数と通信/キューの状態だけを残す。 */
    private static String dhtRejectionDiagnostics(LanControllerHarness admin,LanControllerHarness member,
            byte[] adminId,byte[] memberId,byte[] adminSession,byte[] memberSession,long rejectBefore) throws Exception {
        byte[] adminNow=admin.endpoint().sessionId(memberId),memberNow=member.endpoint().sessionId(adminId);
        try {
            return "DHT_DIAGNOSTICS rejectBefore="+rejectBefore
                +" rejectAfter="+LanControllerHarness.field(member.controller,"reject")
                +" adminSessionPresent="+(adminNow!=null)+" memberSessionPresent="+(memberNow!=null)
                +" adminSessionUnchanged="+java.util.Arrays.equals(adminSession,adminNow)
                +" memberSessionUnchanged="+java.util.Arrays.equals(memberSession,memberNow)
                +" sessionsMatch="+(adminNow!=null&&java.util.Arrays.equals(adminNow,memberNow))
                +" memberDatagrams="+member.link.received.get()
                +" inboxQueued="+((SyncInbox)LanControllerHarness.field(member.controller,"inbox")).size()
                +" adminWorkQueued="+admin.work.tasks.size()+" memberWorkQueued="+member.work.tasks.size()
                +" mainQueued="+(admin.main.tasks.size()+member.main.tasks.size());
        } finally {Crypto.wipe(adminNow);Crypto.wipe(memberNow);}
    }

    // ---- 例外で止めたあとの片づけ（R-3）----
    private static InetSocketAddress sameLan(Rig rig,int last) throws Exception {
        byte[] a=rig.ipv4.clone();
        a[3]=(byte)last;
        return new InetSocketAddress(java.net.InetAddress.getByAddress(a),4000);
    }

    /** 預かりに期限前の記録を 1 件入れる（自分の記録を自分の表へ入れる道を使う）。 */
    private static void putUnexpiredRecord(Rig rig) {
        DiscoveryRecord record=rig.signed(1);
        assertEquals(DiscoveryStatus.ACCEPTED,rig.dht.storeForTest().putOwn(record.nodeId(),record.encode()));
        assertEquals("期限前の記録が預かりに 1 件ある",1,rig.dht.storeForTest().size());
    }

    @Test public void faultDiscardsCoreMemoryReleasesVolatilePeersAndStopsAcceptingReplies() throws Exception {
        Rig rig=new Rig(0);
        rig.pair(realPeer());
        startUnansweredHandshake(rig);
        assertEquals(1,rig.dht.volatileCount());
        int routingBefore=rig.dht.nodeForTest().routing().size();
        assertTrue("止まる前は経路表に相手がいる",routingBefore>=1);
        assertTrue("止まる前は同じサブネットの返事を受ける",rig.dht.allowsReply(sameLan(rig,77)));
        assertTrue(rig.wire.released.isEmpty());
        putUnexpiredRecord(rig);
        // 保存の相手を読む口が例外を出す。次の 1 歩で DHT だけが止まる
        rig.storedThrows=true;
        rig.step(200);
        assertFalse(rig.dht.active());
        assertTrue(rig.logs.contains("DHT_FAILED"));
        assertEquals("核の経路表を捨てる",0,rig.dht.nodeForTest().routing().size());
        assertEquals("期限前の預かりも全部捨てる",0,rig.dht.storeForTest().size());
        assertEquals("預かりの合計の大きさも 0",0L,rig.dht.storeForTest().encodedBytes());
        assertEquals("数えていた揮発の相手を放す",1,rig.wire.released.size());
        assertEquals(0,rig.dht.volatileCount());
        assertFalse("止まったあとは返事を受けない",rig.dht.allowsReply(sameLan(rig,77)));
        for(String log:rig.logs) {
            assertFalse(log,log.contains("secret"));
        }
    }

    @Test public void closedDhtDoesNotAcceptRepliesEither() throws Exception {
        Rig rig=new Rig(LanDht.JITTER_MILLIS);
        assertTrue(rig.dht.allowsReply(sameLan(rig,77)));
        putUnexpiredRecord(rig);
        rig.dht.close();
        assertFalse(rig.dht.allowsReply(sameLan(rig,77)));
        assertEquals("閉じたら期限前の預かりも全部捨てる",0,rig.dht.storeForTest().size());
        assertEquals(0L,rig.dht.storeForTest().encodedBytes());
    }

    // ---- 公開のばらつき（jitter）を試験から決められること（R-1）----
    @Test public void controllerUsesTheInjectedJitterForTheFirstPublish() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.jitterValue=0;
            member.jitterValue=0;
            connectedWithoutWaiting(admin,member);
            advance(admin,member,30);
            assertTrue("ばらつき 0 なら最初の公開は 30 秒以内に起きる",member.disk.reserves>=1);
        }
    }

    @Test public void maximumJitterKeepsTheFirstPublishBeyondFiveMinutes() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            assertEquals(LanDht.JITTER_MILLIS,member.jitterValue);
            connectedWithoutWaiting(admin,member);
            advance(admin,member,240);
            assertEquals("上限のばらつきなら 4 分では公開しない",0,member.disk.reserves);
            advance(admin,member,120);
            assertTrue("5 分を過ぎれば公開する",member.disk.reserves>=1);
        }
    }

    @Test public void buttonFindsOwnRecordOnceAndRespectsOneMinuteFloor() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            connected(admin,member);
            // ボタンの間隔を測る前に背景の握手を終え、メンバー始動の新しいセッションへそろえる。
            // 360秒の経過で必要になった再握手や答え212のFIRSTを、検索の要求と重ねない。
            settle(admin,member);
            byte[] adminId=LanBehaviourWiringTest.group(admin).id(),memberId=LanBehaviourWiringTest.group(member).id();
            var adminSessions=(SessionManager)LanControllerHarness.field(admin.endpoint(),"sessions");
            var memberSessions=(SessionManager)LanControllerHarness.field(member.endpoint(),"sessions");
            LanControllerHarness.until(()->!adminSessions.isHandshaking(memberId)&&!memberSessions.isHandshaking(adminId),admin,member);
            byte[] previous=member.endpoint().sessionId(adminId);
            admin.offset.addAndGet(5L*S);member.offset.addAndGet(5L*S);member.endpoint().start(adminId);
            LanProofRenewalTest.until(()->member.endpoint().sessionId(adminId)!=null
                    &&!java.util.Arrays.equals(previous,member.endpoint().sessionId(adminId))
                    &&java.util.Arrays.equals(member.endpoint().sessionId(adminId),admin.endpoint().sessionId(memberId))
                    &&!member.endpoint().isPeerInitiatedSession(adminId,member.endpoint().sessionId(adminId)),admin,member);
            LanDht dht=dhtOf(member);
            assertNotNull(dht);
            var memberDispatcher=(io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcher)LanControllerHarness.field(dht,"dispatcher");
            var adminDispatcher=(io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcher)LanControllerHarness.field(dhtOf(admin),"dispatcher");
            DhtId a=new DhtId(adminId),m=new DhtId(memberId);
            // Noiseの切替だけでなく、DHTのセッションの覚えが両側で追いつくまで待つ。
            LanControllerHarness.until(()->memberDispatcher.peers().isYes(a)&&adminDispatcher.peers().isYes(m)
                    &&java.util.Arrays.equals(memberDispatcher.peers().sessionOf(a),member.endpoint().sessionId(adminId))
                    &&java.util.Arrays.equals(adminDispatcher.peers().sessionOf(m),admin.endpoint().sessionId(memberId)),admin,member);
            assertTrue(dht.routingSize()>=1);
            int before=member.disk.reserves;
            member.controller.rescanDht();
            member.drain();
            LanControllerHarness.until(()->dht.foundCount()+dht.notFoundCount()>=1,admin,member);
            member.tick();
            assertTrue(dhtText(member),dhtText(member).contains(LanDht.FOUND));
            assertEquals(1,dht.foundCount());
            assertEquals(0,dht.notFoundCount());
            assertEquals(before+1,member.disk.reserves);
            // すぐもう一度押しても予約も送信もしない
            member.controller.rescanDht();
            member.drain();
            assertTrue(dhtText(member),dhtText(member).contains(LanDht.WAIT));
            assertEquals(before+1,member.disk.reserves);
            assertEquals(1,dht.foundCount());
            // 1 分たてば押せる。押すたびに版を取って署名し直す
            advance(admin,member,70);
            member.controller.rescanDht();
            member.drain();
            // 固定の時間ではなく、結果が出るまで待つ（全体実行で、返事が settle の間に間に合わないことがあった）
            LanControllerHarness.until(()->dht.foundCount()+dht.notFoundCount()>=2,admin,member);
            member.tick();
            assertTrue(dhtText(member),dhtText(member).contains(LanDht.FOUND));
            assertEquals(2,dht.foundCount());
            assertTrue(member.disk.reserves>=before+2);
        }
    }

    @Test public void lookupOverlappingMemberFirstRecoversAtNextPermittedPress()throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            connected(admin,member);settle(admin,member);
            byte[] adminId=LanBehaviourWiringTest.group(admin).id(),memberId=LanBehaviourWiringTest.group(member).id();
            var dht=dhtOf(member);int before=member.disk.reserves;
            var receiver=io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpoint.class.getDeclaredField("receiver");receiver.setAccessible(true);
            var original=(io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpoint.Receiver)receiver.get(admin.endpoint());
            var drop=new java.util.concurrent.atomic.AtomicBoolean(true);var stored=new java.util.concurrent.atomic.AtomicInteger();
            receiver.set(admin.endpoint(),new io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpoint.Receiver(){
                public void receive(byte[] peer,byte[] plain){original.receive(peer,plain);}
                public void receive(byte[] peer,byte[] session,byte[] plain){
                    if(drop.get()&&DhtWire.isDht(plain)&&DhtWire.parse(plain).op()==DhtWire.Op.STORE){stored.incrementAndGet();return;}
                    original.receive(peer,session,plain);
                }
            });
            member.controller.rescanDht();member.drain();
            LanControllerHarness.until(()->stored.get()>0,admin,member);
            byte[] old=member.endpoint().sessionId(adminId);
            admin.offset.addAndGet(5L*S);member.offset.addAndGet(5L*S);admin.endpoint().start(memberId);
            LanProofRenewalTest.until(()->member.endpoint().sessionId(adminId)!=null
                    &&!java.util.Arrays.equals(old,member.endpoint().sessionId(adminId))
                    &&member.endpoint().isPeerInitiatedSession(adminId,member.endpoint().sessionId(adminId)),admin,member);
            byte[] administratorStarted=member.endpoint().sessionId(adminId);
            // 検索が進行中のまま、答え212によるメンバーのFIRSTを通す。
            LanProofRenewalTest.until(()->member.endpoint().sessionId(adminId)!=null
                    &&!java.util.Arrays.equals(administratorStarted,member.endpoint().sessionId(adminId))
                    &&!member.endpoint().isPeerInitiatedSession(adminId,member.endpoint().sessionId(adminId)),admin,member);
            drop.set(false);
            LanControllerHarness.until(()->dht.notFoundCount()==1,admin,member);
            assertEquals(0,dht.foundCount());assertEquals(before+1,member.disk.reserves);
            advance(admin,member,70);
            member.controller.rescanDht();member.drain();
            LanControllerHarness.until(()->dht.foundCount()+dht.notFoundCount()>=2,admin,member);
            assertEquals(1,dht.foundCount());assertEquals(1,dht.notFoundCount());assertEquals(before+2,member.disk.reserves);
        }
    }

    // ---- 見つかったかの判定（M6）: 偽の口の向こうの相手が、自分の記録と違う返事をしたとき ----
    /** 本物の握手で 2 台をつなぎ、片方が持つ相手（本物の確立済み）を取り出す。閉じたあとも相手の値は使える。 */
    private static AuthenticatedPeer realPeer() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            connected(admin,member);
            List<AuthenticatedPeer> peers=dhtOf(member).nodeForTest().routing().nearest(new DhtId(new byte[32]),8);
            assertFalse(peers.isEmpty());
            return peers.get(0);
        }
    }

    /** PING には PONG を返し、「あり」の相手にする。 */
    private static void answerProbes(Rig rig) {
        for(int i=0;i<rig.wire.sent.size();i++) {
            DhtWire.Message m=DhtWire.parse(rig.wire.sent.get(i));
            if(m.op()==DhtWire.Op.PING) {
                assertTrue(rig.deliver(DhtWire.pong(rig.group,m.requestId())));
            }
        }
    }

    /** 押して STORE を受けさせ、FIND_VALUE まで進める。返り値は FIND_VALUE の要求。 */
    private static DhtWire.Message pressUntilFindValue(Rig rig,long version) {
        assertNull(rig.dht.press());
        DhtWire.Message store=rig.lastSent();
        assertEquals(DhtWire.Op.STORE,store.op());
        DhtId key=rig.signed(version).key();
        assertTrue(rig.deliver(DhtWire.storeResult(rig.group,store.requestId(),key,DhtWire.StoreStatus.ACCEPTED)));
        DhtWire.Message ask=rig.lastSent();
        assertEquals(DhtWire.Op.FIND_VALUE,ask.op());
        return ask;
    }

    private static Rig pairedRig(AuthenticatedPeer peer) {
        Rig rig=new Rig(LanDht.JITTER_MILLIS);
        rig.pair(peer);
        rig.step(10);
        answerProbes(rig);
        return rig;
    }

    @Test public void matchingOwnRecordIsFoundThroughTheFakeWire() throws Exception {
        Rig rig=pairedRig(realPeer());
        DhtWire.Message ask=pressUntilFindValue(rig,42);
        DiscoveryRecord mine=rig.signed(42);
        assertTrue(rig.deliver(DhtWire.value(rig.group,ask.requestId(),mine.key(),mine.encode())));
        assertEquals(LanDht.FOUND,rig.dht.result());
        assertEquals(1,rig.dht.foundCount());
        assertEquals(0,rig.dht.notFoundCount());
    }

    @Test public void previousVersionOfOwnRecordIsNotFound() throws Exception {
        Rig rig=pairedRig(realPeer());
        DhtWire.Message ask=pressUntilFindValue(rig,42);
        DiscoveryRecord previous=rig.signed(41);
        assertTrue(rig.deliver(DhtWire.value(rig.group,ask.requestId(),previous.key(),previous.encode())));
        assertEquals(LanDht.NOT_FOUND,rig.dht.result());
        assertEquals(0,rig.dht.foundCount());
        assertEquals(1,rig.dht.notFoundCount());
    }

    @Test public void resendOfReplyToEarlierRequestIsNotFound() throws Exception {
        Rig rig=pairedRig(realPeer());
        // 1 回目: 版 42 で見つかる。その返事をとっておく
        DhtWire.Message first=pressUntilFindValue(rig,42);
        DiscoveryRecord firstRecord=rig.signed(42);
        byte[] firstReply=DhtWire.value(rig.group,first.requestId(),firstRecord.key(),firstRecord.encode());
        assertTrue(rig.deliver(firstReply));
        assertEquals(1,rig.dht.foundCount());
        // 1 分たって 2 回目（版 43）。相手は 1 回目の返事をそのまま送り直す
        rig.step(70);
        answerProbes(rig);
        DhtWire.Message second=pressUntilFindValue(rig,43);
        assertNotEquals(java.util.Arrays.toString(first.requestId()),java.util.Arrays.toString(second.requestId()));
        rig.deliver(firstReply);
        assertEquals(1,rig.dht.foundCount());
        assertEquals(0,rig.dht.notFoundCount());
        // 本当の返事が来るまで「見つかった」にならない
        DiscoveryRecord secondRecord=rig.signed(43);
        assertTrue(rig.deliver(DhtWire.value(rig.group,second.requestId(),secondRecord.key(),secondRecord.encode())));
        assertEquals(2,rig.dht.foundCount());
    }

    @Test public void reservationFailureOnButtonShowsNotFoundWithoutSending() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            connected(admin,member);
            LanDht dht=dhtOf(member);
            member.disk.failReserve=true;
            member.controller.rescanDht();
            member.drain();
            assertTrue(dhtText(member),dhtText(member).contains(LanDht.NOT_FOUND));
            assertEquals(1,dht.notFoundCount());
            assertEquals(0,dht.foundCount());
            assertTrue(member.logs.contains("DHT_VERSION_RESERVE_FAILED"));
        }
    }

    @Test public void screenShowsThreeCountsAndNothingSensitive() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            connected(admin,member);
            member.controller.rescanDht();
            member.drain();
            settle(admin,member);
            for(var node:List.of(admin,member)) {
                String text=dhtText(node);
                assertTrue(text,text.contains("DHT 経路表: "));
                assertTrue(text,text.contains("預かり: "));
                assertTrue(text,text.contains("検証で拒否: "));
                assertFalse(text,text.contains("192.0.2."));
                assertFalse(text,text.matches("(?s).*[0-9a-f]{16}.*"));
                for(String line:node.logs) {
                    if(line.contains("DHT")) {
                        assertTrue(line,line.matches("[A-Z0-9_]+"));
                    }
                    assertFalse(line,line.contains("192.0.2."));
                }
            }
        }
    }

    @Test public void networkLossDropsDhtAndRestartsWithNewState() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            connected(admin,member);
            assertNotNull(dhtOf(member));
            var link=member.network.current;
            member.network.current=null;
            member.network.changed.run();
            member.drain();
            assertNull(dhtOf(member));
            assertTrue(member.logs.contains("DHT_CLOSED"));
            assertFalse(member.ui.last.text,member.ui.last.text.contains("DHT 経路表"));
            member.network.current=link;
            member.network.changed.run();
            member.drain();
            member.controller.connect();
            member.drain();
            LanControllerHarness.until("dht restarts",()->dhtOf(member)!=null,admin,member);
            assertEquals(0,dhtOf(member).storedRecords());
        }
    }

    @Test public void eraseStopsPortThenDiscardsDhtMemoryThenDeletesStorage() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            connected(admin,member);
            List<String> order=new CopyOnWriteArrayList<>();
            member.link.afterIoClose=()->order.add("port closed; dht closed="+member.logs.contains("DHT_CLOSED"));
            member.disk.afterStop=()->order.add("storage next; dht closed="+member.logs.contains("DHT_CLOSED"));
            member.controller.erase();
            member.drain();
            assertEquals(List.of("port closed; dht closed=false","storage next; dht closed=true"),order);
        }
    }

    @Test public void forgottenVolatilePeerLeavesNoSpeedBagOrYesMark() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            connected(admin,member);
            LanDht dht=dhtOf(member);
            byte[] peer=dht.nodeForTest().routing().nearest(DhtId.fromIdentityPublicKey(Crypto.ed25519Public(new byte[32])),8).get(0).id().bytes();
            DhtId id=new DhtId(peer);
            assertTrue(dht.dispatcherForTest().peers().isYes(id));
            dht.peerForgotten(peer);
            assertFalse(dht.dispatcherForTest().peers().isYes(id));
        }
    }

    // ---- 同じ Wi-Fi の IPv4 LAN だけ（答え 162・181 (1)、legal Q107 (1)） ----
    private static InetSocketAddress at(int ip,int port) throws Exception {
        byte[] b={(byte)(ip>>>24),(byte)(ip>>>16),(byte)(ip>>>8),(byte)ip};
        return new InetSocketAddress(java.net.InetAddress.getByAddress(b),port);
    }

    @Test public void repliesAreAcceptedOnlyFromTheSameIpv4Subnet() throws Exception {
        Rig rig=new Rig();
        int own=(192<<24)|(0<<16)|(2<<8)|5;
        assertTrue(rig.dht.allowsReply(at(own+10,50000)));
        // 別のサブネット・自分・ブロードキャスト・ポート 0・IPv6・null は受けない
        assertFalse(rig.dht.allowsReply(at((192<<24)|(0<<16)|(3<<8)|5,50000)));
        assertFalse(rig.dht.allowsReply(at(own,50000)));
        assertFalse(rig.dht.allowsReply(at((192<<24)|(0<<16)|(2<<8)|255,50000)));
        assertFalse(rig.dht.allowsReply(at(own+10,0)));
        assertFalse(rig.dht.allowsReply(new InetSocketAddress(java.net.InetAddress.getByName("2001:db8::1"),50000)));
        assertFalse(rig.dht.allowsReply(null));
    }

    @Test public void controllerPassesTheWifiPrefixToTheDhtNetwork() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.link.prefix=26;
            member.link.prefix=26;
            connected(admin,member);
            LanDht dht=dhtOf(member);
            assertNotNull(dht);
            byte[] own=member.link.address.getAddress();
            int ip=((own[0]&0xff)<<24)|((own[1]&0xff)<<16)|((own[2]&0xff)<<8)|(own[3]&0xff);
            int mask=-1<<6;
            int base=ip&mask;
            int inside=base+((ip-base+1<63)?(ip-base+1):((ip-base)>1?1:2));
            int outside=(base+64)+1;
            assertTrue(dht.allowsReply(at(inside,50000)));
            assertFalse(dht.allowsReply(at(outside,50000)));
        }
    }
}
