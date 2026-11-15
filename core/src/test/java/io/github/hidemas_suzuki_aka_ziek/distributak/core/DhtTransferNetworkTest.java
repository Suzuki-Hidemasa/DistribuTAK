// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtId;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtPeers;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtTransfers;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtWire;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 核 C2: 大きな転送（最大 3 MiB）と、DHT を知らない旧版（r19）の相手の拒否の数。
 * 実 UDP（ループバックだけ）の試験と、仮想時間で欠け・重複・順序入れ替えを起こす試験に分ける。
 * 試験の失敗の文にも、番地・端末の番号・鍵・線の中身は出さない。
 */
class DhtTransferNetworkTest {
    static final long SECOND=1_000_000_000L,MINUTE=60*SECOND,DAY=24*60*MINUTE;
    static final DhtTransfers.Limits UNLIMITED=new DhtTransfers.Limits(1_000_000,1_000_000,1_000_000,1_000_000);

    static byte[] pseudoRandom(int length,long seed) {
        byte[] data=new byte[length];new Random(seed).nextBytes(data);return data;
    }

    // ---- 実 UDP ----

    /** 1 端末分の 1 本のスレッド。核の部品は、このスレッドからだけ触る。 */
    static final class Side implements AutoCloseable {
        final UdpEndpointTest.Node node;final DhtId remote;final DhtTransfers transfers;
        final BlockingQueue<Runnable> commands=new LinkedBlockingQueue<>();
        final AtomicReference<byte[]> received=new AtomicReference<>();
        final AtomicReference<Throwable> failure=new AtomicReference<>();
        final Thread thread;volatile boolean stop;
        Side(UdpEndpointTest.Node node,UdpEndpointTest.Node other) {
            this.node=node;this.remote=new DhtId(other.id);
            transfers=new DhtTransfers(Crypto.blake2s(new byte[]{1}),(peerId,sessionId,plain)->node.endpoint.sendIfSession(peerId,sessionId,plain),
                System::nanoTime,new Random(5),(peer,kind,data)->received.set(data.clone()),(peer,id)->false,DhtTransfers.Limits.defaults());
            thread=new Thread(this::pump,"dht-transfer-pump");thread.setDaemon(true);thread.start();
        }
        private void pump() {
            try {
                while(!stop) {
                    Runnable command;
                    while((command=commands.poll())!=null)command.run();
                    byte[] plain=node.inbox.poll(2,TimeUnit.MILLISECONDS);
                    if(plain!=null) {
                        byte[] session=node.sessionInbox.poll(1,TimeUnit.SECONDS);
                        if(session!=null&&DhtWire.isDht(plain)) {
                            try{transfers.receive(remote,session,DhtWire.parse(plain));}catch(IllegalArgumentException|SecurityException e){/* 壊れた線は捨てる */}
                        }
                    }
                    transfers.poll();
                }
            } catch(Throwable t) {
                failure.set(t);
            }
        }
        <T> T call(Supplier<T> action) throws Exception {
            var future=new CompletableFuture<T>();
            commands.add(()->{try{future.complete(action.get());}catch(Throwable t){future.completeExceptionally(t);}});
            return future.get(10,TimeUnit.SECONDS);
        }
        @Override public void close() throws Exception {
            stop=true;thread.join(5000);
        }
    }

    @Test void threeMebibytesOverRealUdpArriveIntactAndTheReservationIsReleased() throws Exception {
        var udp=new UdpEndpointTest();
        try(var a=udp.new Node(1,"127.0.0.1");var b=udp.new Node(2,"127.0.0.1")) {
            udp.connect(a,b);
            a.inbox.clear();b.inbox.clear();a.sessionInbox.clear();b.sessionInbox.clear();
            byte[] data=pseudoRandom(DhtWire.MAX_TRANSFER_BYTES,42);
            try(var sideA=new Side(a,b);var sideB=new Side(b,a)) {
                long heapBefore=usedHeap();long started=System.nanoTime();
                byte[] session=a.endpoint.sessionId(b.id);
                assertNotNull(session);
                byte[] id=sideA.call(()->sideA.transfers.start(sideA.remote,session,DhtWire.TransferKind.STORE,data));
                assertNotNull(id);
                long deadline=started+TimeUnit.SECONDS.toNanos(120);
                while(sideB.received.get()==null||sideA.call(sideA.transfers::activeOut)!=0) {
                    assertNull(sideA.failure.get(),"pump A failed");assertNull(sideB.failure.get(),"pump B failed");
                    assertTrue(System.nanoTime()<deadline,"transfer did not finish in 120 seconds");
                    Thread.sleep(20);
                }
                long elapsedMillis=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started);
                assertTrue(Arrays.equals(data,sideB.received.get()),"received data differs");
                assertEquals(1L,(long)sideA.call(sideA.transfers::completedOut));
                assertEquals(1L,(long)sideB.call(sideB.transfers::completedIn));
                assertEquals(0L,(long)sideA.call(sideA.transfers::failedOut));
                assertEquals(0L,(long)sideB.call(sideB.transfers::abandonedIn));
                assertEquals(0L,(long)sideA.call(sideA.transfers::reservedBytes));
                assertEquals(0L,(long)sideB.call(sideB.transfers::reservedBytes));
                assertEquals(0L,(long)sideB.call(sideB.transfers::corrupt));
                assertEquals(0L,(long)sideB.call(sideB.transfers::mismatched));
                int received=b.datagrams.get();
                assertTrue(received<=DhtWire.MAX_PIECES*(DhtTransfers.MAX_RETRIES+1)+100,"too many datagrams: "+received);
                if(System.getenv("DISTRIBUTAK_UDP_MEASURE")!=null||System.getProperty("distributak.udp.measure")!=null) {
                    System.out.println("[measure] elapsedMillis="+elapsedMillis+" datagramsToReceiver="+received+" datagramsToSender="+a.datagrams.get()
                        +" rateLimited="+sideB.call(sideB.transfers::rateLimited)+" heapGrowthBytes="+(usedHeap()-heapBefore));
                }
            }
        }
    }
    static long usedHeap(){Runtime r=Runtime.getRuntime();return r.totalMemory()-r.freeMemory();}

    // ---- 仮想時間で欠け・重複・順序入れ替え ----

    record Flight(long due,long seq,int to,byte[] wire){}
    static final class Sim implements AutoCloseable {
        static final long STEP=10_000_000L;
        final SessionManagerTest t=new SessionManagerTest();
        final SessionManagerTest.Node a=t.new Node(1),b=t.new Node(2);
        final Random rng;final int lossPercent,duplicatePercent,maxDelaySteps;
        final PriorityQueue<Flight> flights=new PriorityQueue<>((x,y)->x.due()!=y.due()?Long.compare(x.due(),y.due()):Long.compare(x.seq(),y.seq()));
        final DhtTransfers[] transfers=new DhtTransfers[2];
        final List<byte[]> sunk=new ArrayList<>();
        long step,seq,dropped,duplicated,sessionRejected,malformed,sentAtoB;
        Sim(long seed,int lossPercent,int duplicatePercent,int maxDelaySteps) {
            this.rng=new Random(seed);this.lossPercent=lossPercent;this.duplicatePercent=duplicatePercent;this.maxDelaySteps=maxDelaySteps;
            t.connect(a,b);
            var nodes=new SessionManagerTest.Node[]{a,b};
            for(int i=0;i<2;i++) {
                int from=i;
                transfers[i]=new DhtTransfers(t.group,(peerId,sessionId,plain)->{
                    try {
                        for(var o:nodes[from].sessions.send(peerId,plain))enqueue(1-from,o.packet());
                        return true;
                    } catch(RuntimeException e) {
                        return false;
                    }
                },()->t.time.nanos+1_000*SECOND,new Random(seed+i),(peer,kind,data)->sunk.add(data.clone()),(peer,id)->false,UNLIMITED);
            }
        }
        void enqueue(int to,byte[] wire) {
            if(to==1)sentAtoB++;
            if(rng.nextInt(100)<lossPercent){dropped++;return;}
            flights.add(new Flight(step+1+rng.nextInt(maxDelaySteps),seq++,to,wire.clone()));
            if(rng.nextInt(100)<duplicatePercent){duplicated++;flights.add(new Flight(step+1+rng.nextInt(maxDelaySteps),seq++,to,wire.clone()));}
        }
        void deliver(Flight f) {
            var node=f.to()==1?b:a;var other=f.to()==1?a:b;
            SessionManager.Received r;
            try {
                r=node.sessions.receive(f.wire());
            } catch(RuntimeException e) {
                sessionRejected++;return;
            }
            for(var o:r.outbound())enqueue(1-f.to(),o.packet());
            byte[] plain=r.plaintext();
            if(plain==null||plain.length==0||!DhtWire.isDht(plain))return;
            try {
                transfers[f.to()].receive(new DhtId(other.id),r.sessionId(),DhtWire.parse(plain));
            } catch(IllegalArgumentException|SecurityException e) {
                malformed++;
            }
        }
        void advance() {
            step++;t.time.nanos+=STEP;
            while(!flights.isEmpty()&&flights.peek().due()<=step)deliver(flights.poll());
            transfers[0].poll();transfers[1].poll();
        }
        /** 仮想時間で maxSeconds まで、条件が成り立つまで進める。成り立ったら true。 */
        boolean runUntil(int maxSeconds,Supplier<Boolean> done) {
            long limit=step+maxSeconds*100L;
            while(step<limit){advance();if(done.get())return true;}
            return false;
        }
        @Override public void close(){a.close();b.close();}
    }

    private void lossyTransfer(long seed,int lossPercent,int duplicatePercent,int maxDelaySteps,int size) {
        try(var sim=new Sim(seed,lossPercent,duplicatePercent,maxDelaySteps)) {
            byte[] data=pseudoRandom(size,seed);
            byte[] session=sim.a.sessions.sessionId(sim.b.id);
            assertNotNull(sim.transfers[0].start(new DhtId(sim.b.id),session,DhtWire.TransferKind.STORE,data));
            assertTrue(sim.runUntil(150,()->sim.transfers[0].activeOut()==0&&sim.transfers[1].activeIn()==0&&!sim.sunk.isEmpty()),
                "transfer did not finish");
            assertEquals(1,sim.sunk.size());
            assertTrue(Arrays.equals(data,sim.sunk.get(0)),"received data differs");
            assertEquals(1L,sim.transfers[0].completedOut());assertEquals(1L,sim.transfers[1].completedIn());
            assertEquals(0L,sim.transfers[0].failedOut());assertEquals(0L,sim.transfers[1].abandonedIn());
            assertEquals(0L,sim.transfers[0].reservedBytes());assertEquals(0L,sim.transfers[1].reservedBytes());
            assertEquals(0L,sim.transfers[1].corrupt());
            int pieces=(size+DhtWire.PIECE_BYTES-1)/DhtWire.PIECE_BYTES;
            assertTrue(sim.sentAtoB<=pieces*(long)(DhtTransfers.MAX_RETRIES+1)+16,"too many sends: "+sim.sentAtoB);
            if(lossPercent>0)assertTrue(sim.dropped>0);
            if(duplicatePercent>0)assertTrue(sim.duplicated>0);
        }
    }

    @Test void aTransferSurvivesLossDuplicationAndReordering() {
        lossyTransfer(1,10,10,5,256*1024);
    }
    @Test void aTransferSurvivesHeavyReorderingWithoutLoss() {
        lossyTransfer(2,0,5,50,256*1024);
    }
    @Test void aTransferSurvivesSeveralDifferentSeeds() {
        for(long seed=10;seed<14;seed++)lossyTransfer(seed,8,8,8,64*1024+17);
    }
    @Test void aTransferWithEveryPacketLostFailsAndReleasesTheReservation() {
        try(var sim=new Sim(3,100,0,3)) {
            byte[] session=sim.a.sessions.sessionId(sim.b.id);
            assertNotNull(sim.transfers[0].start(new DhtId(sim.b.id),session,DhtWire.TransferKind.STORE,pseudoRandom(64*1024,3)));
            assertTrue(sim.runUntil(60,()->sim.transfers[0].activeOut()==0),"transfer did not give up");
            assertEquals(1L,sim.transfers[0].failedOut());assertEquals(0L,sim.transfers[0].completedOut());
            assertEquals(0L,sim.transfers[0].reservedBytes());assertEquals(0L,sim.transfers[1].reservedBytes());
            assertTrue(sim.sunk.isEmpty());
        }
    }

    // ---- DHT を知らない旧版（r19）の相手 ----

    private List<Long> oldPeerRejections(long minutes,Random rng) {
        var t=new SessionManagerTest();
        try(var a=t.new Node(1);var b=t.new Node(2)) {
            t.connect(a,b);
            var clock=new AtomicLong(1_000*SECOND);
            var rejectedAt=new ArrayList<Long>();
            DhtId peer=new DhtId(b.id);
            var peers=new DhtPeers(clock::get,(p,session)->{
                byte[] requestId=new byte[DhtWire.REQUEST_BYTES];rng.nextBytes(requestId);
                for(var o:a.sessions.send(b.id,DhtWire.ping(t.group,requestId))) {
                    var r=b.sessions.receive(o.packet());
                    if(r.plaintext()==null||r.plaintext().length==0)continue;
                    try {
                        LegacyR18SyncWire.parse(r.plaintext());
                    } catch(IllegalArgumentException|SecurityException e) {
                        rejectedAt.add(clock.get());
                    }
                }
                return true;
            });
            long begin=clock.get();
            peers.sessionStarted(peer,sessionBytes(0));
            for(long m=1;m<=minutes;m++) {
                clock.addAndGet(MINUTE);peers.tick();
                if(m%7==0)peers.hint(peer,sessionBytes(m));
                if(m%11==0)peers.sessionStarted(peer,sessionBytes(m));
                if(m%13==0)peers.retryAll();
                if(m%90==0){peers.networkChanged();peers.sessionStarted(peer,sessionBytes(m));}
                if(m%200==0){peers.forget(peer);peers.sessionStarted(peer,sessionBytes(m));}
                if(m%1000==0)assertTrue(clock.get()>begin);
            }
            assertFalse(peers.isYes(peer));
            assertEquals(peers.probesSent(),(long)rejectedAt.size());
            assertTrue(peers.stateCount()<=DhtPeers.MAX_STATES);
            assertTrue(peers.budgetCount()<=DhtPeers.MAX_BUDGETS);
            return rejectedAt;
        }
    }
    static byte[] sessionBytes(long n){byte[] s=new byte[16];s[0]=(byte)n;s[1]=(byte)(n>>8);s[2]=(byte)(n>>16);return s;}

    private void assertAtMostTwelveInAnyDay(List<Long> times) {
        for(int i=0;i<times.size();i++) {
            int n=0;
            for(int j=i;j<times.size()&&times.get(j)-times.get(i)<DAY;j++)n++;
            assertTrue(n<=DhtPeers.PEER_PER_DAY,"rejections in one day: "+n);
        }
    }

    @Test void anOldPeerSeesAtMostTwelveRejectionsInADayWhateverTheTriggers() {
        var times=oldPeerRejections(24*60-1,new Random(1));
        assertTrue(times.size()>=1&&times.size()<=DhtPeers.PEER_PER_DAY,"rejections: "+times.size());
        assertAtMostTwelveInAnyDay(times);
    }
    @Test void anOldPeerRejectionCountDoesNotKeepGrowingOverThreeDays() {
        var times=oldPeerRejections(3*24*60,new Random(2));
        assertTrue(times.size()<=3*DhtPeers.PEER_PER_DAY+1,"rejections: "+times.size());
        assertTrue(times.size()>=DhtPeers.PEER_PER_DAY,"rejections: "+times.size()); // 実際に送ったと分かる下限
        assertAtMostTwelveInAnyDay(times);
    }
}
