// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** 核 C2: 大きな転送（最大 3 MiB）の断片・ACK・再送・資源の上限。 */
class DhtTransfersTest {
    static final long MS=1_000_000L,SECOND=1_000_000_000L;
    static final byte[] GROUP=new byte[32];
    static final byte[] SESSION=new byte[16];
    static { GROUP[0]=7;SESSION[0]=9; }
    static DhtId id(int n){return DhtIdTest.id(n);}

    record Frame(DhtId to,byte[] bytes) {}
    record Received(DhtId peer,DhtWire.TransferKind kind,byte[] data) {}

    /** 2 台（x=id(1)、y=id(2)）を、時計と待ち行列でつなぐ。 */
    static final class Net {
        final AtomicLong nanos=new AtomicLong(1_000*SECOND);
        final ArrayDeque<Frame> toX=new ArrayDeque<>(),toY=new ArrayDeque<>();
        final List<Received> receivedByY=new ArrayList<>(),receivedByX=new ArrayList<>();
        boolean valueExpected=false;
        boolean xCanSend=true;
        final DhtTransfers x,y;
        /** 1 通届けるごとに進める時間。 */
        long step=5*MS;
        Predicate<Frame> dropToY=f->false,dropToX=f->false;
        /** y へ届く前に中身を書き換える（壊れた転送の試験用）。 */
        java.util.function.UnaryOperator<Frame> mutateToY=f->f;
        Net(DhtTransferSink ySink,DhtTransfers.Limits limits) {
            x=new DhtTransfers(GROUP,(peer,session,bytes)->{if(!xCanSend)return false;toY.add(new Frame(new DhtId(peer),bytes));return true;},nanos::get,new Random(1),
                (peer,kind,data)->receivedByX.add(new Received(peer,kind,data)),(peer,tid)->true,limits);
            y=new DhtTransfers(GROUP,(peer,session,bytes)->{toX.add(new Frame(new DhtId(peer),bytes));return true;},nanos::get,new Random(2),ySink,
                (peer,tid)->valueExpected,limits);
        }
        Net() {
            this(null,DhtTransfers.Limits.defaults());
        }
        static Net withSink() {
            Net[] holder=new Net[1];
            holder[0]=new Net((peer,kind,data)->holder[0].receivedByY.add(new Received(peer,kind,data)),DhtTransfers.Limits.defaults());
            return holder[0];
        }
        /** 待ち行列が空になるまで届ける。1 通ごとに時計を進める。 */
        void pump() {
            int guard=0;
            while((!toX.isEmpty()||!toY.isEmpty())&&guard++<200_000) {
                if(!toY.isEmpty()) {
                    Frame f=mutateToY.apply(toY.poll());nanos.addAndGet(step);
                    if(!dropToY.test(f))y.receive(id(1),SESSION,DhtWire.parse(f.bytes()));
                }
                if(!toX.isEmpty()) {
                    Frame f=toX.poll();nanos.addAndGet(step);
                    if(!dropToX.test(f))x.receive(id(2),SESSION,DhtWire.parse(f.bytes()));
                }
            }
        }
    }
    static byte[] data(int size,int seed) {
        byte[] b=new byte[size];new Random(seed).nextBytes(b);return b;
    }
    static byte[] tid(int n){byte[] b=new byte[16];b[0]=(byte)n;b[1]=(byte)(n>>8);return b;}

    @Test void aTransferOfEveryBoundarySizeArrivesIntact() {
        for(int size:new int[]{1,1023,1024,1025,2048,5000,100_000}) {
            Net n=Net.withSink();byte[] data=data(size,size);
            assertTrue(n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data),"start "+size);
            n.pump();
            assertEquals(1,n.receivedByY.size(),"size "+size);
            assertArrayEquals(data,n.receivedByY.get(0).data());assertEquals(DhtWire.TransferKind.STORE,n.receivedByY.get(0).kind());
            assertEquals(id(1),n.receivedByY.get(0).peer());
            assertEquals(1,n.x.completedOut());assertEquals(1,n.y.completedIn());
            assertEquals(0,n.x.activeOut());assertEquals(0,n.y.activeIn());assertEquals(0,n.y.reservedBytes());
        }
    }
    @Test void theMaximumSizeThreeMebibytesArrivesIntactInsideTheDeadline() {
        Net n=Net.withSink();byte[] data=data(DhtWire.MAX_TRANSFER_BYTES,3);
        assertTrue(n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data));
        long begin=n.nanos.get();n.pump();
        assertEquals(1,n.receivedByY.size());assertArrayEquals(data,n.receivedByY.get(0).data());
        assertTrue(n.nanos.get()-begin<DhtTransfers.TOTAL_NANOS);
        assertEquals(1,n.x.completedOut());assertEquals(0,n.x.failedOut());
    }
    @Test void anOversizeOrEmptyTransferIsRefused() {
        Net n=Net.withSink();
        assertFalse(n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),new byte[0]));
        assertFalse(n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),new byte[DhtWire.MAX_TRANSFER_BYTES+1]));
        assertFalse(n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,new byte[15],new byte[10]));
        assertEquals(0,n.x.activeOut());assertTrue(n.toY.isEmpty());
    }
    @Test void theSenderNeverHasMoreThanFourPiecesInFlightBeforeAnAck() {
        Net n=Net.withSink();
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data(20_000,1));
        assertEquals(DhtTransfers.WINDOW,n.toY.size());
    }
    @Test void aDuplicatePieceIsAcknowledgedButCountedOnce() {
        Net n=Net.withSink();byte[] data=data(3000,1);
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data);
        Frame first=n.toY.peek();
        n.toY.addFirst(first); // 同じ断片を 2 回
        n.pump();
        assertArrayEquals(data,n.receivedByY.get(0).data());assertEquals(1,n.receivedByY.size());
    }
    @Test void aLostPieceIsResentAfterOneSecond() {
        Net n=Net.withSink();byte[] data=data(10_000,1);
        boolean[] dropped={false};
        n.dropToY=f->{var m=DhtWire.parse(f.bytes());if(m.index()==3&&!dropped[0]){dropped[0]=true;return true;}return false;};
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data);
        n.pump();
        assertTrue(n.receivedByY.isEmpty());
        n.nanos.addAndGet(SECOND);n.x.poll();n.pump();
        assertEquals(1,n.receivedByY.size());assertArrayEquals(data,n.receivedByY.get(0).data());
    }
    @Test void aPieceThatNeverArrivesIsResentThreeTimesAndThenTheSenderGivesUp() {
        Net n=Net.withSink();
        n.dropToY=f->DhtWire.parse(f.bytes()).index()==2;
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data(10_000,1));
        n.pump();
        int resends=0;
        for(int i=0;i<10&&n.x.activeOut()>0;i++) {
            n.nanos.addAndGet(SECOND);n.x.poll();
            int pieces=0;for(Frame f:n.toY)if(DhtWire.parse(f.bytes()).index()==2)pieces++;
            resends+=pieces;n.pump();
        }
        assertEquals(DhtTransfers.MAX_RETRIES,resends);
        assertEquals(0,n.x.activeOut());assertEquals(1,n.x.failedOut());
    }
    @Test void piecesArrivingInAnyOrderAreAssembledCorrectly() {
        Net n=Net.withSink();byte[] data=data(9000,5);
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data);
        List<Frame> window=new ArrayList<>(n.toY);n.toY.clear();
        java.util.Collections.reverse(window);n.toY.addAll(window);
        n.pump();
        assertArrayEquals(data,n.receivedByY.get(0).data());
    }
    @Test void aCorruptedTransferIsNotHandedOverAndIsCounted() {
        Net n=Net.withSink();byte[] data=data(2500,1);
        byte[] wrongDigest=DhtTransfers.digestOf(data(2500,2));
        for(int i=0;i<3;i++) {
            int from=i*1024,to=Math.min(2500,from+1024);
            n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),wrongDigest,2500,i,3,java.util.Arrays.copyOfRange(data,from,to))));
        }
        assertTrue(n.receivedByY.isEmpty());assertEquals(1,n.y.corrupt());assertEquals(0,n.y.completedIn());
        assertEquals(0,n.y.activeIn());assertEquals(0,n.y.reservedBytes());
    }
    @Test void aCorruptedTransferGetsNoFullAckAndItsDuplicatesGetNoAckEither() {
        Net n=Net.withSink();byte[] data=data(2500,1);
        byte[] wrongDigest=DhtTransfers.digestOf(data(2500,2));
        for(int i=0;i<3;i++) {
            int from=i*1024,to=Math.min(2500,from+1024);
            n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),wrongDigest,2500,i,3,java.util.Arrays.copyOfRange(data,from,to))));
        }
        assertEquals(1,n.y.corrupt());
        // 最後の断片には ACK を返していない（返したのは先の 2 通だけ）。全ビットの ACK はひとつもない。
        assertEquals(2,n.toX.size());
        for(Frame f:n.toX) {
            byte[] bits=DhtWire.parse(f.bytes()).received();
            assertFalse(bits[0]==0b111,"corrupt transfer must not be acknowledged as complete");
        }
        // 重複の断片にも ACK を返さない（送り手に枠を取り直させない）。
        n.toX.clear();
        for(int i=0;i<3;i++) {
            int from=i*1024,to=Math.min(2500,from+1024);
            n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),wrongDigest,2500,i,3,java.util.Arrays.copyOfRange(data,from,to))));
        }
        assertTrue(n.toX.isEmpty());assertEquals(0,n.y.activeIn());assertEquals(0,n.y.reservedBytes());
    }
    @Test void aSenderWhoseTransferArrivesCorruptedDoesNotCountItAsDone() {
        Net n=Net.withSink();byte[] data=data(2500,1);
        n.mutateToY=f->{
            var m=DhtWire.parse(f.bytes());
            if(m.index()!=2)return f;
            byte[] p=m.piece().clone();p[0]^=1;
            return new Frame(f.to(),DhtWire.transfer(GROUP,m.transferKind(),m.transferId(),m.digest(),m.totalBytes(),m.index(),m.count(),p));
        };
        assertTrue(n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data));
        n.pump();
        assertEquals(1,n.y.corrupt());assertTrue(n.receivedByY.isEmpty());
        assertEquals(0,n.x.completedOut());
        // 全ビットの ACK が来ないので、送り手は送り直し、最後には失敗と数える。
        for(int i=0;i<10;i++){n.nanos.addAndGet(2*SECOND);n.x.poll();n.pump();}
        assertEquals(0,n.x.completedOut());assertEquals(1,n.x.failedOut());assertEquals(0,n.x.activeOut());
    }
    @Test void aCompletedTransferAnswersADuplicateOnlyWhenDigestTotalAndKindMatch() {
        Net n=Net.withSink();byte[] data=data(2500,1);
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data);
        byte[] last=null;for(Frame f:n.toY)if(DhtWire.parse(f.bytes()).index()==2)last=f.bytes();
        n.pump();
        assertEquals(1,n.y.completedIn());n.toX.clear();
        byte[] piece=DhtWire.parse(last).piece();
        byte[] dg=DhtTransfers.digestOf(data);
        // 別の digest・別の総バイト数・別の種類の重複には、ACK を返さない。
        n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),DhtTransfers.digestOf(data(2500,2)),2500,2,3,piece)));
        assertTrue(n.toX.isEmpty(),"different digest");
        n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),dg,2499,2,3,java.util.Arrays.copyOf(piece,piece.length-1))));
        assertTrue(n.toX.isEmpty(),"different total");
        n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.VALUE,tid(1),dg,2500,2,3,piece)));
        assertTrue(n.toX.isEmpty(),"different kind");
        // 全部合う重複には返す。
        n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),dg,2500,2,3,piece)));
        assertEquals(1,n.toX.size());
        assertArrayEquals(dg,DhtWire.parse(n.toX.peek().bytes()).digest());
    }
    @Test void aSecondTransferToTheSamePeerIsRefusedAndAThirdOverallToo() {
        Net n=Net.withSink();
        assertTrue(n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data(5000,1)));
        assertFalse(n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(2),data(5000,2)));
        assertTrue(n.x.start(id(3),SESSION,DhtWire.TransferKind.STORE,tid(3),data(5000,3)));
        assertFalse(n.x.start(id(4),SESSION,DhtWire.TransferKind.STORE,tid(4),data(5000,4)));
        assertEquals(2,n.x.activeOut());
    }
    @Test void aSenderThatCannotSendTheFirstPieceDoesNotKeepTheTransfer() {
        Net n=Net.withSink();n.xCanSend=false;
        assertFalse(n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data(5000,1)));
        assertEquals(0,n.x.activeOut());
    }
    @Test void aReceiverAcceptsOnePerPeerAndTwoInTotalAndReservesTheBytes() {
        Net n=Net.withSink();
        for(int peer=1;peer<=3;peer++) {
            byte[] data=data(DhtWire.MAX_TRANSFER_BYTES,peer);
            n.y.receive(id(peer),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(peer),DhtTransfers.digestOf(data),data.length,0,DhtWire.MAX_PIECES,java.util.Arrays.copyOf(data,1024))));
        }
        assertEquals(2,n.y.activeIn());assertEquals(2L*DhtWire.MAX_TRANSFER_BYTES,n.y.reservedBytes());
        assertTrue(n.y.reservedBytes()<=DhtTransfers.RESERVE_BYTES);assertEquals(1,n.y.rejected());
        // 同じ相手の 2 件目
        byte[] data=data(5000,9);
        n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(50),DhtTransfers.digestOf(data),5000,0,5,java.util.Arrays.copyOf(data,1024))));
        assertEquals(2,n.y.activeIn());assertEquals(2,n.y.rejected());
    }
    @Test void aReceiverWithoutASinkDropsEverythingAndSendsNoAck() {
        Net n=new Net();
        byte[] data=data(3000,1);
        n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),DhtTransfers.digestOf(data),3000,0,3,java.util.Arrays.copyOf(data,1024))));
        assertEquals(0,n.y.activeIn());assertEquals(0,n.y.reservedBytes());assertEquals(1,n.y.unsupported());assertTrue(n.toX.isEmpty());
    }
    @Test void aValueTransferNobodyAskedForIsNotReserved() {
        Net n=Net.withSink();byte[] data=data(3000,1);
        byte[] piece=DhtWire.transfer(GROUP,DhtWire.TransferKind.VALUE,tid(1),DhtTransfers.digestOf(data),3000,0,3,java.util.Arrays.copyOf(data,1024));
        n.y.receive(id(1),SESSION,DhtWire.parse(piece));
        assertEquals(0,n.y.activeIn());assertEquals(1,n.y.rejected());assertTrue(n.toX.isEmpty());
        n.valueExpected=true;
        n.y.receive(id(1),SESSION,DhtWire.parse(piece));
        assertEquals(1,n.y.activeIn());
    }
    @Test void aTransferThatStopsMakingProgressIsDroppedAfterThirtySeconds() {
        Net n=Net.withSink();byte[] data=data(5000,1);
        n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),DhtTransfers.digestOf(data),5000,0,5,java.util.Arrays.copyOf(data,1024))));
        assertEquals(1,n.y.activeIn());
        n.nanos.addAndGet(29*SECOND);n.y.poll();assertEquals(1,n.y.activeIn());
        n.nanos.addAndGet(SECOND);n.y.poll();assertEquals(0,n.y.activeIn());assertEquals(0,n.y.reservedBytes());assertEquals(1,n.y.abandonedIn());
    }
    @Test void aDuplicatePieceDoesNotCountAsProgress() {
        Net n=Net.withSink();byte[] data=data(5000,1);
        byte[] first=DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),DhtTransfers.digestOf(data),5000,0,5,java.util.Arrays.copyOf(data,1024));
        n.y.receive(id(1),SESSION,DhtWire.parse(first));
        for(int i=0;i<10;i++){n.nanos.addAndGet(3*SECOND);n.y.receive(id(1),SESSION,DhtWire.parse(first));}
        n.y.poll();assertEquals(0,n.y.activeIn());
    }
    @Test void aSlowTrickleStillEndsAfterTwoHundredFortySeconds() {
        Net n=Net.withSink();byte[] data=data(DhtWire.MAX_TRANSFER_BYTES,1);byte[] digest=DhtTransfers.digestOf(data);
        n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),digest,data.length,0,DhtWire.MAX_PIECES,java.util.Arrays.copyOf(data,1024))));
        for(int i=1;i<=12&&n.y.activeIn()>0;i++) {
            n.nanos.addAndGet(25*SECOND);
            n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),digest,data.length,i,DhtWire.MAX_PIECES,java.util.Arrays.copyOfRange(data,i*1024,i*1024+1024))));
            n.y.poll();
        }
        assertEquals(0,n.y.activeIn());assertEquals(1,n.y.abandonedIn());
    }
    @Test void aPieceWithADifferentDigestOrSessionForAKnownTransferIsNotCopied() {
        Net n=Net.withSink();byte[] data=data(3000,1);
        byte[] ok=DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),DhtTransfers.digestOf(data),3000,0,3,java.util.Arrays.copyOf(data,1024));
        n.y.receive(id(1),SESSION,DhtWire.parse(ok));
        byte[] otherSession=new byte[16];otherSession[0]=1;
        n.y.receive(id(1),otherSession,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),DhtTransfers.digestOf(data),3000,1,3,java.util.Arrays.copyOfRange(data,1024,2048))));
        n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),DhtTransfers.digestOf(data(3000,2)),3000,1,3,java.util.Arrays.copyOfRange(data,1024,2048))));
        assertEquals(2,n.y.mismatched());assertEquals(1,n.y.activeIn());
    }
    @Test void afterCompletionADuplicatePieceGetsAFullAckUpToALimit() {
        Net n=Net.withSink();byte[] data=data(2500,1);
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data);
        // 最後の断片を控える。
        byte[] last=null;for(Frame f:n.toY)if(DhtWire.parse(f.bytes()).index()==2)last=f.bytes();
        byte[] first=null;for(Frame f:n.toY)if(DhtWire.parse(f.bytes()).index()==0)first=f.bytes();
        n.pump();
        assertEquals(1,n.y.completedIn());
        n.toX.clear();
        n.y.receive(id(1),SESSION,DhtWire.parse(first));assertEquals(1,n.toX.size());
        n.toX.clear();
        n.y.receive(id(1),SESSION,DhtWire.parse(last));assertEquals(1,n.toX.size());
        var ack=DhtWire.parse(n.toX.peek().bytes());assertEquals(DhtWire.Op.TRANSFER_ACK,ack.op());
        assertEquals(1,n.receivedByY.size());
        // 返すACKの数には上限がある（3 断片 × (送り直し 3 回 + 1)）。
        n.toX.clear();
        for(int i=0;i<100;i++)n.y.receive(id(1),SESSION,DhtWire.parse(last));
        // すでに 2 回返したので、残りはちょうど 3*(MAX_RETRIES+1)-2 回（0 通でも通る書き方にしない）。
        assertEquals(3*(DhtTransfers.MAX_RETRIES+1)-2,n.toX.size());
        // 30 秒たつと覚えを消し、重複には答えない。
        n.toX.clear();n.nanos.addAndGet(31*SECOND);n.y.poll();
        n.y.receive(id(1),SESSION,DhtWire.parse(last));
        assertEquals(1,n.y.activeIn()); // 新しい転送として始まる（予約される）
    }
    @Test void anAckForAnUnknownTransferOrWithWrongDigestIsIgnored() {
        Net n=Net.withSink();byte[] data=data(5000,1);
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data);
        byte[] all=new byte[1];all[0]=0x1F;
        n.x.receive(id(2),SESSION,DhtWire.parse(DhtWire.transferAck(GROUP,tid(99),DhtTransfers.digestOf(data),5,all)));
        n.x.receive(id(2),SESSION,DhtWire.parse(DhtWire.transferAck(GROUP,tid(1),DhtTransfers.digestOf(data(5000,2)),5,all)));
        assertEquals(2,n.x.mismatched());assertEquals(1,n.x.activeOut());assertEquals(0,n.x.completedOut());
    }
    @Test void anAckForPiecesNeverSentDoesNotCompleteTheTransfer() {
        Net n=Net.withSink();byte[] data=data(DhtWire.PIECE_BYTES*10,1);
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data);
        byte[] all=new byte[]{(byte)0xFF,0x03};
        n.x.receive(id(2),SESSION,DhtWire.parse(DhtWire.transferAck(GROUP,tid(1),DhtTransfers.digestOf(data),10,all)));
        // 送った 4 個だけが受け付けられ、完了にはならない。
        assertEquals(1,n.x.activeOut());assertEquals(0,n.x.completedOut());
    }
    @Test void anAckFromAnotherSessionIsIgnored() {
        Net n=Net.withSink();byte[] data=data(1000,1);
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data);
        byte[] other=new byte[16];other[0]=1;
        n.x.receive(id(2),other,DhtWire.parse(DhtWire.transferAck(GROUP,tid(1),DhtTransfers.digestOf(data),1,new byte[]{1})));
        assertEquals(1,n.x.activeOut());assertEquals(1,n.x.mismatched());
    }
    @Test void aFloodOfPiecesIsLimitedByThePeerBucket() {
        Net n=Net.withSink();byte[] data=data(DhtWire.MAX_TRANSFER_BYTES,1);byte[] digest=DhtTransfers.digestOf(data);
        for(int i=0;i<1000;i++) {
            n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),digest,data.length,i,DhtWire.MAX_PIECES,java.util.Arrays.copyOfRange(data,i*1024,i*1024+1024))));
        }
        assertEquals(1000-400,n.y.rateLimited());
    }
    @Test void aFloodFromManyPeersIsLimitedByTheTotalBucket() {
        Net n=Net.withSink();byte[] data=data(DhtWire.MAX_TRANSFER_BYTES,1);byte[] digest=DhtTransfers.digestOf(data);
        for(int peer=1;peer<=20;peer++)for(int i=0;i<100;i++) {
            n.y.receive(id(peer),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(1),digest,data.length,i,DhtWire.MAX_PIECES,java.util.Arrays.copyOfRange(data,i*1024,i*1024+1024))));
        }
        assertEquals(2000-800,n.y.rateLimited());
    }
    @Test void forgetAndClearDropTheTransfers() {
        Net n=Net.withSink();byte[] data=data(5000,1);
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data);
        n.y.receive(id(1),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(2),DhtTransfers.digestOf(data),5000,0,5,java.util.Arrays.copyOf(data,1024))));
        n.x.forget(id(2));assertEquals(0,n.x.activeOut());
        n.y.forget(id(1));assertEquals(0,n.y.activeIn());assertEquals(0,n.y.reservedBytes());
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(3),data);n.x.clear();assertEquals(0,n.x.activeOut());
    }
    @Test void aSinkThatThrowsDoesNotBreakTheTransfer() {
        Net n=new Net((p,k,d)->{throw new IllegalStateException("x");},DhtTransfers.Limits.defaults());
        byte[] data=data(1500,1);
        n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,tid(1),data);
        n.pump();
        assertEquals(1,n.y.completedIn());assertEquals(1,n.x.completedOut());
    }
    @Test void aStartWithoutAnIdPicksARandomOne() {
        Net n=Net.withSink();
        byte[] id=n.x.start(id(2),SESSION,DhtWire.TransferKind.STORE,data(3000,1));
        assertNotNull(id);assertEquals(16,id.length);
    }
    @Test void thereIsNoIdentifierInTheStringForms() {
        Net n=Net.withSink();
        assertEquals("DHT transfers",n.x.toString());assertEquals("DHT transfer limits",DhtTransfers.Limits.defaults().toString());
    }
}
