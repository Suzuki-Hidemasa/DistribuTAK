// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SessionManagerTest.Node;

class SessionManagerFix3Test {
    final SessionManagerFix2Test h=new SessionManagerFix2Test();
    final SessionManagerFix1Test g=h.g;
    final SessionManagerTest f=g.f;
    Node node(int n) { return g.node(n); }
    void candidate(Node sender,Node responder) {
        sender.remember(responder);responder.remember(sender);
        var reply=responder.sessions.receive(sender.sessions.start(responder.id).packet());assertEquals(1,reply.outbound().size());
        assertTrue(responder.sessions.isHandshaking(sender.id));assertFalse(responder.sessions.isEstablished(sender.id));
    }
    void bidirectionalData(Node a,Node b) {
        assertArrayEquals(new byte[]{1},b.sessions.receive(f.data(a,b,1)).plaintext());
        assertArrayEquals(new byte[]{2},a.sessions.receive(f.data(b,a,2)).plaintext());
    }
    @Test void candidateSurvivesTwoRotationsBeforeFirstPollAndEstablishesInBothDirections() throws Exception {
        for(boolean reverse:new boolean[]{false,true}) for(int rotations:new int[]{1,2}) {
            try(var a=node(1);var b=node(2)) {
                Node sender=reverse ? b : a,responder=reverse ? a : b;candidate(sender,responder);
                var old=f.secrets(responder,sender);
                for(int version=1;version<=rotations;version++) {
                    a.sessions.rotateGroupKey(key(50+version),version);b.sessions.rotateGroupKey(key(50+version),version);
                }
                f.wiped(old);var first=responder.sessions.poll();assertEquals(1,first.size());
                assertEquals(rotations,SessionPacket.decode(first.get(0).packet()).version());
                g.finish(responder,sender,first.get(0));bidirectionalData(a,b);
            }
        }
    }
    @Test void candidateRotationKeepsEighteenPacketBudgetThroughRepeatedRotations() throws Exception {
        for(int mode=0;mode<3;mode++) {
            try(var a=node(1);var b=node(2)) {
                candidate(a,b);f.time.advance(1);b.sessions.rotateGroupKey(key(51),1);
                long version=1;
                if(mode==1) b.sessions.rotateGroupKey(key(52),++version);
                var times=new ArrayList<Integer>();List<byte[]> lastKeys=List.of();
                for(int second=0;second<=100;second++) {
                    if(mode==2 && second>0) b.sessions.rotateGroupKey(key(53),++version);
                    var out=b.sessions.poll();assertTrue(out.size()<=1);
                    if(!out.isEmpty()) {
                        times.add(second);assertEquals(SessionPacket.FIRST,SessionPacket.decode(out.get(0).packet()).kind());
                        assertEquals(version,SessionPacket.decode(out.get(0).packet()).version());lastKeys=f.secrets(b,a);
                    }
                    if(second>=90) { assertTrue(out.isEmpty());assertFalse(b.sessions.isHandshaking(a.id));f.wiped(lastKeys); }
                    f.time.advance(1);
                }
                assertEquals(h.slots(),times);
            }
        }
    }
    @Test void delayedPollUsesOnlyTimeRemainingSinceCandidateRotation() {
        for(int delay:new int[]{0,60,89}) {
            try(var a=node(1);var b=node(2)) {
                candidate(a,b);f.time.advance(1);b.sessions.rotateGroupKey(key(51),1);f.time.advance(delay);
                var times=new ArrayList<Integer>();
                for(int second=delay;second<=160;second++) {
                    var out=b.sessions.poll();assertTrue(out.size()<=1);
                    if(!out.isEmpty()) times.add(second);
                    if(second>=90) { assertTrue(out.isEmpty());assertFalse(b.sessions.isHandshaking(a.id)); }
                    f.time.advance(1);
                }
                var expected=new ArrayList<Integer>();for(int second=delay;second<90;second+=5) expected.add(second);
                assertEquals(expected,times);
            }
        }
    }
    @Test void firstPollAtOrAfterNinetySecondsEmitsNothingButSendCanStartANewAttempt() throws Exception {
        for(int delay:new int[]{90,91}) {
            try(var a=node(1);var b=node(2)) {
                candidate(a,b);var old=f.secrets(b,a);f.time.advance(1);
                a.sessions.rotateGroupKey(key(51),1);b.sessions.rotateGroupKey(key(51),1);f.wiped(old);
                f.time.advance(delay);
                for(int i=0;i<10;i++) { assertTrue(b.sessions.poll().isEmpty());assertFalse(b.sessions.isHandshaking(a.id));f.time.advance(1); }
                var demand=b.sessions.sendWithStatus(a.id,new byte[]{99});assertFalse(demand.plaintextSent());assertEquals(1,demand.outbound().size());
                g.finish(b,a,demand.outbound().get(0));bidirectionalData(a,b);
            }
        }
    }
    @Test void rotatingBothSidesTwiceAtEightyNineSecondsPreservesResponderScheduleAndConverges() {
        for(int rotations:new int[]{1,2}) {
            try(var a=node(1);var b=node(2)) {
                Node low=g.low(a,b),high=low==a ? b : a;candidate(high,low);f.time.advance(89);
                for(int version=1;version<=rotations;version++) {
                    low.sessions.rotateGroupKey(key(50+version),version);high.sessions.rotateGroupKey(key(50+version),version);
                }
                var initial=low.sessions.poll();assertEquals(1,initial.size());g.finish(low,high,initial.get(0));
                for(int second=90;second<=119;second++) {
                    f.time.advance(1);assertTrue(low.sessions.poll().isEmpty());assertTrue(high.sessions.poll().isEmpty());
                    assertTrue(low.sessions.isEstablished(high.id));assertTrue(high.sessions.isEstablished(low.id));
                }
                bidirectionalData(low,high);
            }
        }
    }
    @Test void freshCandidateTakesPriorityOverPreviousExhaustionWithOrWithoutOldSession() throws Exception {
        for(boolean exhausted:new boolean[]{false,true}) for(boolean established:new boolean[]{false,true}) {
            try(var a=node(1);var b=node(2)) {
                a.remember(b);b.remember(a);
                if(established) f.connect(a,b);
                if(exhausted) {
                    if(established) { g.setSent(a,b,NoiseTransport.REKEY_MESSAGES);a.sessions.poll(); }
                    else a.sessions.start(b.id);
                    f.time.advance(90);assertTrue(a.sessions.poll().isEmpty());assertFalse(a.sessions.isHandshaking(b.id));
                }
                a.sessions.receive(b.sessions.start(a.id).packet());var keys=f.secrets(a,b);
                NoiseTransport old=established ? f.active(a,b) : null;
                a.sessions.rotateGroupKey(key(51),1);b.sessions.rotateGroupKey(key(51),1);
                f.wiped(keys.subList(established ? 2 : 0,keys.size()));
                if(old!=null) assertFalse(old.isClosed());
                var first=a.sessions.poll();assertEquals(1,first.size());g.finish(a,b,first.get(0));
                if(old!=null) assertTrue(old.isClosed());bidirectionalData(a,b);
            }
        }
    }
}
