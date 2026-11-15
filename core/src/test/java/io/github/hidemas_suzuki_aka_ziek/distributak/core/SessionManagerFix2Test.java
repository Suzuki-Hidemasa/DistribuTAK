// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SessionManagerTest.Node;

class SessionManagerFix2Test {
    final SessionManagerFix1Test g=new SessionManagerFix1Test();
    final SessionManagerTest f=g.f;
    Node node(int n) { return g.node(n); }
    byte[] forged(SessionManager.Outbound first) {
        var p=SessionPacket.decode(first.packet());return new SessionPacket(SessionPacket.SECOND,p.id(),p.version(),0,new byte[60]).encode();
    }
    List<Integer> slots() { var result=new ArrayList<Integer>();for(int i=0;i<90;i+=5) result.add(i);return result; }
    @Test void forgedSecondEverySecondCannotExceedEighteenFirstsOrExtendNinetySeconds() {
        try(var a=node(1);var b=node(2)) {
            a.remember(b);b.remember(a);var current=a.sessions.start(b.id);var sentAt=new ArrayList<Integer>();sentAt.add(0);
            for(int second=1;second<=300;second++) {
                byte[] fake=forged(current);assertThrows(SecurityException.class,()->a.sessions.receive(fake));
                f.time.advance(1);var out=a.sessions.poll();assertTrue(out.size()<=1);
                if(!out.isEmpty()) { current=out.get(0);sentAt.add(second); }
                if(second>=90) { assertTrue(out.isEmpty());assertFalse(a.sessions.isHandshaking(b.id)); }
            }
            assertEquals(slots(),sentAt);
            var restarted=a.sessions.sendWithStatus(b.id,new byte[]{99});assertFalse(restarted.plaintextSent());
            g.finish(a,b,restarted.outbound().get(0));assertArrayEquals(new byte[]{1},b.sessions.receive(f.data(a,b,1)).plaintext());
        }
    }
    @Test void olderCertificateSecondDoesNotCauseBusyLoopAndStopsAtOriginalDeadline() {
        try(var a=node(1);var b=node(2)) {
            a.remember(b);b.remember(a);f.time.advance(10);var latest=b.certificate(b.secret,f.time.millis());a.sessions.rememberPeer(latest);
            var first=a.sessions.sendWithStatus(b.id,new byte[]{1}).outbound().get(0);
            byte[] reply=b.sessions.receive(first.packet()).outbound().get(0).packet();
            assertThrows(SecurityException.class,()->a.sessions.receive(reply));
            for(int i=0;i<1000;i++) assertTrue(a.sessions.poll().isEmpty());
            var times=new ArrayList<Integer>();times.add(0);
            for(int second=1;second<=100;second++) {
                f.time.advance(1);
                for(var retry:a.sessions.poll()) {
                    times.add(second);var response=b.sessions.receive(retry.packet()).outbound().get(0).packet();
                    assertThrows(SecurityException.class,()->a.sessions.receive(response));
                }
            }
            assertEquals(slots(),times);assertFalse(a.sessions.isHandshaking(b.id));
            b.sessions.updateLocalCertificate(latest);
            g.finish(a,b,a.sessions.sendWithStatus(b.id,new byte[]{1}).outbound().get(0));
            assertArrayEquals(new byte[]{2},a.sessions.receive(f.data(b,a,2)).plaintext());
        }
    }
    @Test void singleForgedSecondWaitsFiveSecondsThenRecoversWithoutDamagingOldKeys() throws Exception {
        for(boolean fake:new boolean[]{false,true}) {
            try(var a=node(1);var b=node(2)) {
                f.connect(a,b);f.time.advance(120);var oldA=f.secrets(a,b);var oldB=f.secrets(b,a);
                var first=a.sessions.poll().get(0);var reply=b.sessions.receive(first.packet()).outbound().get(0);
                if(fake) {
                    assertThrows(SecurityException.class,()->a.sessions.receive(forged(first)));
                    for(int i=0;i<1000;i++) assertTrue(a.sessions.poll().isEmpty());
                    f.time.advance(4);assertTrue(a.sessions.poll().isEmpty());f.time.advance(1);
                    reply=b.sessions.receive(a.sessions.poll().get(0).packet()).outbound().get(0);
                }
                b.sessions.receive(a.sessions.receive(reply.packet()).outbound().get(0).packet());
                f.wiped(oldA);f.wiped(oldB);assertArrayEquals(new byte[]{3},b.sessions.receive(f.data(a,b,3)).plaintext());
            }
        }
    }
    @Test void rotatingNeverContactedExhaustedAndExpiredPeersIsSilentUntilSend() {
        for(int stage=0;stage<4;stage++) {
            try(var a=node(1);var b=node(2)) {
                a.remember(b);b.remember(a);
                if(stage==1) { a.sessions.start(b.id);f.time.advance(90);assertTrue(a.sessions.poll().isEmpty()); }
                if(stage==2) { f.connect(a,b);f.time.advance(181);a.sessions.refresh();b.sessions.refresh(); }
                if(stage==3) {
                    b.sessions.receive(a.sessions.start(b.id).packet());f.time.advance(90);a.sessions.refresh();b.sessions.refresh();
                }
                a.sessions.rotateGroupKey(key(50),1);b.sessions.rotateGroupKey(key(50),1);
                for(int second=0;second<100;second++) {
                    assertTrue(a.sessions.poll().isEmpty());assertTrue(b.sessions.poll().isEmpty());f.time.advance(1);
                }
                var send=a.sessions.sendWithStatus(b.id,new byte[]{99});assertFalse(send.plaintextSent());assertEquals(1,send.outbound().size());
                assertEquals(1,SessionPacket.decode(send.outbound().get(0).packet()).version());g.finish(a,b,send.outbound().get(0));
                assertArrayEquals(new byte[]{4},b.sessions.receive(f.data(a,b,4)).plaintext());
            }
        }
    }
    SessionManager replacement(Node source,Clock clock) {
        var state=new AdminState(f.group,Crypto.ed25519Public(f.admin),clock,new InMemoryAdminRecordStore());
        var admins=AdminRecords.list(ADMINS,f.group,0,f.time.millis(),List.of(Crypto.ed25519Public(f.admin)),f.admin);
        state.bootstrap(admins,AdminRecords.signAnchor(admins,f.admin));
        state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,0,f.time.millis(),List.of(),f.admin));
        return new SessionManager(state,source.cert,source.secret,f.psk,0,clock,()->f.time.nanos,256);
    }
    void exchange(SessionManager from,Node remote,byte[] id) {
        var first=from.start(id);var replies=remote.sessions.receive(first.packet()).outbound();assertEquals(1,replies.size());
        var confirms=from.receive(replies.get(0).packet()).outbound();assertEquals(1,confirms.size());remote.sessions.receive(confirms.get(0).packet());
        assertTrue(from.isEstablished(id));
    }
    @Test void restartAfterSimultaneousWorksAtSameTickAndWhenClockAdvanced() {
        for(boolean advance:new boolean[]{true,false}) {
            try(var a=node(1);var b=node(2)) {
                Node low=g.low(a,b),high=low==a ? b : a;a.remember(b);b.remember(a);
                var lf=low.sessions.start(high.id);high.sessions.start(low.id);g.finish(low,high,lf);
                assertTrue(gEmptyGuard(low));high.sessions.close();if(advance) f.time.advance(1);
                try(var restarted=replacement(high,f.time)) {
                    restarted.rememberPeer(low.cert);exchange(restarted,low,low.id);
                    assertArrayEquals(new byte[]{5},low.sessions.receive(restarted.send(high==a ? b.id : a.id,new byte[]{5}).get(0).packet()).plaintext());
                    assertArrayEquals(new byte[]{6},restarted.receive(f.data(low,high,6)).plaintext());
                }
            }
        }
    }
    boolean gEmptyGuard(Node n) { try { return g.timestamps(n).isEmpty(); }catch(Exception e) { throw new AssertionError(e); } }
    @Test void restartingWithWallClockSixtySecondsBehindWorksWhenFirstReplayGuardIsEmpty() {
        for(boolean rollback:new boolean[]{false,true}) {
            try(var a=node(1);var b=node(2)) {
                Node low=g.low(a,b),high=low==a ? b : a;f.time.advance(120);f.connect(low,high);
                assertTrue(gEmptyGuard(low));high.sessions.close();f.time.advance(2);
                Clock remoteClock=Clock.offset(f.time,rollback ? Duration.ofSeconds(-60) : Duration.ZERO);
                try(var restarted=replacement(high,remoteClock)) {
                    restarted.rememberPeer(low.cert);exchange(restarted,low,low.id);
                    var data=restarted.sendWithStatus(low.id,new byte[]{7});assertTrue(data.plaintextSent());
                    assertArrayEquals(new byte[]{7},low.sessions.receive(data.outbound().get(0).packet()).plaintext());
                    assertArrayEquals(new byte[]{8},restarted.receive(f.data(low,high,8)).plaintext());
                }
            }
        }
    }
    @Test void delayedLosingFirstKeepsCurrentSessionAndItsResponseIsBoundedIncludingDuplicates() throws Exception {
        try(var a=node(1);var b=node(2)) {
            Node low=g.low(a,b),high=low==a ? b : a;a.remember(b);b.remember(a);
            var lf=low.sessions.start(high.id);byte[] delayed=high.sessions.start(low.id).packet();g.finish(low,high,lf);
            var activeLow=f.active(low,high);var activeHigh=f.active(high,low);var oldLow=f.secrets(low,high);
            var reply=low.sessions.receive(delayed).outbound();assertEquals(1,reply.size());
            assertThrows(SecurityException.class,()->high.sessions.receive(reply.get(0).packet()));
            assertSame(activeLow,f.active(low,high));assertSame(activeHigh,f.active(high,low));
            var candidate=f.secrets(low,high).subList(2,4);int responses=1;
            for(int second=0;second<90;second++) {
                for(int i=0;i<10;i++) responses+=low.sessions.receive(delayed).outbound().size();
                responses+=low.sessions.poll().size();
                assertArrayEquals(new byte[]{9},high.sessions.receive(f.data(low,high,9)).plaintext());
                assertArrayEquals(new byte[]{10},low.sessions.receive(f.data(high,low,10)).plaintext());
                f.time.advance(1);
            }
            assertEquals(18,responses);low.sessions.refresh();f.wiped(candidate);assertFalse(activeLow.isClosed());
            for(byte[] secret:oldLow) assertFalse(Arrays.equals(secret,new byte[secret.length]));
            assertFalse(low.sessions.isHandshaking(high.id));assertTrue(low.sessions.poll().isEmpty());
            assertThrows(SecurityException.class,()->low.sessions.receive(delayed));
            f.time.advance(30);var rekey=low.sessions.poll();assertEquals(1,rekey.size());
            g.finish(low,high,rekey.get(0));assertTrue(activeLow.isClosed());assertTrue(activeHigh.isClosed());
            assertArrayEquals(new byte[]{11},high.sessions.receive(f.data(low,high,11)).plaintext());
        }
    }
    @Test void rotationDuringFailedAttemptPreservesOriginalFiveSecondPacingAndNinetySecondDeadline() throws Exception {
        try(var a=node(1);var b=node(2)) {
            a.remember(b);var first=a.sessions.start(b.id);
            assertThrows(SecurityException.class,()->a.sessions.receive(forged(first)));
            f.time.advance(4);a.sessions.rotateGroupKey(key(50),1);assertTrue(a.sessions.poll().isEmpty());
            f.time.advance(1);var next=a.sessions.poll();assertEquals(1,next.size());assertEquals(1,SessionPacket.decode(next.get(0).packet()).version());
            assertFalse(Arrays.equals(Arrays.copyOf(SessionPacket.decode(first.packet()).body(),32),
                Arrays.copyOf(SessionPacket.decode(next.get(0).packet()).body(),32)));
            assertThrows(SecurityException.class,()->a.sessions.receive(forged(next.get(0))));
            f.time.advance(84);a.sessions.rotateGroupKey(key(51),2);var last=a.sessions.poll();assertEquals(1,last.size());
            var keys=f.secrets(a,b);f.time.advance(1);assertTrue(a.sessions.poll().isEmpty());f.wiped(keys);
            assertFalse(a.sessions.isHandshaking(b.id));f.time.advance(5);assertTrue(a.sessions.poll().isEmpty());
        }
    }
    @Test void explicitStartCannotBypassPacingButCanRequestANewAttemptAfterTimeout() throws Exception {
        try(var a=node(1);var b=node(2)) {
            a.remember(b);b.remember(a);var first=a.sessions.start(b.id);
            for(int i=0;i<100;i++) assertThrows(IllegalStateException.class,()->a.sessions.start(b.id));
            assertTrue(a.sessions.sendWithStatus(b.id,new byte[]{99}).outbound().isEmpty());
            f.time.advance(4);assertThrows(IllegalStateException.class,()->a.sessions.start(b.id));
            f.time.advance(1);assertArrayEquals(first.packet(),a.sessions.start(b.id).packet());assertTrue(a.sessions.poll().isEmpty());
            var keys=f.secrets(a,b);f.time.advance(85);assertTrue(a.sessions.poll().isEmpty());f.wiped(keys);
            var fresh=a.sessions.start(b.id);assertFalse(Arrays.equals(first.packet(),fresh.packet()));
            g.finish(a,b,fresh);assertArrayEquals(new byte[]{12},b.sessions.receive(f.data(a,b,12)).plaintext());
        }
    }
    @Test void exhaustedEarlyRekeyIsNotAutomaticallyRescheduledByGroupRotationEvenWhileOldSessionRemains() throws Exception {
        try(var a=node(1);var b=node(2)) {
            f.connect(a,b);g.setSent(a,b,NoiseTransport.REKEY_MESSAGES);a.sessions.poll();
            var old=f.active(a,b);var pending=f.secrets(a,b).subList(2,f.secrets(a,b).size());
            f.time.advance(90);assertTrue(a.sessions.poll().isEmpty());f.wiped(pending);assertTrue(a.sessions.isEstablished(b.id));
            a.sessions.rotateGroupKey(key(50),1);b.sessions.rotateGroupKey(key(50),1);
            assertTrue(a.sessions.poll().isEmpty());assertFalse(old.isClosed());
            var demand=a.sessions.sendWithStatus(b.id,new byte[]{99});assertTrue(demand.plaintextSent());
            assertEquals(SessionPacket.FIRST,SessionPacket.decode(demand.outbound().get(0).packet()).kind());
            g.finish(a,b,demand.outbound().get(0));assertTrue(old.isClosed());
            assertArrayEquals(new byte[]{13},b.sessions.receive(f.data(a,b,13)).plaintext());
        }
    }
}
