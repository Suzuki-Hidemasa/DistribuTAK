// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.AuthenticatedPeer;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtId;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** 核 C1: DHT の相手は、全検査を通した確立済みのセッションからだけ作れる。 */
class VerifiedSessionTest {
    private final SessionManagerTest t=new SessionManagerTest();
    @Test void onlyAnEstablishedPeerGivesAVerifiedSession() {
        try(var a=t.new Node(1);var b=t.new Node(2)) {
            assertNull(a.sessions.verifiedSession(b.id));
            a.remember(b);b.remember(a);assertNull(a.sessions.verifiedSession(b.id));
            // 握手の途中（2通目を受けただけ）では、まだ確認済みにならない。
            var second=b.sessions.receive(a.sessions.start(b.id).packet());assertNull(a.sessions.verifiedSession(b.id));
            var confirm=a.sessions.receive(second.outbound().get(0).packet());b.sessions.receive(confirm.outbound().get(0).packet());
            var session=a.sessions.verifiedSession(b.id);assertNotNull(session);
            assertArrayEquals(b.id,session.peerId());assertArrayEquals(a.sessions.sessionId(b.id),session.sessionId());
        }
    }
    @Test void anUnknownPeerAndAWrongLengthGiveNothing() {
        try(var a=t.new Node(1)) {
            assertNull(a.sessions.verifiedSession(new byte[32]));
            assertThrows(RuntimeException.class,()->a.sessions.verifiedSession(new byte[5]));
        }
    }
    @Test void theDhtPeerKeepsTheNodeIdAndTheGenerationFromTheSession() {
        try(var a=t.new Node(1);var b=t.new Node(2)) {
            t.connect(a,b);var session=a.sessions.verifiedSession(b.id);
            assertEquals(0,session.generation());
            var peer=AuthenticatedPeer.fromVerifiedSession(session);
            assertEquals(new DhtId(b.id),peer.id());
            assertFalse(peer.toString().contains("="));
        }
    }
    @Test void theGenerationGrowsWithEachNetworkChangeAndIsTakenWhenTheSessionIsMade() {
        try(var a=t.new Node(1);var b=t.new Node(2)) {
            t.connect(a,b);
            var before=a.sessions.verifiedSession(b.id);
            assertEquals(0,a.sessions.generation());
            a.sessions.forgetAllVolatile();
            assertEquals(1,a.sessions.generation());
            // 前に作ったセッションの世代は変わらない。保存した相手の新しい確認は新しい世代を持つ。
            assertEquals(0,before.generation());
            assertEquals(1,a.sessions.verifiedSession(b.id).generation());
            a.sessions.forgetAllVolatile();
            assertEquals(2,a.sessions.verifiedSession(b.id).generation());
        }
    }
    @Test void aVerifiedSessionDoesNotShowItsIdsInText() {
        try(var a=t.new Node(1);var b=t.new Node(2)) {
            t.connect(a,b);assertEquals("Verified session",a.sessions.verifiedSession(b.id).toString());
        }
    }
}
