// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class NamingCandidatesTest {
    @Test public void rekeyWithoutObservedDisconnectIsNotCandidate(){
        var identity=UUID.randomUUID().toString();byte[] original=LanGroup.random(new java.security.SecureRandom()),changed=LanGroup.random(new java.security.SecureRandom());
        var selector=new NamingCandidates(Map.of(identity,original));
        assertTrue(selector.observe(Map.of(identity,changed)).isEmpty());
    }
    @Test public void reconnectAfterObservedDisconnectIsCandidate(){
        var identity=UUID.randomUUID().toString();byte[] original=LanGroup.random(new java.security.SecureRandom()),changed=LanGroup.random(new java.security.SecureRandom());
        var selector=new NamingCandidates(Map.of(identity,original));assertTrue(selector.observe(Map.of()).isEmpty());
        assertEquals(1,selector.observe(Map.of(identity,changed)).size());
    }
    @Test public void oneNewConnectionIsCandidate(){
        var selector=new NamingCandidates(Map.of());assertEquals(1,selector.observe(Map.of(UUID.randomUUID().toString(),new byte[16])).size());
    }
    @Test public void twoNewConnectionsAreNotReducedToOne(){
        var selector=new NamingCandidates(Map.of());assertEquals(2,selector.observe(Map.of(UUID.randomUUID().toString(),new byte[16],UUID.randomUUID().toString(),new byte[16])).size());
    }
}
