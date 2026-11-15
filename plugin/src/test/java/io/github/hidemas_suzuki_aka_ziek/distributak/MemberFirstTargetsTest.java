// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;
public class MemberFirstTargetsTest {
    @Test public void multipleAdministratorTargetsUseBoundIdentityAndExcludeOrdinaryMembers()throws Exception {
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())) {
            byte[] identity=StoredUpdatesTest.key(70),admin=StoredUpdatesTest.key(72);
            var proof=AdminControl.keyProof(g.groupId,new byte[16],0,identity,admin);var bindings=new ArrayList<>(g.state.administrators().bindings());
            bindings.add(AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode()));
            g.state.acceptAdministrators(AdminRecords.administrators(g.groupId,1,StorageGroupTest.NOW,bindings,g.administratorSecret),v->fail());
            var b=StoredUpdatesTest.peer(g,70,71,StorageGroupTest.NOW);var m=StoredUpdatesTest.peer(g,80,81,StorageGroupTest.NOW);
            var address=new java.net.InetSocketAddress("192.0.2.1",54321);
            var targets=LanController.memberFirstTargets(g,List.of(g.certificate,b,m));
            assertEquals(2,targets.size());assertTrue(targets.stream().anyMatch(x->Crypto.equal(x,g.id())));assertTrue(targets.stream().anyMatch(x->Crypto.equal(x,proof.memberId())));
            assertFalse(targets.stream().anyMatch(x->Crypto.equal(x,Crypto.blake2s(m.field(0)))));assertFalse(Crypto.equal(g.id(),g.urlAdmin));
        }
    }
}
