// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;
public class AdministratorRemovalRecoveryTest {
    @Test public void offlineMemberAutomaticallyErasesAfterLearningItsIssuerWasRemoved()throws Exception {
        var disks=LanProofRenewalTest.legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.incrementAndGet();
        AdminRecords.Record removal;
        // Bを残したあとの公開状態を用意する。製品に管理操作の口は配線しない。
        try(var retained=disks[0].load(wall)) {
            byte[] identity=StoredUpdatesTest.key(101),administrator=StoredUpdatesTest.key(102);
            var proof=AdminControl.keyProof(retained.groupId,new byte[16],0,identity,administrator);
            removal=AdminRecords.administrators(retained.groupId,1,wall.millis(),List.of(AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode())),retained.administratorSecret);

        }
        try(var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            assertTrue(member.endpoint().acceptAdministrators(removal,v->fail()));
            LanProofRenewalTest.until(()->member.disk.erased,member);assertFalse(member.ui.last.member);
            assertNull(member.disk.load(wall));
        }
    }
}
