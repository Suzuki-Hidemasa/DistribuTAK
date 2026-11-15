// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;
public class InvitationPrepareTest {
    @Test public void newGroupStartsWithSelfBoundAdministrator()throws Exception {
        try(var h=new LanControllerHarness()) {h.create();var g=LanBehaviourWiringTest.group(h);
            var binding=g.state.administrators().binding(g.urlAdmin);assertEquals(AdminBinding.State.BOUND,binding.state());assertTrue(Crypto.equal(g.id(),binding.memberId()));}
    }
    @Test public void invitationMigratesLegacySelfAfterClockAdvancesWithoutErasingGroup()throws Exception {
        var disks=LanProofRenewalTest.legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.incrementAndGet();
        try(var h=new LanControllerHarness(disks[0],CotPort.NONE,wall)) {
            var before=LanBehaviourWiringTest.group(h);byte[] identity=before.id(),group=before.groupId.clone();
            h.controller.showRejoinInvitation(h.controller.ticket(),64);h.drain();
            var current=LanBehaviourWiringTest.group(h);assertEquals(2,current.certificate.format());assertTrue(Crypto.equal(identity,current.id()));assertTrue(Crypto.equal(group,current.groupId));
            assertFalse(h.disk.erased);assertTrue(h.logs.contains("LAN_INVITATION_SHOWN"));
        }
    }
    @Test public void withoutInvitationLegacyCertificateAndStoredGroupRemainUnchanged()throws Exception {
        var disks=LanProofRenewalTest.legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.incrementAndGet();
        try(var h=new LanControllerHarness(disks[0],CotPort.NONE,wall)) {
            var g=LanBehaviourWiringTest.group(h);byte[] before=g.certificate.encode();long sequence=g.saveSeq;
            for(int i=0;i<10;i++)h.tick();h.drain();assertEquals(1,g.certificate.format());assertEquals(sequence,g.saveSeq);
            assertTrue(java.util.Arrays.equals(before,g.certificate.encode()));
        }
    }
    @Test public void sameMillisecondInvitationWaitsWithoutChangingStoredLegacyCertificate()throws Exception {
        var disks=LanProofRenewalTest.legacyPair();
        try(var h=new LanControllerHarness(disks[0],CotPort.NONE,LanControllerHarness.CLOCK)) {
            var g=LanBehaviourWiringTest.group(h);long sequence=g.saveSeq;h.controller.showRejoinInvitation(h.controller.ticket(),64);h.drain();
            assertEquals(1,g.certificate.format());assertEquals(sequence,g.saveSeq);assertFalse(h.logs.contains("LAN_INVITATION_SHOWN"));
        }
    }
    @Test public void legacyAdministratorJoinsAndConnectsAfterOneMillisecondAdvances()throws Exception {
        var disks=LanProofRenewalTest.legacyPair();
        try(var saved=disks[0].load(LanControllerHarness.CLOCK)){saved.peerCertificate=null;saved.peerAddress=null;disks[0].save(saved);}
        var wall=new LanAutomaticRenewalTest.Wall();wall.now.incrementAndGet();
        try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall);var member=new LanControllerHarness(null,CotPort.NONE,wall)) {
            member.beginJoin(admin);LanProofRenewalTest.until(()->member.ui.last.member,admin,member);
            assertEquals(2,LanBehaviourWiringTest.group(admin).certificate.format());assertEquals(2,LanBehaviourWiringTest.group(member).certificate.format());
            admin.controller.connect();admin.drain();LanProofRenewalTest.until(()->member.endpoint().isEstablished(LanBehaviourWiringTest.group(admin).id()),admin,member);
        }
    }
}
