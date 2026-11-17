// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ManagementReviewFixTest {
    static void promoted(UnknownOnlineTest.Pair p)throws Exception{
        AdministrationButtonsTest.prepare(p);
        p.a.controller.confirmManagement(AdministrationButtonsTest.select(p,LanController.ManagementAction.OFFER));p.a.drain();
        LanProofRenewalTest.until(()->UnknownOnlineTest.group(p.m).isAdministrator(),p.a,p.m);
    }
    static AdminRecords.Record renewed(LanGroup group,byte[] signer){
        return AdminRecords.certificate(group.groupId,group.certificate.field(0),group.certificate.field(1),
                SignaturePurpose.identityProof(group.identitySecret,group.groupId,group.certificate.field(1)),
                group.certificate.issuedAt()+1,signer);
    }
    private void removalChange(int kind)throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            promoted(p);Object token=AdministrationButtonsTest.select(p,LanController.ManagementAction.REMOVE);
            var group=UnknownOnlineTest.group(p.a);long sequence=group.saveSeq;
            byte[] list=group.state.administrators().encode();
            if(kind==0)group.certificate=renewed(group,group.administratorSecret);
            if(kind==1)group.keyVersion++;
            if(kind==2){
                var member=UnknownOnlineTest.group(p.m);
                var directory=new MemberDirectory(group.state);directory.restoreSnapshot(group.management.roster);
                directory.saved(renewed(member,group.administratorSecret));
                p.a.disk.saveDirectory(group,directory,group.management.aliases);sequence=group.saveSeq;
            }
            p.a.controller.confirmManagement(token);p.a.drain();
            assertEquals(sequence,group.saveSeq);assertArrayEquals(list,group.state.administrators().encode());
            assertNull(LanControllerHarness.field(p.a.controller,"preparation"));assertNotNull(p.a.endpoint());
            assertTrue(p.a.ui.last.text.contains("取り消しました"));
        }
    }
    @Test public void individualRemovalRejectsChangedLocalCertificate()throws Exception{removalChange(0);}
    @Test public void individualRemovalRejectsChangedKeyVersion()throws Exception{removalChange(1);}
    @Test public void individualRemovalRejectsChangedTargetCertificate()throws Exception{removalChange(2);}
    static void fault(LanControllerHarness h)throws Exception{
        var dht=(LanDht)LanControllerHarness.field(h.controller,"dht");
        var method=LanDht.class.getDeclaredMethod("fault");method.setAccessible(true);method.invoke(dht);assertFalse(dht.active());
    }
    static void unchanged(LanControllerHarness h,LanGroup group,long sequence,byte[] list)throws Exception{
        assertNotNull(h.endpoint());assertSame(group,UnknownOnlineTest.group(h));assertEquals(sequence,group.saveSeq);
        assertArrayEquals(list,group.state.administrators().encode());assertFalse((boolean)LanControllerHarness.field(h.controller,"committedNotApplied"));
    }
    @Test public void stoppedHolderAtRotationConfirmationKeepsCommunication()throws Exception{
        try(var h=new LanControllerHarness(ManualRotationScreenTest.disk())){
            Object token=ManualRotationScreenTest.ask(h);var group=UnknownOnlineTest.group(h);long seq=group.saveSeq;
            byte[] list=group.state.administrators().encode();long version=group.keyVersion;
            fault(h);h.controller.confirmManagement(token);h.drain();unchanged(h,group,seq,list);assertEquals(version,group.keyVersion);
        }
    }
    @Test public void stoppedHolderAtRevocationConfirmationKeepsCommunication()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            AdministrationButtonsTest.prepare(p);Object token=AdministrationButtonsTest.select(p,LanController.ManagementAction.REVOKE);
            var group=UnknownOnlineTest.group(p.a);long seq=group.saveSeq;byte[] list=group.state.administrators().encode(),revocations=group.state.revocations().encode();
            fault(p.a);p.a.controller.confirmManagement(token);p.a.drain();unchanged(p.a,group,seq,list);assertArrayEquals(revocations,group.state.revocations().encode());
        }
    }
    @Test public void stoppedHolderRejectsRotationBeforeConfirmation()throws Exception{
        try(var h=new LanControllerHarness(ManualRotationScreenTest.disk())){
            fault(h);h.controller.rotateKey(h.controller.ticket());h.drain();assertNull(h.ui.confirmation);assertNotNull(h.endpoint());
        }
    }
    @Test public void stoppedHolderRejectsSelectionBeforeConfirmation()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            AdministrationButtonsTest.prepare(p);p.a.ui.choices=null;fault(p.a);
            p.a.controller.chooseManagement(p.a.controller.ticket(),LanController.ManagementAction.REVOKE);p.a.drain();
            assertNull(p.a.ui.choices);assertNotNull(p.a.endpoint());
        }
    }
    @Test public void secondConnectedAdministratorCancelsRequest()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            AdministrationButtonsTest.prepare(p);var a=UnknownOnlineTest.group(p.a);var m=UnknownOnlineTest.group(p.m);
            var random=new java.security.SecureRandom();byte[] identity=LanGroup.random(random),handshake=LanGroup.random(random),secret=LanGroup.random(random);
            try{
                var proof=AdminControl.keyProof(a.groupId,new byte[16],a.state.administrators().version(),identity,secret);
                var bindings=new ArrayList<>(a.state.administrators().bindings());bindings.add(AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode()));
                var list=AdminRecords.administrators(a.groupId,a.state.administrators().version()+1,p.wall.millis(),bindings,a.administratorSecret);
                a.state.acceptAdministrators(list,v->{throw new AssertionError();});m.state.acceptAdministrators(list,v->{throw new AssertionError();});
                p.a.disk.save(a);p.m.disk.save(m);
                p.m.controller.requestAdministration(p.m.controller.ticket());p.m.drain();Object token=p.m.ui.confirmation;assertNotNull(token);
                try(var other=p.a.disk.load(p.wall)){
                    Crypto.wipe(other.identitySecret);Crypto.wipe(other.handshakeSecret);Crypto.wipe(other.administratorSecret);
                    other.identitySecret=identity.clone();other.handshakeSecret=handshake.clone();other.administratorSecret=secret.clone();
                    other.certificate=AdminRecords.certificate(a.groupId,Crypto.ed25519Public(identity),Crypto.x25519Public(handshake),
                            SignaturePurpose.identityProof(identity,a.groupId,Crypto.x25519Public(handshake)),p.wall.millis(),a.administratorSecret);
                    try(var sessions=other.sessions(p.wall,System::nanoTime)){
                        var member=(SessionManager)LanControllerHarness.field(p.m.controller,"managedSessions");
                        p.m.endpoint().rememberPeer(other.certificate);p.m.endpoint().setPeerAddress(other.id(),new java.net.InetSocketAddress(p.a.link.address,LanControllerHarness.freePort()));
                        sessions.rememberPeer(m.certificate);
                        var second=member.receive(sessions.start(m.id()).packet());var first=sessions.receive(second.outbound().get(0).packet());
                        member.receive(first.outbound().get(0).packet());
                        long connected=p.m.endpoint().knownPeers().stream().filter(peer->member.verifiedSession(Crypto.blake2s(peer.certificate().field(0)))!=null).count();
                        assertEquals(2,connected);assertNotNull(member.verifiedSession(other.id()));
                        p.m.controller.confirmManagement(token);p.m.drain();
                        assertNull(LanControllerHarness.field(p.m.controller,"outboundAdministration"));assertNotNull(p.m.endpoint());
                        assertTrue(p.m.ui.last.text.contains("取り消しました"));
                    }
                }
            }finally{Crypto.wipe(identity);Crypto.wipe(handshake);Crypto.wipe(secret);}
        }
    }
    @Test public void individualRemovalAcceptsItsOwnLocalRenewal()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            promoted(p);var group=UnknownOnlineTest.group(p.a);var member=UnknownOnlineTest.group(p.m);
            var changed=renewed(group,member.administratorSecret);p.a.disk.saveLocalRenewal(group,changed);p.a.endpoint().updateLocalCertificate(changed);
            p.wall.now.addAndGet(2);Object token=AdministrationButtonsTest.select(p,LanController.ManagementAction.REMOVE);
            p.a.controller.confirmManagement(token);p.a.drain();
            LanProofRenewalTest.until(()->group.state.administrators().entries().size()==1,p.a,p.m);
            assertTrue(Crypto.equal(group.certificate.signer(),Crypto.ed25519Public(group.administratorSecret)));
            assertNotNull(p.a.endpoint());
        }
    }
    @Test public void parallelLocalRenewalDuringPreparationCancelsDeletion()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            promoted(p);var group=UnknownOnlineTest.group(p.a);var member=UnknownOnlineTest.group(p.m);
            var changed=renewed(group,member.administratorSecret);p.a.disk.saveLocalRenewal(group,changed);p.a.endpoint().updateLocalCertificate(changed);
            p.wall.now.addAndGet(3);Object token=AdministrationButtonsTest.select(p,LanController.ManagementAction.REMOVE);
            p.a.disk.afterLocalRenewal=()->group.certificate=renewed(group,group.administratorSecret);
            p.a.controller.confirmManagement(token);p.a.drain();
            assertEquals(2,group.state.administrators().entries().size());assertNull(LanControllerHarness.field(p.a.controller,"preparation"));
            assertNotNull(p.a.endpoint());assertTrue(p.a.ui.last.text.contains("取り消しました"));
            try(var restored=p.a.disk.load(p.wall)){assertEquals(2,restored.state.administrators().entries().size());}
        }
    }
    @Test public void individualRemovalAcceptsItsOwnTargetRenewal()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            promoted(p);var group=UnknownOnlineTest.group(p.a);var member=UnknownOnlineTest.group(p.m);
            var changed=renewed(member,member.administratorSecret);p.m.disk.saveLocalRenewal(member,changed);p.m.endpoint().updateLocalCertificate(changed);
            p.a.endpoint().rememberPeer(changed);
            var directory=new MemberDirectory(group.state);directory.restoreSnapshot(group.management.roster);directory.saved(changed);
            p.a.disk.saveDirectory(group,directory,group.management.aliases);
            p.wall.now.addAndGet(3);Object token=AdministrationButtonsTest.select(p,LanController.ManagementAction.REMOVE);
            p.a.controller.confirmManagement(token);p.a.drain();
            LanProofRenewalTest.until(()->group.state.administrators().entries().size()==1,p.a,p.m);
            assertTrue(Crypto.equal(UnknownOnlineTest.group(p.m).certificate.signer(),Crypto.ed25519Public(group.administratorSecret)));
            assertNotNull(p.a.endpoint());
        }
    }
}
