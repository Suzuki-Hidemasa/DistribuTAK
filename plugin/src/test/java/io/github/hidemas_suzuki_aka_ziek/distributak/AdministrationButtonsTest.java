// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;

public class AdministrationButtonsTest {
    static void prepare(UnknownOnlineTest.Pair p)throws Exception{
        p.a.controller.confirmUnknown(p.ask());p.a.drain();
        LanProofRenewalTest.until(()->UnknownOnlineTest.group(p.a).state.administrators().bindings().size()==1,p.a,p.m);
        LanProofRenewalTest.until(()->UnknownOnlineTest.group(p.m).certificate.format()==2,p.a,p.m);
        LanProofRenewalTest.until(()->UnknownOnlineTest.group(p.m).state.administrators().version()==UnknownOnlineTest.group(p.a).state.administrators().version(),p.a,p.m);
        p.a.controller.confirmManagement(NamingScreenTest.reconnect(p));p.a.drain();
        p.a.controller.setLabel(p.a.ui.input,NamingScreenTest.label());p.a.drain();
        p.a.controller.confirmManagement(p.a.ui.confirmation);p.a.drain();
    }
    static Object select(UnknownOnlineTest.Pair p,LanController.ManagementAction action)throws Exception{
        p.a.ui.confirmation=null;p.a.ui.choices=null;
        p.a.controller.chooseManagement(p.a.controller.ticket(),action);p.a.drain();assertNotNull(p.a.ui.choices);
        assertEquals(1,p.a.ui.choices.size());
        p.a.controller.selectManagement(p.a.ui.choiceToken,p.a.ui.choices.get(0).token);p.a.drain();
        assertNotNull(p.a.ui.confirmation);return p.a.ui.confirmation;
    }
    @Test public void requestWaitsForConfirmationAndApprovalPersistsBothSides()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            prepare(p);p.m.controller.requestAdministration(p.m.controller.ticket());p.m.drain();assertNotNull(p.m.ui.confirmation);
            assertFalse(UnknownOnlineTest.group(p.m).isAdministrator());
            p.m.controller.confirmManagement(p.m.ui.confirmation);p.m.drain();
            assertTrue("依頼を送る段階を完了していません",p.m.ui.last.text.contains("リクエストしました"));
            LanProofRenewalTest.until(()->!((Map<?,?>)LanControllerHarness.field(p.a.controller,"administrationRequests")).isEmpty(),p.a,p.m);
            p.a.controller.confirmManagement(select(p,LanController.ManagementAction.APPROVE));p.a.drain();
            LanProofRenewalTest.until(()->UnknownOnlineTest.group(p.m).isAdministrator(),p.a,p.m);
            try(var restored=p.m.disk.load(p.wall)){assertTrue(restored.isAdministrator());assertEquals(2,restored.state.administrators().bindings().size());}
            assertFalse(p.a.ui.last.text.contains(p.a.ui.choices.get(0).label));
        }
    }
    @Test public void offerWaitsForProofAndPersistsGrant()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            prepare(p);Object token=select(p,LanController.ManagementAction.OFFER);
            assertEquals(1,UnknownOnlineTest.group(p.a).state.administrators().bindings().size());
            p.a.controller.confirmManagement(token);p.a.drain();
            LanProofRenewalTest.until(()->UnknownOnlineTest.group(p.m).isAdministrator(),p.a,p.m);
        }
    }
    @Test public void revocationIncludesRotationAndRemovesLabelAtomically()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            prepare(p);var group=UnknownOnlineTest.group(p.a);long version=group.keyVersion;byte[] target=UnknownOnlineTest.group(p.m).id();
            Object token=select(p,LanController.ManagementAction.REVOKE);
            ManualRotationScreenTest.assertRotationNotice(p.a.ui.managementTexts.get(p.a.ui.managementTexts.size()-1));
            assertFalse(group.state.revocations().hasEntry(target));p.a.controller.confirmManagement(token);p.a.drain();
            assertTrue(group.state.revocations().hasEntry(target));assertTrue(group.keyVersion>version);
            assertTrue(group.management.aliases.isEmpty());
            try(var restored=p.a.disk.load(p.wall)){assertTrue(restored.state.revocations().hasEntry(target));assertTrue(restored.management.aliases.isEmpty());}
        }
    }
    @Test public void boundRemovalDeletesLabelInSameSavedCandidate()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            prepare(p);p.a.controller.confirmManagement(select(p,LanController.ManagementAction.OFFER));p.a.drain();
            LanProofRenewalTest.until(()->UnknownOnlineTest.group(p.m).isAdministrator(),p.a,p.m);
            Object token=select(p,LanController.ManagementAction.REMOVE);var group=UnknownOnlineTest.group(p.a);
            assertEquals(2,group.state.administrators().entries().size());assertFalse(group.management.aliases.isEmpty());
            p.a.controller.confirmManagement(token);p.a.drain();
            LanProofRenewalTest.until(()->group.state.administrators().entries().size()==1,p.a,p.m);
            try(var saved=p.a.disk.load(p.wall)){assertEquals(1,saved.state.administrators().entries().size());assertTrue(saved.management.aliases.isEmpty());}
        }
    }
    @Test public void revokedPeerDoesNotReceiveNewEnvelope()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            prepare(p);byte[] target=UnknownOnlineTest.group(p.m).id();
            p.a.controller.confirmManagement(select(p,LanController.ManagementAction.REVOKE));p.a.drain();
            for(byte[] bytes:UnknownOnlineTest.group(p.a).management.outgoing)
                assertFalse(Crypto.equal(target,AdminRecords.decode(bytes).field(0)));
            assertFalse(p.a.endpoint().isEstablished(target));
        }
    }
    @Test public void selectionCancelledByAuthorityBasisChange()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            prepare(p);Object token=select(p,LanController.ManagementAction.OFFER);
            ((java.util.concurrent.atomic.AtomicLong)LanControllerHarness.field(p.a.controller,"generation")).incrementAndGet();
            p.a.controller.confirmManagement(token);p.a.drain();
            assertEquals(1,UnknownOnlineTest.group(p.a).state.administrators().entries().size());
        }
    }
    @Test public void cancelRequestDoesNotGeneratePendingProof()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            prepare(p);p.m.controller.requestAdministration(p.m.controller.ticket());p.m.drain();Object token=p.m.ui.confirmation;assertNotNull(token);
            p.m.controller.cancelManagement();p.m.drain();p.m.controller.confirmManagement(token);p.m.drain();
            assertNull(LanControllerHarness.field(p.m.controller,"outboundAdministration"));
        }
    }
    @Test public void failureAfterGrantSaveStopsWithoutCompensation()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            prepare(p);p.m.disk.afterMembership=()->{throw new IllegalStateException("保存後に中断しました");};
            p.a.controller.confirmManagement(select(p,LanController.ManagementAction.OFFER));p.a.drain();
            LanProofRenewalTest.until(()->p.m.endpoint()==null,p.a,p.m);
            assertTrue((boolean)LanControllerHarness.field(p.m.controller,"committedNotApplied"));
            try(var saved=p.m.disk.load(p.wall)){assertTrue(saved.isAdministrator());}
        }
    }
    @Test public void failureBeforeGrantSaveKeepsCommunicationAndStoredMembership()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            prepare(p);p.m.controller.requestAdministration(p.m.controller.ticket());p.m.drain();
            p.m.controller.confirmManagement(p.m.ui.confirmation);p.m.drain();
            LanProofRenewalTest.until(()->!((Map<?,?>)LanControllerHarness.field(p.a.controller,"administrationRequests")).isEmpty(),p.a,p.m);
            var a=UnknownOnlineTest.group(p.a);var member=UnknownOnlineTest.group(p.m);
            var service=(GroupAdministration)LanControllerHarness.field(p.a.controller,"incomingAdministration");
            var sessions=(SessionManager)LanControllerHarness.field(p.a.controller,"managedSessions");var candidate=service.approve(sessions,member.id());
            var basis=a.state.administrators();
            var record=io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecord.issue(
                    io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtKeys.LATEST_ADMINS,a.groupId,a.administratorSecret,
                    candidate.administrators(),0,basis.version(),Crypto.blake2s(basis.signedBytes()),p.wall.millis(),null);
            var dht=(LanDht)LanControllerHarness.field(p.m.controller,"dht");var cfg=(LanDht.Config)LanControllerHarness.field(dht,"cfg");
            long sequence=member.saveSeq;byte[] saved=p.m.disk.state.value.clone(),list=member.state.administrators().encode();
            int attempts=p.m.disk.membershipAttempts;
            p.m.disk.failSave=true;
            assertEquals(io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtWire.StoreStatus.INVALID,cfg.management.store().accept(null,record,false));
            assertEquals(attempts+1,p.m.disk.membershipAttempts);
            assertNotNull(p.m.endpoint());assertTrue(dht.active());assertFalse((boolean)LanControllerHarness.field(p.m.controller,"committedNotApplied"));
            assertEquals(sequence,member.saveSeq);assertArrayEquals(saved,p.m.disk.state.value);assertArrayEquals(list,member.state.administrators().encode());
            assertNull(LanControllerHarness.field(p.m.controller,"outboundAdministration"));assertFalse(member.isAdministrator());
            try(var restored=p.m.disk.load(p.wall)){assertFalse(restored.isAdministrator());assertArrayEquals(list,restored.state.administrators().encode());}
        }
    }
}
