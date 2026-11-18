// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class GrantRetryInvestigationTest {
    private void retry(boolean failure)throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            AdministrationButtonsTest.prepare(p);p.m.controller.requestAdministration(p.m.controller.ticket());p.m.drain();
            p.m.controller.confirmManagement(p.m.ui.confirmation);p.m.drain();
            LanProofRenewalTest.until(()->!((Map<?,?>)LanControllerHarness.field(p.a.controller,"administrationRequests")).isEmpty(),p.a,p.m);
            var a=UnknownOnlineTest.group(p.a);var member=UnknownOnlineTest.group(p.m);var basis=a.state.administrators();
            var service=(GroupAdministration)LanControllerHarness.field(p.a.controller,"incomingAdministration");
            var sessions=(SessionManager)LanControllerHarness.field(p.a.controller,"managedSessions");
            var candidate=service.approve(sessions,member.id());
            var bridge=AdminRecords.administrators(a.groupId,basis.version()+1,p.wall.millis(),basis.bindings(),a.administratorSecret);
            assertTrue(a.state.acceptAdministrators(bridge,v->fail()));p.a.disk.save(a);
            var grant=AdminRecords.administrators(a.groupId,bridge.version()+1,p.wall.millis(),candidate.administrators().bindings(),a.administratorSecret);
            var future=ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,a.groupId,a.administratorSecret,grant,0,
                    bridge.version(),Crypto.blake2s(bridge.signedBytes()),p.wall.millis(),null);
            var missing=ManagedDhtRecord.issue(DhtKeys.ADMIN_HISTORY,a.groupId,a.administratorSecret,bridge,0,
                    basis.version(),Crypto.blake2s(basis.signedBytes()),p.wall.millis(),null);
            var dht=(LanDht)LanControllerHarness.field(p.m.controller,"dht");var cfg=(LanDht.Config)LanControllerHarness.field(dht,"cfg");var store=cfg.management.store();
            assertEquals(DhtWire.StoreStatus.INVALID,store.accept(null,future,false));assertEquals(1,store.pendingCount());
            assertEquals(0,p.m.disk.membershipAttempts);assertEquals(DhtWire.StoreStatus.ACCEPTED,store.accept(null,missing,false));
            assertEquals(bridge.version(),member.state.administrators().version());
            var verifier=new ManagedVerifier(new AdminStateTrust(member.state),p.wall);
            assertEquals(ManagedVerdict.Status.ACCEPTED,verifier.judge(future,null).status());
            long before=member.saveSeq;byte[] old=p.m.disk.state.value.clone();p.m.disk.failSave=failure;
            dht.step();
            assertEquals(0,p.m.disk.membershipAttempts);
            assertFalse(dht.active());assertNotNull(p.m.endpoint());assertFalse(member.isAdministrator());
            assertEquals(before,member.saveSeq);assertTrue(Arrays.equals(old,p.m.disk.state.value));
            assertFalse((boolean)LanControllerHarness.field(p.m.controller,"committedNotApplied"));
            assertNull(LanControllerHarness.field(p.m.controller,"outboundAdministration"));
        }
    }
    @Test public void pendingGrantStopsBeforeStorageEvenWhenStorageFails()throws Exception{retry(true);}
    @Test public void pendingProofExpiresBeforeStorageEvenWhenStorageIsAvailable()throws Exception{retry(false);}
    @Test public void offerWaitHasNoIndependentPluginDeadline()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            AdministrationButtonsTest.prepare(p);
            Object token=AdministrationButtonsTest.select(p,LanController.ManagementAction.OFFER);
            p.a.controller.confirmManagement(token);p.a.drain();
            Object waiting=LanControllerHarness.field(p.a.controller,"managementPending");assertNotNull(waiting);
            assertEquals("OFFER_WAIT",LanControllerHarness.field(waiting,"step").toString());
            var service=(GroupAdministration)LanControllerHarness.field(p.a.controller,"incomingAdministration");
            var time=new java.util.concurrent.atomic.AtomicLong();
            var nanos=GroupAdministration.class.getDeclaredField("nanos");nanos.setAccessible(true);nanos.set(service,(java.util.function.LongSupplier)time::get);
            var entries=(Map<?,?>)LanControllerHarness.field(service,"pending");assertEquals(1,entries.size());
            Object pending=entries.values().iterator().next();long began=(long)LanControllerHarness.field(pending,"began");
            var expire=GroupAdministration.class.getDeclaredMethod("expire");expire.setAccessible(true);
            for(long delta:new long[]{GroupAdministration.PENDING_NANOS-1,GroupAdministration.PENDING_NANOS,GroupAdministration.PENDING_NANOS+1}){
                time.set(began+delta);expire.invoke(service);
                p.a.tick();assertSame(waiting,LanControllerHarness.field(p.a.controller,"managementPending"));
                assertTrue((boolean)LanControllerHarness.field(p.a.controller,"managementBusy"));
                assertEquals(delta<GroupAdministration.PENDING_NANOS?1:0,entries.size());
            }
        }
    }
}
