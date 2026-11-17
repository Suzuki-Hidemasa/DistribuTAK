// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class InitialManagementTest {
    private static LanGroup group(LanControllerHarness h)throws Exception {
        return (LanGroup)LanControllerHarness.field(h.controller,"group");
    }
    private static void join(LanControllerHarness admin,LanControllerHarness member)throws Exception {
        admin.disk.enableSix();member.disk.enableSix();admin.create();member.beginJoin(admin);
        LanControllerHarness.until(()->member.ui.last.member&&!member.ui.last.busy
                &&admin.logs.contains("LAN_MEMBER_ISSUED"),admin,member);
    }
    private static void connect(LanControllerHarness admin,LanControllerHarness member)throws Exception {
        admin.controller.connect();admin.drain();
        LanControllerHarness.until(()->member.endpoint().isEstablished(group(admin).id())
                &&admin.endpoint().isEstablished(group(member).id()),admin,member);
    }
    @Test public void initialJoinCreatesSharedComponentsWithoutStartingFirstOrDuplicatingSync()throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()){
            join(admin,member);
            for(String field:List.of("persistence","managementClock","recovery","roster","managedSessions"))
                assertNotNull(field,LanControllerHarness.field(member.controller,field));
            assertEquals(2,member.link.opens);assertEquals(1,member.disk.spillOpens);
            var endpoint=member.endpoint();var sync=LanControllerHarness.field(member.controller,"sync");
            for(int i=0;i<4;i++)member.tick();
            assertSame(endpoint,member.endpoint());assertSame(sync,LanControllerHarness.field(member.controller,"sync"));
            assertFalse(member.endpoint().isEstablished(group(admin).id()));
            assertFalse(((SessionManager)LanControllerHarness.field(member.controller,"managedSessions")).isHandshaking(group(admin).id()));
        }
    }
    @Test public void initialJoinReceivesRevocationPagesAndPersistsBeforeCompletion()throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()){
            join(admin,member);assertNotNull(LanControllerHarness.field(member.controller,"recovery"));connect(admin,member);
            var a=group(admin);var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,a.groupId,1,
                    LanControllerHarness.CLOCK.millis(),List.of(Crypto.blake2s(new byte[]{1})),a.administratorSecret);
            for(var page:ManagementPage.split(ManagementPage.Kind.REVOCATION,new byte[16],a.groupId,body.encode(),1))
                assertTrue(admin.endpoint().sendIfSession(group(member).id(),admin.endpoint().sessionId(group(member).id()),page.envelope()));
            LanControllerHarness.until(()->group(member).state.revocations().version()==1,admin,member);
            try(var loaded=member.disk.load(LanControllerHarness.CLOCK)){
                assertArrayEquals(body.encode(),loaded.state.revocations().encode());assertFalse(loaded.storageBlocked);
            }
        }
    }
    @Test public void initialJoinManagementDhtDeliveryPersistsAndFirstUpdatesRoster()throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()){
            join(admin,member);
            var initial=(LanDht)LanControllerHarness.field(member.controller,"dht");
            assertNotNull(((LanDht.Config)LanControllerHarness.field(initial,"cfg")).management);connect(admin,member);
            LanControllerHarness.until(()->group(admin).management.roster.size()>=2,admin,member);
            var a=group(admin);var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,a.groupId,1,
                    LanControllerHarness.CLOCK.millis(),List.of(Crypto.blake2s(new byte[]{2})),a.administratorSecret);
            var admins=a.state.administrators();
            var record=ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,a.groupId,a.administratorSecret,body,1,
                    admins.version(),Crypto.blake2s(admins.signedBytes()),LanControllerHarness.CLOCK.millis(),null);
            var statuses=new ArrayList<DhtWire.StoreStatus>();
            var dht=(LanDht)LanControllerHarness.field(admin.controller,"dht");
            assertTrue(dht.publishManaged(new Contact(new DhtId(group(member).id())),record.encode(),statuses::add));
            LanControllerHarness.until(()->!statuses.isEmpty(),admin,member);
            assertEquals(List.of(DhtWire.StoreStatus.ACCEPTED),statuses);
            try(var loaded=member.disk.load(LanControllerHarness.CLOCK)){
                assertArrayEquals(body.encode(),loaded.state.revocations().encode());
            }
            try(var loaded=admin.disk.load(LanControllerHarness.CLOCK)){assertTrue(loaded.management.roster.size()>=2);}
        }
    }
}
