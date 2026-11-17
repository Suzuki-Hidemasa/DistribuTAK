// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class RemovedAdministratorContinuityTest {
    @Test public void removedAdministratorKeepsCommunicationAfterControllerPoll()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var h=new LanControllerHarness(p.db,CotPort.NONE,p.wall)){
            var dht=(LanDht)LanControllerHarness.field(h.controller,"dht");
            var cfg=(LanDht.Config)LanControllerHarness.field(dht,"cfg");
            assertEquals(DhtWire.StoreStatus.ACCEPTED,cfg.management.store().accept(null,RemovedAdministratorSecretsTest.removal(p),false));
            assertFalse(UnknownOnlineTest.group(h).isAdministrator());assertNotNull(h.endpoint());
            h.tick();
            assertNotNull(h.endpoint());assertTrue(dht.active());
        }
    }
    @Test public void committedRemovalWipesSecretWhenWallClockMovesBackwards()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var removal=RemovedAdministratorSecretsTest.removal(p);
            var six=new VersionSixStorage(p.db.envelope,p.db.managementFiles,p.db.stopMarker.marker());
            var target=new StateEnvelope.AtomicTarget(){
                public void begin()throws Exception{p.db.state.begin();}
                public void write(byte[] wire)throws Exception{p.db.state.write(wire);}
                public void commit()throws Exception{p.db.state.commit();p.wallAdvance=-300001;}
                public void rollback(){p.db.state.rollback();}
            };
            var storage=(LanRuntime.Storage)java.lang.reflect.Proxy.newProxyInstance(
                    LanRuntime.Storage.class.getClassLoader(),new Class<?>[]{LanRuntime.Storage.class},
                    (proxy,method,args)->method.getName().equals("persistenceHooks")
                            ?six.hooks(p.b,target,()->{}):method.invoke(p.db,args));
            try(var x=new ManagedDhtExchange(p.b,p.sb,p.cb,p.ub,p.wall,p.deadlines,
                    ()->p.now*1_000_000,new java.security.SecureRandom(),storage)){
                long before=p.b.saveSeq;byte[] owned=p.b.administratorSecret;
                byte[] copy=(byte[])LanControllerHarness.field(LanControllerHarness.field(x,"administration"),"administratorSecret");
                byte[] rotation=(byte[])LanControllerHarness.field(x.rotation(),"secret");
                assertEquals(DhtWire.StoreStatus.INVALID,x.store().accept(null,removal,false));
                assertFalse(p.b.isAdministrator());assertEquals(before+1,p.b.saveSeq);
                RemovedAdministratorSecretsTest.wiped(owned);RemovedAdministratorSecretsTest.wiped(copy);RemovedAdministratorSecretsTest.wiped(rotation);
                assertEquals(CorePersistenceCoordinator.StopReason.COMMITTED_NOT_APPLIED,p.cb.stopReason());
                assertFalse(x.allowed());p.wallAdvance=0;
                try(var loaded=p.db.load(p.wall)){
                    assertFalse(loaded.isAdministrator());assertEquals(before+1,loaded.saveSeq);
                    assertEquals(removal.inner().version(),loaded.state.administrators().version());
                }
            }
        }
    }
    @Test public void removedAdministratorStillAcceptsAnnouncementPages()throws Exception{receive(false);}
    @Test public void freshMemberExchangeAcceptsSameAnnouncementPage()throws Exception{receive(true);}
    private void receive(boolean fresh)throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=RemovedAdministratorSecretsTest.receiver(p)){
            var removal=RemovedAdministratorSecretsTest.removal(p);
            assertEquals(DhtWire.StoreStatus.ACCEPTED,x.store().accept(null,removal,false));
            assertFalse(p.b.isAdministrator());
            assertTrue(p.ca.receiveAdministrators(removal.inner(),p.da.persistenceHooks(p.a)));
            var announcement=new ManagedDhtExchangeTest().announcement(p,p.a.state.revocations(),2,230).announcement();
            var page=ManagementPage.split(ManagementPage.Kind.ANNOUNCEMENT,new byte[16],p.a.groupId,announcement.encode(),0).get(0);
            assertNotNull(p.sb.verifiedSession(p.a.id()));
            if(fresh){
                try(var active=RemovedAdministratorSecretsTest.receiver(p)){accept(active,p,page);}
            }else accept(x,p,page);
        }
    }
    private void accept(ManagedDhtExchange active,RosterExchangeTest.Pair p,ManagementPage page){
        var ack=active.receiveAnnouncement(p.a.id(),p.sb.sessionId(p.a.id()),page.envelope(),p.now);
        assertNotNull(ack);assertTrue(ack.complete());
    }
}
