// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class RemovedAdministratorSecretsTest {
    @Test public void retainedAdministratorKeepsItsSecret()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=receiver(p)){
            var list=new ManagedDhtExchangeTest().nextAdmins(p,true);var basis=p.a.state.administrators();
            byte[] secret=p.b.administratorSecret.clone();
            var record=ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,p.a.groupId,p.a.administratorSecret,list,0,
                    basis.version(),Crypto.blake2s(basis.signedBytes()),p.wall.millis(),null);
            assertEquals(DhtWire.StoreStatus.ACCEPTED,x.store().accept(null,record,false));
            assertTrue(p.b.isAdministrator());assertTrue(Arrays.equals(secret,p.b.administratorSecret));Crypto.wipe(secret);
        }
    }
    private void controllerCopies(boolean stop)throws Exception{
        try(var p=new RosterExchangeTest.Pair();var h=new LanControllerHarness(p.db,CotPort.NONE,p.wall)){
            var group=UnknownOnlineTest.group(h);byte[] owned=group.administratorSecret;
            var incoming=LanController.class.getDeclaredMethod("incoming");incoming.setAccessible(true);
            Object owner=incoming.invoke(h.controller);
            byte[] copy=(byte[])LanControllerHarness.field(owner,"administratorSecret");
            var dht=(LanDht)LanControllerHarness.field(h.controller,"dht");
            var cfg=(LanDht.Config)LanControllerHarness.field(dht,"cfg");
            var other=LanControllerHarness.field(cfg.management,"administration");
            byte[] otherCopy=(byte[])LanControllerHarness.field(other,"administratorSecret");
            if(stop){
                var sessions=(SessionManager)LanControllerHarness.field(h.controller,"managedSessions");
                h.disk.afterCandidateSave=snapshot->sessions.close();
            }
            assertEquals(stop?DhtWire.StoreStatus.INVALID:DhtWire.StoreStatus.ACCEPTED,
                    cfg.management.store().accept(null,removal(p),false));
            wiped(owned);wiped(copy);wiped(otherCopy);
            assertNull(LanControllerHarness.field(h.controller,"incomingAdministration"));
            if(stop){
                var coordinator=(CorePersistenceCoordinator)LanControllerHarness.field(h.controller,"persistence");
                assertEquals(CorePersistenceCoordinator.StopReason.COMMITTED_NOT_APPLIED,coordinator.stopReason());
            }else{dht.step();assertTrue(dht.active());assertNotNull(h.endpoint());}
        }
    }
    @Test public void controllerClosesAllAdministratorOwnersOnRemoval()throws Exception{controllerCopies(false);}
    @Test public void controllerClosesAllAdministratorOwnersBeforeCommittedStop()throws Exception{controllerCopies(true);}
    static ManagedDhtExchange receiver(RosterExchangeTest.Pair p){
        return new ManagedDhtExchange(p.b,p.sb,p.cb,p.ub,p.wall,p.deadlines,()->p.now*1_000_000,
                new java.security.SecureRandom(),p.db);
    }
    static ManagedDhtRecord removal(RosterExchangeTest.Pair p){
        var list=new ManagedDhtExchangeTest().nextAdmins(p,false);var basis=p.a.state.administrators();
        return ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,p.a.groupId,p.a.administratorSecret,list,0,
                basis.version(),Crypto.blake2s(basis.signedBytes()),p.wall.millis(),null);
    }
    static void labels(RosterExchangeTest.Pair p)throws Exception{
        var directory=new MemberDirectory(p.b.state);directory.saved(p.a.certificate);directory.saved(p.b.certificate);
        p.db.saveDirectory(p.b,directory,Map.of(Base64.getEncoder().encodeToString(p.a.certificate.field(0)),NamingScreenTest.label()));
    }
    static void wiped(byte[] value){assertNotNull(value);for(byte part:value)assertTrue(part==0);}
    @Test public void receivedRemovalClearsStoredAndOwnedSecretsTogether()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=receiver(p)){
            labels(p);byte[] owned=p.b.administratorSecret;
            var administration=LanControllerHarness.field(x,"administration");
            byte[] copy=(byte[])LanControllerHarness.field(administration,"administratorSecret");
            byte[] rotation=(byte[])LanControllerHarness.field(x.rotation(),"secret");
            long before=p.b.saveSeq;
            assertEquals(DhtWire.StoreStatus.ACCEPTED,x.store().accept(null,removal(p),false));
            assertEquals(before+1,p.b.saveSeq);assertFalse(p.b.isAdministrator());assertTrue(p.b.management.aliases.isEmpty());
            wiped(owned);wiped(copy);wiped(rotation);assertTrue(x.allowed());
            try(var loaded=p.db.load(p.wall)){
                assertFalse(loaded.isAdministrator());assertEquals(0,loaded.administratorSecret.length);
                assertEquals(1,loaded.state.administrators().entries().size());assertTrue(loaded.management.aliases.isEmpty());
            }
        }
    }
    private void failedSave(boolean management)throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=receiver(p)){
            labels(p);byte[] old=p.db.state.value.clone(),secret=p.b.administratorSecret.clone();long before=p.b.saveSeq;
            int generations=p.db.managementFiles.values.size();
            if(management)p.db.managementFiles.fail=true;else p.db.failSave=true;
            assertEquals(DhtWire.StoreStatus.INVALID,x.store().accept(null,removal(p),false));
            assertEquals(before,p.b.saveSeq);assertTrue(p.b.isAdministrator());assertTrue(Arrays.equals(secret,p.b.administratorSecret));
            assertTrue(Arrays.equals(old,p.db.state.value));assertFalse(p.b.management.aliases.isEmpty());assertTrue(x.allowed());
            if(!management)assertTrue(p.db.managementFiles.values.size()>generations);
            p.db.managementFiles.fail=false;p.db.failSave=false;
            try(var loaded=p.db.load(p.wall)){assertTrue(loaded.isAdministrator());assertFalse(loaded.management.aliases.isEmpty());}
            Crypto.wipe(secret);
        }
    }
    @Test public void managementWriteFailureKeepsOldMembershipTogether()throws Exception{failedSave(true);}
    @Test public void stateSwitchFailureKeepsOldMembershipTogether()throws Exception{failedSave(false);}
    @Test public void committedRemovalWipesMemoryEvenWhenPublicationStops()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=receiver(p)){
            labels(p);byte[] owned=p.b.administratorSecret;
            byte[] copy=(byte[])LanControllerHarness.field(LanControllerHarness.field(x,"administration"),"administratorSecret");
            byte[] rotation=(byte[])LanControllerHarness.field(x.rotation(),"secret");
            p.db.afterCandidateSave=snapshot->p.sb.close();
            assertEquals(DhtWire.StoreStatus.INVALID,x.store().accept(null,removal(p),false));
            assertEquals(1,p.db.candidateSaves);
            assertEquals(CorePersistenceCoordinator.StopReason.COMMITTED_NOT_APPLIED,p.cb.stopReason());
            wiped(owned);wiped(copy);wiped(rotation);assertFalse(p.b.isAdministrator());
            try(var loaded=p.db.load(p.wall)){assertFalse(loaded.isAdministrator());assertTrue(loaded.management.aliases.isEmpty());}
        }
    }
}
