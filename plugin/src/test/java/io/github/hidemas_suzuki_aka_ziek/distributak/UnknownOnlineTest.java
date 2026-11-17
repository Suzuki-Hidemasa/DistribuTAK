// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.Test;
import static org.junit.Assert.*;
public class UnknownOnlineTest {
    @Test public void failureBeforeDurableSaveCancelsWithoutStoppingNetwork()throws Exception {
        try(var p=new Pair()) {
            Object token=p.ask();long version=group(p.a).state.administrators().version();
            p.a.disk.beforeCandidateSave=()->{throw new IllegalStateException("保存前に取り消しました");};
            p.a.controller.confirmUnknown(token);p.a.drain();
            LanProofRenewalTest.until(()->LanControllerHarness.field(p.a.controller,"preparation")==null,p.a,p.m);
            assertFalse((boolean)LanControllerHarness.field(p.a.controller,"committedNotApplied"));
            assertNotNull(p.a.endpoint());assertTrue(p.a.ui.last.ready);assertEquals(0,p.a.disk.candidateSaves);
            try(var saved=p.a.disk.load(p.wall)){assertEquals(version,saved.state.administrators().version());}
        }
    }
    static final class Pair implements AutoCloseable {
        final LanAutomaticRenewalTest.Wall wall=new LanAutomaticRenewalTest.Wall();
        final LanControllerHarness a,m;
        Pair()throws Exception {
            var disks=LanProofRenewalTest.legacyPair();
            try(var old=disks[0].load(LanControllerHarness.CLOCK)) {
                byte[] retained=LanGroup.random(new java.security.SecureRandom());
                try{
                    var proof=AdminControl.keyProof(old.groupId,new byte[16],0,old.identitySecret,retained);
                    var list=AdminRecords.administrators(old.groupId,0,LanControllerHarness.CLOCK.millis(),List.of(
                        AdminBinding.unknown(old.urlAdmin),AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode())),old.administratorSecret);
                    var revoked=old.state.revocations();
                    var snapshot=new AdminRecordStore.Snapshot(List.of(list.encode(),revoked.encode()),AdminRecords.signAnchor(list,old.administratorSecret),revoked.encode(),0,revoked.version());
                    for(int i=0;i<disks.length;i++)try(var group=disks[i].load(LanControllerHarness.CLOCK)) {
                        group.state=LanGroup.restore(group.groupId,group.urlAdmin,snapshot,LanControllerHarness.CLOCK);
                        group.state.trustStoredLegacyCertificate(group.certificate);group.state.trustStoredLegacyCertificate(group.peerCertificate);
                        if(i==0){Crypto.wipe(group.administratorSecret);group.administratorSecret=retained.clone();}
                        disks[i].enableSix();disks[i].save(group);
                    }
                }finally{Crypto.wipe(retained);}
            }
            wall.now.incrementAndGet();a=new LanControllerHarness(disks[0],CotPort.NONE,wall);m=new LanControllerHarness(disks[1],CotPort.NONE,wall);
            LanProofRenewalTest.until(()->a.endpoint().isEstablished(group(m).id())&&m.endpoint().isEstablished(group(a).id()),a,m);
        }
        Object ask()throws Exception {a.controller.removeUnknown(a.controller.ticket());a.drain();assertNotNull(a.ui.confirmation);assertEquals(1,a.ui.confirmationCount);return a.ui.confirmation;}
        public void close(){a.close();m.close();}
    }
    static LanGroup group(LanControllerHarness h)throws Exception{return LanBehaviourWiringTest.group(h);}
    @Test public void onlineUnknownRemovalWaitsForFirstAndPersistsWholeCandidate()throws Exception {
        try(var p=new Pair()) {
            var tap=new LanProofRenewalTest.Tap();tap.dropReplies=true;tap.install(p.a);
            Object token=p.ask();long version=group(p.a).state.administrators().version();
            p.a.controller.confirmUnknown(token);p.a.drain();
            for(int i=0;i<10;i++){p.a.tick();p.m.tick();}
            assertEquals(version,group(p.a).state.administrators().version());
            tap.dropReplies=false;
            LanProofRenewalTest.until(()->group(p.a).state.administrators().version()>version,p.a,p.m);
            assertEquals(1,group(p.a).state.administrators().bindings().size());
            assertFalse(p.a.ui.last.text.contains("保存がいっぱい"));assertTrue(p.a.ui.last.operationsReady);
            try(var saved=p.a.disk.load(p.wall)){assertEquals(1,saved.state.administrators().bindings().size());assertTrue(saved.state.revocations().version()>0);}
        }
    }
    @Test public void durableCandidateFailureStopsWithoutCompensation()throws Exception {
        try(var p=new Pair()) {
            Object token=p.ask();var sessions=(SessionManager)LanControllerHarness.field(p.a.controller,"managedSessions");
            p.a.disk.afterCandidateSave=snapshot->sessions.close();
            p.a.controller.confirmUnknown(token);p.a.drain();
            LanProofRenewalTest.until(()->p.a.disk.candidateSaves>0,p.a,p.m);
            assertTrue((boolean)LanControllerHarness.field(p.a.controller,"committedNotApplied"));
            assertNull(p.a.endpoint());assertTrue(p.a.ui.last.text.contains("保存した変更を適用できません"));
            assertFalse(p.a.ui.last.text.contains("保存がいっぱい"));
            int writes=p.a.disk.candidateSaves;
            for(int i=0;i<3;i++)p.a.tick();
            assertNull(p.a.endpoint());assertEquals(writes,p.a.disk.candidateSaves);
            try(var saved=p.a.disk.load(p.wall)){assertEquals(1,saved.state.administrators().bindings().size());}
        }
    }
    @Test public void endpointRefreshAndCommitUseOneLockOrder()throws Exception {
        var p=new Pair();Object token=p.ask();
        var sessions=(SessionManager)LanControllerHarness.field(p.a.controller,"managedSessions");
        var refreshThread=new AtomicReference<Thread>();
        p.a.disk.beforeCandidateSave=()->{
            var started=new CountDownLatch(1);var acquired=new CountDownLatch(1);
            var receiver=new Thread(()->{started.countDown();synchronized(sessions){acquired.countDown();sessions.refresh();}});
            receiver.setDaemon(true);refreshThread.set(receiver);receiver.start();
            try{
                assertTrue(started.await(2,TimeUnit.SECONDS));
                if(!Thread.holdsLock(sessions))assertTrue(acquired.await(2,TimeUnit.SECONDS));
            }catch(InterruptedException e){throw new AssertionError("試験を中断しました");}
        };
        var helper=(AdministrationPreparation)LanControllerHarness.field(p.a.controller,"preparation");
        var original=(AdministrationPreparation.Port)LanControllerHarness.field(helper,"port");
        var field=AdministrationPreparation.class.getDeclaredField("port");field.setAccessible(true);
        field.set(helper,new AdministrationPreparation.Port(){
            public void own(AdminRecords.Record certificate){original.own(certificate);}
            public void issued(AdminRecords.Record certificate){original.issued(certificate);}
            public void send(byte[] peer,RenewalMessage message){original.send(peer,message);}
            public void commit(GroupAdministration.Preparation preparation,GroupAdministration.Candidate candidate){
                var complete=new CountDownLatch(1);var failure=new AtomicReference<Throwable>();
                var worker=new Thread(()->{try{original.commit(preparation,candidate);}catch(Throwable e){failure.set(e);}finally{complete.countDown();}});
                worker.setDaemon(true);worker.start();
                try{assertTrue("保存と端点の処理が行き詰まりました",complete.await(3,TimeUnit.SECONDS));}
                catch(InterruptedException e){throw new AssertionError("試験を中断しました");}
                if(failure.get()!=null)throw new AssertionError("保存の試験に失敗しました",failure.get());
            }
        });
        p.a.controller.confirmUnknown(token);p.a.drain();
        LanProofRenewalTest.until(()->p.a.disk.candidateSaves>0,p.a,p.m);
        var receiver=refreshThread.get();assertNotNull(receiver);receiver.join(2000);assertFalse(receiver.isAlive());
        assertEquals(1,p.a.disk.candidateSaves);p.close();
    }
}
