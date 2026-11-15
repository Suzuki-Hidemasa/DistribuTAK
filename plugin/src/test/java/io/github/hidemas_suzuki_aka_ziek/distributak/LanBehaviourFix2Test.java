// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;

public class LanBehaviourFix2Test {
    static final String SYNC_FAILED="同期の記録を開けません。消去して作成か加入をやり直してください";
    static final String SOCKET_FAILED="待ち受けを開けません。ポートを確かめてください";
    static final String RENEW_FAILED=LanBehaviourFixTest.RENEW_FAILED;
    @Test public void legacyValidMemberStartsAndPreservesIdentityCertificateAndBytes()throws Exception{
        try(var group=LanGroup.decode(StorageGroupTest.fixture(3,"member-valid"),LanControllerHarness.CLOCK,true)){
            assertFalse(group.isAdministrator());assertNull(group.peerCertificate);
        }
        new LanBehaviourFixTest().legacy("member-valid",false,false);
    }
    @Test public void administratorRenewalSavedBeforeSocketFailureCanConnectWithoutCountingAgain()throws Exception{runningFailure(false);}
    @Test public void administratorSyncFailureKeepsStoppedMessageAndDoesNotErase()throws Exception{runningFailure(true);}
    void runningFailure(boolean sync)throws Exception{
        var wall=new LanAutomaticRenewalTest.Wall();
        try(var admin=new LanControllerHarness(null,CotPort.NONE,wall)){
            admin.create();var endpoint=admin.endpoint();
            if(sync)admin.disk.sync.value=null;else admin.link.failOpens=1;
            wall.now.addAndGet(AdminRecords.CERTIFICATE_LIFETIME_MILLIS+1);
            LanControllerHarness.until(()->endpoint.closeReason()==UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED);
            LanControllerHarness.until(()->!admin.ui.last.running,admin);
            assertEquals(!sync,admin.ui.last.ready);assertFalse(admin.disk.erased);
            assertTrue(admin.ui.last.text.contains(sync?SYNC_FAILED:SOCKET_FAILED));assertFalse(admin.ui.last.text.contains(RENEW_FAILED));
            try(var saved=admin.disk.load(wall)){assertEquals(1,saved.renewalCount);}
            if(!sync){admin.controller.connect();admin.drain();assertTrue(admin.ui.last.running);try(var saved=admin.disk.load(wall)){assertEquals(1,saved.renewalCount);}}
        }
    }
    @Test public void rejoinRecoverySyncFailurePreservesStoppedMessageAndOriginalState()throws Exception{
        var pair=LanBehaviourFixTest.validPair();
        try(var admin=LanBehaviourFixTest.stoppedAdmin(pair[0]);var member=new LanControllerHarness(pair[1])){
            LanBehaviourFixTest.keyHint(member);byte[] old=member.disk.state.value.clone();
            member.disk.sync.value=null;member.link.failOpens=1;LanBehaviourFixTest.beginRejoin(member,admin);
            assertFalse(member.ui.last.ready);assertFalse(member.ui.last.running);assertFalse(member.disk.erased);
            assertTrue(member.ui.last.text.contains(SYNC_FAILED));assertFalse(member.ui.last.text.contains(LanBehaviourFixTest.JOIN_FAILED));
            assertArrayEquals(old,member.disk.state.value);
        }
    }
    @Test public void startupExpiredAdministratorSaveFailureAllowsConnectAndCountsOnce()throws Exception{startupFailure(31);}
    @Test public void startupAdministratorAtThresholdSaveFailureAllowsConnectAndCountsOnce()throws Exception{startupFailure(20);}
    void startupFailure(int days)throws Exception{
        var wall=new LanAutomaticRenewalTest.Wall();LanControllerHarness.Disk disk;
        try(var original=new LanControllerHarness(null,CotPort.NONE,wall)){original.create();disk=original.disk;}
        byte[] old=disk.state.value.clone();wall.now.addAndGet(days*86_400_000L);disk.failSave=true;
        try(var next=new LanControllerHarness(disk,CotPort.NONE,wall)){
            checkWaiting(next,old,wall);
            next.controller.connect();next.drain();checkWaiting(next,old,wall);
            disk.failSave=false;next.controller.connect();next.drain();assertTrue(next.ui.last.ready);assertTrue(next.ui.last.running);
            try(var saved=disk.load(wall)){assertEquals(1,saved.renewalCount);assertEquals(wall.millis(),saved.certificate.issuedAt());}
            next.tick();try(var saved=disk.load(wall)){assertEquals(1,saved.renewalCount);}
        }
    }
    void checkWaiting(LanControllerHarness node,byte[] old,LanAutomaticRenewalTest.Wall wall)throws Exception{
        assertTrue(node.ui.last.ready);assertFalse(node.ui.last.running);assertFalse(node.disk.erased);
        assertTrue(node.ui.last.text.contains(RENEW_FAILED));assertArrayEquals(old,node.disk.state.value);
        try(var saved=node.disk.load(wall)){assertEquals(0,saved.renewalCount);}
    }
}
