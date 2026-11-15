// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class LanControllerOrderTest {
    @Test public void qrRequestedThenHiddenDiscardsLatePixelsButVisibleControlDisplays() throws Exception {
        try(var f=new LanControllerHarness()) {
            f.create();var request=f.controller.ticket();f.controller.showInvitation(request);f.work.drain();
            f.ui.hide();f.ui.show();f.main.drain();assertEquals(0,f.ui.qrs);assertFalse(f.ui.sensitive);
            f.ui.show();f.controller.showInvitation(f.controller.ticket());f.drain();
            assertEquals(1,f.ui.qrs);assertTrue(f.ui.sensitive);
            f.ui.hide();assertFalse(f.ui.sensitive);
        }
    }
    @Test public void missingWifiIsRecoverableButPersistenceFailureStopsController() throws Exception {
        try(var f=new LanControllerHarness()) {
            f.network.current=null;f.controller.create();f.drain();assertTrue(f.ui.last.ready);assertFalse(f.ui.last.member);
            f.network.current=f.link;f.network.changed.run();f.drain();f.create();assertTrue(f.ui.last.member);
        }
        try(var f=new LanControllerHarness()) {
            f.disk.failSave=true;f.controller.create();f.drain();assertFalse(f.ui.last.ready);assertFalse(f.ui.last.member);
        }
    }

    @Test public void joiningThenCloseBeforeFirstRestoresPinAndFinishesHandshake() throws Exception {
        try(var admin=new LanControllerHarness()) {
            admin.create();LanControllerHarness.Disk saved;
            try(var member=new LanControllerHarness()) {
                member.beginJoin(admin);LanControllerHarness.until(()->member.ui.last.member&&admin.logs.contains("LAN_MEMBER_ISSUED"),admin,member);
                saved=member.disk;
                try(var group=saved.load(LanControllerHarness.CLOCK)){assertNull(group.peerCertificate);assertNotNull(group.pendingHandshake);}
                member.controller.disconnect();member.drain();
            }
            try(var restored=new LanControllerHarness(saved)) {
                restored.controller.connect();restored.drain();admin.controller.connect();admin.drain();
                LanControllerHarness.until(()->restored.logs.stream().anyMatch(x->x.startsWith("LAN_ESTABLISHED"))
                        &&admin.logs.stream().anyMatch(x->x.startsWith("LAN_ESTABLISHED")),admin,restored);
                try(var group=saved.load(LanControllerHarness.CLOCK)){assertNotNull(group.peerCertificate);assertNull(group.pendingHandshake);assertNull(group.pendingAddress);}
                admin.controller.sendTest();restored.controller.sendTest();
                LanControllerHarness.until(()->admin.logs.stream().anyMatch(x->x.startsWith("LAN_TEST_RX"))
                        &&restored.logs.stream().anyMatch(x->x.startsWith("LAN_TEST_RX")),admin,restored);
            }
        }
    }
    @Test public void absentSavedPinDoesNotReplyToAuthenticatedFirst() throws Exception {
        try(var admin=new LanControllerHarness()) {
            admin.create();LanControllerHarness.Disk saved;
            try(var member=new LanControllerHarness()) {
                member.beginJoin(admin);LanControllerHarness.until(()->member.ui.last.member&&admin.logs.contains("LAN_MEMBER_ISSUED"),admin,member);
                saved=member.disk;member.controller.disconnect();member.drain();
                try(var group=saved.load(LanControllerHarness.CLOCK)){group.clearPendingPeer();saved.save(group);}
            }
            try(var restored=new LanControllerHarness(saved);var adminGroup=admin.disk.load(LanControllerHarness.CLOCK)) {
                restored.controller.connect();restored.drain();admin.controller.connect();admin.drain();
                var endpoint=restored.endpoint();var sessions=(io.github.hidemas_suzuki_aka_ziek.distributak.core.SessionManager)LanControllerHarness.field(endpoint,"sessions");
                // 第12段の配線: DHT が動くので、同じ Wi-Fi の同じグループの相手の 1 通目は揮発の相手として受ける。
                // ただし保存した相手（pin）は作らない・書かない。揮発の相手は保存に入らず、保存の相手の表にも出ない。
                LanControllerHarness.until(()->endpoint.isEstablished(adminGroup.id()),admin,restored);
                assertFalse(sessions.isHandshaking(adminGroup.id()));
                try(var after=saved.load(LanControllerHarness.CLOCK)){assertNull(after.peerCertificate);assertNull(after.pendingHandshake);assertNull(after.pendingAddress);}
            }
        }
    }
    @Test public void failedPeerPersistenceKeepsPendingRecordInDurableState() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.create();member.beginJoin(admin);LanControllerHarness.until(()->member.ui.last.member&&admin.logs.contains("LAN_MEMBER_ISSUED"),admin,member);
            member.disk.failSave=true;admin.controller.connect();admin.drain();
            LanControllerHarness.until(()->!member.ui.last.ready,admin,member);
            try(var group=member.disk.load(LanControllerHarness.CLOCK)){assertNotNull(group.pendingHandshake);assertNull(group.peerCertificate);}
        }
    }
    @Test public void networkSwitchWithoutEndpointDiscardsCameraAndPermissionTicket() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.create();var invitation=admin.invitation();var ticket=member.controller.ticket();member.ui.sensitive=true;
            member.network.current=member.new Link("B",member.link.address);member.network.changed.run();
            member.work.drain();assertFalse(member.controller.accepts(ticket));
            member.controller.join(invitation,ticket);member.drain();
            assertFalse(member.ui.sensitive);assertEquals(0,member.link.opens);assertTrue(member.ui.last.ready);assertFalse(member.ui.last.member);
        }
    }
    @Test public void unchangedNetworkAndVisibleCameraResultCanJoin() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.create();var invitation=admin.invitation();var ticket=member.controller.ticket();
            member.network.changed.run();member.drain();assertTrue(member.controller.accepts(ticket));
            member.controller.join(invitation,ticket);member.drain();
            LanControllerHarness.until(()->member.ui.last.member,admin,member);assertTrue(member.ui.last.ready);
        }
    }
    @Test public void hiddenThenShownDoesNotReviveOldCameraOrQrTicket() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.create();var invitation=admin.invitation();var ticket=member.controller.ticket();
            member.ui.hide();member.ui.show();assertFalse(member.controller.accepts(ticket));
            member.controller.join(invitation,ticket);member.drain();assertEquals(0,member.link.opens);assertTrue(member.ui.last.ready);
        }
    }
    @Test public void ordinaryTimeoutAndCancellationCleanUpBeforeOrAfterCloseAndAllowRetry() throws Exception {
        for(boolean cancellation:new boolean[]{false,true})for(boolean pollFirst:new boolean[]{false,true}) {
            try(var member=new LanControllerHarness()) {
                var invitation=member.unreachable();member.controller.join(invitation,member.controller.ticket());member.drain();
                var future=member.joinFuture();var endpoint=member.endpoint();
                if(cancellation)future.cancel(false);else member.offset.addAndGet(11_000_000_000L);
                long limit=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(3);
                while(!future.isDone()){if(System.nanoTime()>limit)fail("join did not time out");Thread.sleep(5);}
                if(pollFirst)member.work.repeated.run();else {
                    endpoint.close(); // closeの通知を先にキューへ入れ、pollはあとにする。
                    member.work.drain();
                }
                member.drain();assertTrue(member.ui.last.ready);assertFalse(member.ui.last.busy);assertFalse(member.ui.last.member);
                assertNull(member.disk.state.value);assertNull(member.disk.temporary.value);
                member.controller.join(member.unreachable(),member.controller.ticket());member.drain();assertTrue(member.ui.last.busy);
                member.controller.disconnect();member.drain();member.create();assertTrue(member.ui.last.ready);
            }
        }
    }
    @Test public void stalePrereconditionsPreserveMemberAndConnectCanBeUsedAgain() throws Exception {
        try(var member=new LanControllerHarness()) {
            member.create();member.controller.create();member.controller.setPort(54321);member.drain();assertTrue(member.ui.last.ready);
            member.controller.disconnect();member.drain();member.network.current=null;
            member.controller.connect();member.drain();assertTrue(member.ui.last.ready);assertTrue(member.ui.last.member);
            member.network.current=member.link;member.network.changed.run();member.drain();member.controller.connect();member.drain();assertTrue(member.ui.last.running);
        }
    }
    @Test public void unacceptedGenerationAndExpiredJoinLeavePreviousPersistedStateUnchanged() throws Exception {
        for(boolean expired:new boolean[]{false,true}) {
            try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
                admin.create();member.disk.erased=true;
                try(var previous=LanGroup.create(member.disk.port,LanControllerHarness.CLOCK,new java.security.SecureRandom())){member.disk.save(previous);}
                byte[] before=member.disk.state.value.clone();
                member.disk.afterStage=()->{
                    if(expired)member.offset.addAndGet(11_000_000_000L);
                    else{member.network.current=member.new Link("B",member.link.address);member.network.changed.run();}
                };
                member.beginJoin(admin);
                LanControllerHarness.until("after-stage expired="+expired,()->member.disk.staged==1&&!member.ui.last.busy,admin,member);
                assertArrayEquals(before,member.disk.state.value);assertNull(member.disk.temporary.value);assertTrue(member.disk.erased);
                assertTrue(member.ui.last.ready);assertFalse(member.ui.last.member);
            }
        }
    }
    @Test public void stagingFailureIsFatalInBothFutureAndCloseOrders() throws Exception {
        for(boolean pollFirst:new boolean[]{false,true})try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.create();member.disk.failStage=true;member.beginJoin(admin);var future=member.joinFuture();var endpoint=member.endpoint();
            long limit=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(3);
            while(!future.isDone()){admin.drain();if(System.nanoTime()>limit)fail("stage failure missing");Thread.sleep(5);}
            if(pollFirst)member.work.repeated.run();else{endpoint.close();member.work.drain();}
            member.drain();assertFalse(member.ui.last.ready);assertFalse(member.ui.last.member);assertNull(member.disk.state.value);
        }
    }

    @Test public void foregroundMustStillBeVisibleWhenQrDeliveryRuns() throws Exception {
        try(var f=new LanControllerHarness()) {
            f.create();f.controller.showInvitation(f.controller.ticket());f.work.drain();
            f.ui.front=false;f.main.drain();assertEquals(0,f.ui.qrs);
        }
    }

    @Test public void pendingSavedStateContainsPublicPeerButNoInvitationOrJoinSecret() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.create();var value=admin.invitation();
            byte[] totp=value.totpSecret();String url=io.github.hidemas_suzuki_aka_ziek.distributak.core.InvitationUrl.encode(value);
            byte[] urlBytes=url.getBytes(java.nio.charset.StandardCharsets.US_ASCII),wire=java.util.Base64.getUrlDecoder().decode(url.substring(url.indexOf('#')+1));
            Object registration=LanControllerHarness.field(admin.controller,"invitation");
            Object issuer=LanControllerHarness.field(registration,"admin"),context=LanControllerHarness.field(issuer,"context");
            byte[] proof=((byte[])LanControllerHarness.field(context,"proofKey")).clone();byte[] plain=null;
            try {
                member.controller.join(value,member.controller.ticket());member.drain();
                LanControllerHarness.until(()->member.ui.last.member,admin,member);
                plain=member.disk.envelope.open(member.disk.state.value);
                for(byte[] secret:new byte[][]{totp,urlBytes,wire,proof}) {
                    assertFalse("decoded state contains invitation secret",contains(plain,secret));
                    assertFalse("envelope contains invitation secret",contains(member.disk.state.value,secret));
                }
                try(var group=member.disk.load(LanControllerHarness.CLOCK);var adminGroup=admin.disk.load(LanControllerHarness.CLOCK)) {
                    assertTrue(io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto.equal(adminGroup.groupKey,group.groupKey));
                    assertArrayEquals(value.handshakePublicKey(),group.pendingHandshake);
                    assertEquals(new java.net.InetSocketAddress(java.net.InetAddress.getByAddress(value.adminAddress()),value.udpPort()),group.pendingAddress);
                    assertNull(group.peerCertificate);assertNull(group.peerAddress);
                }
                assertEquals(5,java.nio.ByteBuffer.wrap(plain).getInt());
                byte[] old=plain.clone();java.nio.ByteBuffer.wrap(old).putInt(1);
                assertThrows(Exception.class,()->LanGroup.decode(old,LanControllerHarness.CLOCK));
                io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto.wipe(old);
            }finally {
                for(byte[] secret:new byte[][]{totp,urlBytes,wire,proof,plain})io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto.wipe(secret);
            }
        }
    }
    private static boolean contains(byte[] haystack,byte[] needle){
        for(int i=0;i<=haystack.length-needle.length;i++){
            boolean matches=true;for(int j=0;j<needle.length;j++)matches&=haystack[i+j]==needle[j];if(matches)return true;
        }return false;
    }

    @Test public void stageFailureConcurrentWithNetworkSwitchStillStopsOperations() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.create();member.disk.failStage=true;member.disk.beforeStage=()->{
                member.network.current=member.new Link("B",member.link.address);member.network.changed.run();
            };
            member.beginJoin(admin);LanControllerHarness.until(()->!member.ui.last.busy,admin,member);
            assertFalse(member.ui.last.ready);assertNull(member.disk.state.value);assertNull(member.disk.temporary.value);
        }
    }

    @Test public void finalJoinCommitIsAtomicAndOnlySuccessClearsErasedMark() throws Exception {
        for(boolean fail:new boolean[]{false,true})try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.create();member.disk.erased=true;
            try(var previous=LanGroup.create(member.disk.port,LanControllerHarness.CLOCK,new java.security.SecureRandom())){member.disk.save(previous);}
            byte[] before=member.disk.state.value.clone();member.disk.afterStage=()->member.disk.state.fail=fail;
            member.beginJoin(admin);LanControllerHarness.until(()->member.disk.staged==1&&!member.ui.last.busy,admin,member);
            assertNull(member.disk.temporary.value);
            // 原子的な書き込みの失敗後も、M1の復旧で古い包みを含めて作りかけを取り除く。
            if(fail){assertFalse(member.ui.last.ready);assertTrue(member.disk.erased);assertTrue(member.disk.state.rolledBack);assertNull(member.disk.state.value);}
            else{assertTrue(member.ui.last.ready);assertTrue(member.ui.last.member);assertFalse(member.disk.erased);
                assertFalse(java.util.Arrays.equals(before,member.disk.state.value));}
        }
    }

    @Test public void eraseRemovesPendingPeerAndAllowsNewGroup() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.create();member.beginJoin(admin);LanControllerHarness.until(()->member.ui.last.member,admin,member);
            var active=(LanGroup)LanControllerHarness.field(member.controller,"group");byte[] pending=active.pendingHandshake;
            assertNotNull(pending);member.controller.erase();member.drain();
            assertArrayEquals(new byte[32],pending);assertNull(member.disk.state.value);assertTrue(member.disk.erased);
            assertFalse(member.ui.last.member);assertTrue(member.ui.last.ready);
            member.create();assertTrue(member.ui.last.ready);assertFalse(member.ui.last.erased);
            assertFalse(StoreRecovery.canJoin(member.ui.last.member));
        }
    }
    @Test public void alreadyJoinedAndCannotInviteAreRecoverablePrerequisites() throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()) {
            admin.create();member.beginJoin(admin);LanControllerHarness.until(()->member.ui.last.member&&admin.logs.contains("LAN_MEMBER_ISSUED"),admin,member);
            int opened=member.link.opens;
            member.controller.showInvitation(member.controller.ticket());member.controller.create();
            member.controller.join(member.unreachable(),member.controller.ticket());member.drain();
            assertTrue(member.ui.last.ready);assertTrue(member.ui.last.member);assertEquals(opened,member.link.opens);
            admin.controller.connect();admin.drain();
            LanControllerHarness.until(()->member.logs.stream().anyMatch(x->x.startsWith("LAN_ESTABLISHED")),admin,member);
        }
    }
}
