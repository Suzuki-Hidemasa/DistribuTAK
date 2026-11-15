// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.util.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;import static org.junit.Assert.*;
public class NewGroupAfterEraseTest {
    private static void differentFingerprint(byte[] previous,byte[] value) {
        byte[] current=Crypto.blake2s(value);
        try{assertFalse(Crypto.equal(previous,current));}finally{Crypto.wipe(current);}
    }
    @Test public void eraseThenCreateProducesDistinctGroupAndIdentityAndInvitation()throws Exception {
        try(var f=new LanControllerHarness()) {
            f.create();byte[] group,id,admin,handshake,key;
            try(var old=f.disk.load(LanControllerHarness.CLOCK)) {
                group=old.groupId.clone();id=old.id();admin=old.urlAdmin.clone();handshake=Crypto.x25519Public(old.handshakeSecret);key=Crypto.blake2s(old.groupKey);
            }
            byte[] totp;
            try(var old=f.invitation()){byte[] secret=old.totpSecret();try{totp=Crypto.blake2s(secret);}finally{Crypto.wipe(secret);}}
            f.controller.erase();f.drain();assertTrue(f.disk.erased);f.create();assertFalse(f.disk.erased);
            try(var fresh=f.disk.load(LanControllerHarness.CLOCK);var next=f.invitation()) {
                assertFalse(Crypto.equal(group,fresh.groupId));assertFalse(Crypto.equal(id,fresh.id()));assertFalse(Crypto.equal(admin,fresh.urlAdmin));
                assertFalse(Crypto.equal(handshake,Crypto.x25519Public(fresh.handshakeSecret)));differentFingerprint(key,fresh.groupKey);
                byte[] secret=next.totpSecret();try{differentFingerprint(totp,secret);}finally{Crypto.wipe(secret);}
            }finally{for(byte[] bytes:new byte[][]{group,id,admin,handshake,key,totp})Crypto.wipe(bytes);}
        }
    }
    @Test public void failedNewCreationKeepsErasedMarkAndRemovesUncommittedState()throws Exception {
        try(var f=new LanControllerHarness()) {
            f.create();f.controller.erase();f.drain();f.disk.failSave=true;f.controller.create();f.drain();
            assertFalse(f.ui.last.ready);assertTrue(f.disk.erased);assertNull(f.disk.state.value);assertNull(f.disk.temporary.value);
            assertArrayEquals(new byte[32],f.disk.creating.identitySecret);assertArrayEquals(new byte[32],f.disk.creating.handshakeSecret);
            assertArrayEquals(new byte[32],f.disk.creating.administratorSecret);assertArrayEquals(new byte[32],f.disk.creating.groupKey);
        }
    }
    @Test public void bothErasedCanRecoverWithOneNewAdministrator()throws Exception {
        try(var a=new LanControllerHarness();var b=new LanControllerHarness()) {
            a.controller.erase();b.controller.erase();a.drain();b.drain();a.create();b.beginJoin(a);
            LanControllerHarness.until("both-erased recovery",()->b.ui.last.member,a,b);
            assertFalse(a.ui.last.erased);assertFalse(b.ui.last.erased);
            try(var left=a.disk.load(LanControllerHarness.CLOCK);var right=b.disk.load(LanControllerHarness.CLOCK)){assertArrayEquals(left.groupId,right.groupId);}
        }
    }
    @Test public void erasingBlocksCreationAndStartupFinishesBeforeAllowingCreate()throws Exception {
        LanControllerHarness.Disk disk;
        try(var f=new LanControllerHarness()) {
            disk=f.disk;disk.erasing=true;f.controller.create();f.drain();
            assertFalse(f.ui.last.member);assertTrue(f.ui.last.erasing);assertNull(disk.state.value);
        }
        try(var restarted=new LanControllerHarness(disk)) {
            assertFalse(restarted.ui.last.erasing);assertTrue(restarted.ui.last.erased);restarted.create();assertFalse(disk.erased);
        }
    }
    @Test public void oldInvitationCannotJoinNewGroupButFreshInvitationCan()throws Exception {
        try(var a=new LanControllerHarness();var b=new LanControllerHarness()) {
            a.create();int previous=a.disk.port;
            try(var old=a.invitation()) {
                a.controller.erase();a.drain();assertEquals(1,a.disk.portDraws);
                assertTrue(a.disk.port>=49152&&a.disk.port<=65535);
                // 同じ番地とポートでも古い公開鍵・TOTPでは入れない。
                a.controller.setPort(previous);a.drain();a.create();a.invitation().close();
                b.controller.join(old,b.controller.ticket());b.drain();
                b.offset.addAndGet(11_000_000_000L);
                LanControllerHarness.until("old invitation rejected",()->!b.ui.last.busy,a,b);
                assertFalse(b.ui.last.member);assertNull(b.disk.state.value);
                try(var current=a.disk.load(LanControllerHarness.CLOCK)){assertNull(current.peerCertificate);}
                b.beginJoin(a);LanControllerHarness.until("fresh invitation accepted",()->b.ui.last.member,a,b);
            }
        }
    }
    @Test public void oldMemberStateCannotEstablishNewGroupButFreshJoinCan()throws Exception {
        try(var a=new LanControllerHarness();var b=new LanControllerHarness()) {
            a.create();b.beginJoin(a);
            LanControllerHarness.until("old membership saved",()->b.ui.last.member&&a.logs.contains("LAN_MEMBER_ISSUED"),a,b);
            a.controller.connect();a.drain();
            LanControllerHarness.until("old session established",()->b.ui.last.text.contains("セッション: 確立"),a,b);
            b.controller.disconnect();b.drain();
            int previous=a.disk.port;a.controller.erase();a.drain();a.controller.setPort(previous);a.drain();a.create();
            int received=a.link.received.get();b.controller.connect();b.drain();
            // 管理者に旧メンバーの暗号パケットが実際に届いても所属を増やさない。
            b.offset.addAndGet(2_000_000_000L);b.tick();
            LanControllerHarness.until("old member packet delivered",()->a.link.received.get()>received,a,b);
            assertFalse(b.ui.last.text.contains("セッション: 確立"));
            try(var current=a.disk.load(LanControllerHarness.CLOCK)){assertNull(current.peerCertificate);}
            b.controller.erase();b.drain();b.beginJoin(a);
            LanControllerHarness.until("fresh membership accepted",()->b.ui.last.member,a,b);
        }
    }

}
