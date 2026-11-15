// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.time.*;
import java.security.SecureRandom;
import java.net.*;
import java.util.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class LanGroupTest {
    final Clock clock=Clock.fixed(Instant.ofEpochMilli(10_000_000_000L),ZoneOffset.UTC);
    /** 自分以外の相手は 128 台まで（第12段。ADR 0030 答え 190・192）。コアへ渡す台数は自分を含めて 129。 */
    @Test public void theGroupAdmitsOneHundredTwentyEightOtherPeers() {
        assertEquals(128,LanGroup.MAX_PEERS);
    }
    /** コアへ渡す台数は自分を含めて MAX_PEERS+1。加入（LanController）も復元（LanGroup.sessions）も coreGroupSize() を通す。 */
    @Test public void theGroupSizeGivenToTheCoreCountsTheLocalDeviceToo() {
        assertEquals(LanGroup.MAX_PEERS+1,LanGroup.coreGroupSize());
        assertEquals(129,LanGroup.coreGroupSize());
    }
    @Test public void createsAdministratorAndRestoresSameKeysAndVerifiedRecords() throws Exception {
        try(var group=LanGroup.create(54321,clock,new SecureRandom())) {
            byte[] encoded=group.encode();
            try(var restored=LanGroup.decode(encoded,clock)) {
                assertTrue(restored.isAdministrator());assertArrayEquals(group.identitySecret,restored.identitySecret);
                assertArrayEquals(group.groupKey,restored.groupKey);
                restored.state.verifyCertificate(restored.certificate,Crypto.x25519Public(restored.handshakeSecret));
                assertEquals(54321,restored.port);
            } finally {Crypto.wipe(encoded);}
            byte[] secret=group.handshakeSecret;group.close();assertArrayEquals(new byte[32],secret);
        }
    }
    @Test public void joinResultCanBeStoredIndependentlyOfEndpointOwnership() throws Exception {
        try(var admin=LanGroup.create(54321,clock,new SecureRandom())) {
            byte[] identity=new byte[32],handshake=new byte[32];new SecureRandom().nextBytes(identity);new SecureRandom().nextBytes(handshake);
            byte[] totp=new byte[32];new SecureRandom().nextBytes(totp);
            try(var invitation=new Invitation(new byte[]{(byte)192,(byte)168,1,2},54321,Crypto.x25519Public(admin.handshakeSecret),
                    Crypto.ed25519Public(admin.administratorSecret),totp, admin.groupId);
                var issuer=new JoinHandshake.Admin(invitation,admin.state.administrators(),admin.state.snapshot().anchorSignature(),clock,System::nanoTime);
                var joiner=new JoinHandshake.Joiner(invitation,identity,handshake,clock);
                var materials=new JoinHandshake.Materials(List.of(admin.state.administrators()),admin.state.revocations(),0,admin.groupKey)) {
                byte[] request=joiner.request(),response=issuer.respond(request,admin.handshakeSecret,admin.administratorSecret,materials);
                try(var joined=joiner.receive(response);var member=LanGroup.joined(54322,identity,handshake,invitation.adminPublicKey(),joined,clock)) {
                    byte[] encoded=member.encode();joined.close();
                    try(var restored=LanGroup.decode(encoded,clock)) {
                        assertFalse(restored.isAdministrator());assertArrayEquals(admin.groupKey,restored.groupKey);
                        restored.state.verifyCertificate(restored.certificate,Crypto.x25519Public(handshake));
                    }finally{Crypto.wipe(encoded);}
                }finally{Crypto.wipe(request);Crypto.wipe(response);}
            } finally {Crypto.wipe(identity);Crypto.wipe(handshake);Crypto.wipe(totp);}
        }
    }
    @Test public void corruptAndTruncatedStateCannotReplaceValidRecord() throws Exception {
        try(var group=LanGroup.create(54321,clock,new SecureRandom())) {
            byte[] good=group.encode();
            assertThrows(Exception.class,()->LanGroup.decode(Arrays.copyOf(good,good.length-1),clock));
            byte[] bad=good.clone();bad[0]^=1;assertThrows(Exception.class,()->LanGroup.decode(bad,clock));
            // 署名済みの自分の証明書を壊し、中身の再検査も確かめる。
            byte[] certificate=group.certificate.encode();certificate[certificate.length-1]^=1;
            group.certificate=AdminRecords.decode(certificate);
            assertThrows(Exception.class,group::encode);
            byte[] altered=good.clone();
            // 固定の先頭部をDataInputでたどり、自分の証明書の署名だけを変える。
            var input=new java.io.DataInputStream(new java.io.ByteArrayInputStream(altered));
            input.readInt();input.readInt();
            for(int i=0;i<4;i++)input.skipBytes(input.readInt());
            input.readLong();for(int i=0;i<2;i++)input.skipBytes(input.readInt());
            int length=input.readInt(),offset=altered.length-input.available();altered[offset+length-1]^=1;
            assertThrows(Exception.class,()->LanGroup.decode(altered,clock));
            try(var control=LanGroup.decode(good,clock)){assertArrayEquals(group.groupId,control.groupId);}
            Crypto.wipe(good);Crypto.wipe(bad);
        }
    }
}
