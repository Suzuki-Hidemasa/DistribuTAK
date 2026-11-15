// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class InvitationQrTest {
    @Test public void qrPixelsRoundTripCanonicalInvitationAndRejectDamage() throws Exception {
        try(var invitation=new Invitation(new byte[]{(byte)192,(byte)168,1,2},54321,new byte[32],new byte[32],new byte[32], new byte[32])) {
            String url=InvitationUrl.encode(invitation);
            byte[] pixels=InvitationQr.encode(invitation,512);
            try(var decoded=InvitationQr.decode(pixels,512,512)) { assertTrue(url.equals(InvitationUrl.encode(decoded))); }
            assertThrows(Exception.class,()->InvitationQr.decode(new byte[512*512],512,512));
            assertThrows(Exception.class,()->InvitationQr.decode(new byte[4],512,512));
            String broken=url.substring(0,url.length()-1)+(url.endsWith("A")?"B":"A");
            assertThrows(Exception.class,()->InvitationQr.parse(broken));
            try(var decoded=InvitationQr.parse(url)){assertTrue(url.equals(InvitationUrl.encode(decoded)));}
        }
    }

    @Test public void seededThousandInvitationsIncludingCase72RoundTripWithNormalDetector() throws Exception {
        var random=new java.util.Random(163);
        for(int index=0;index<1000;index++) {
            byte[] x=new byte[32],a=new byte[32],t=new byte[32],pixels=null;
            random.nextBytes(x);random.nextBytes(a);random.nextBytes(t);
            try(var invitation=new Invitation(new byte[]{(byte)192,0,2,1},54321,Crypto.x25519Public(x),Crypto.ed25519Public(a),t, new byte[32])) {
                pixels=InvitationQr.encode(invitation,512);
                try(var decoded=InvitationQr.decode(pixels,512,512)) {
                    assertTrue("QR roundtrip case="+index,InvitationUrl.encode(invitation).equals(InvitationUrl.encode(decoded)));
                }catch(Exception e){throw new AssertionError("QR normal detector failed case="+index,e);}
            }finally{Crypto.wipe(x);Crypto.wipe(a);Crypto.wipe(t);Crypto.wipe(pixels);}
        }
    }
}
