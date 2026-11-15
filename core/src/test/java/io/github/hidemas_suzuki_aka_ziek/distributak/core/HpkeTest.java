// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HpkeTest {
    @Test void rfc9180BaseVector() throws Exception {
        var v=new Vectors("hpke");
        assertArrayEquals(v.bytes("skEm"), Hpke.derivePrivateKey(v.bytes("ikmE")));
        assertArrayEquals(v.bytes("skRm"), Hpke.derivePrivateKey(v.bytes("ikmR")));
        try(var s=Hpke.sender(v.bytes("pkRm"),v.bytes("info"),v.bytes("skEm"));
            var r=Hpke.recipient(v.bytes("skRm"),v.bytes("enc"),v.bytes("info"))) {
            assertArrayEquals(v.bytes("enc"),s.encapsulation());
            assertArrayEquals(v.bytes("key"),s.keyForTest());
            assertArrayEquals(v.bytes("base_nonce"),s.nonceForTest());
            for(int n=0;n<v.count("encryptions");n++) {
                String prefix="encryptions."+n+".";
                byte[] ct=s.seal(v.bytes(prefix+"aad"),v.bytes(prefix+"pt"));
                assertArrayEquals(v.bytes(prefix+"ct"),ct,"index="+n);
                assertArrayEquals(v.bytes(prefix+"pt"),r.open(v.bytes(prefix+"aad"),ct));
            }
            for(int n=0;n<v.count("exports");n++) {
                String p="exports."+n+".";
                int len=Integer.parseInt(v.values.getProperty(p+"L"));
                assertArrayEquals(v.bytes(p+"exported_value"),s.export(v.bytes(p+"exporter_context"),len));
                assertArrayEquals(s.export(v.bytes(p+"exporter_context"),len),r.export(v.bytes(p+"exporter_context"),len));
            }
        }
    }
    @Test void tamperingWrongKeyAndRoleRejected() throws Exception {
        var v=new Vectors("hpke");
        try(var s=Hpke.sender(v.bytes("pkRm"),v.bytes("info"),v.bytes("skEm"));
            var r=Hpke.recipient(v.bytes("skRm"),v.bytes("enc"),v.bytes("info"))) {
            byte[] ct=s.seal(new byte[0],new byte[]{1}); ct[0]^=1;
            assertThrows(SecurityException.class,()->r.open(new byte[0],ct));
            assertThrows(IllegalStateException.class,()->r.seal(new byte[0],new byte[0]));
            assertThrows(IllegalStateException.class,()->s.open(new byte[0],ct));
            s.close(); assertThrows(IllegalStateException.class,()->s.seal(new byte[0],new byte[0]));
        }
        assertThrows(SecurityException.class,()->Hpke.sender(new byte[32],new byte[0]));
    }
}
