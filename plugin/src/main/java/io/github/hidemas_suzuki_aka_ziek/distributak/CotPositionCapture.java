// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.CotXml;
import java.util.function.*;

/** 位置の本番XMLだけを渡し、失敗した場合も配列を消す。 */
final class CotPositionCapture {
    static void capture(Supplier<byte[]> serialize,Consumer<byte[]> publish){
        byte[] xml=null;
        try{xml=serialize.get();if(xml!=null){CotXml.inspect(xml);publish.accept(xml);}}
        finally{Crypto.wipe(xml);}
    }
}
