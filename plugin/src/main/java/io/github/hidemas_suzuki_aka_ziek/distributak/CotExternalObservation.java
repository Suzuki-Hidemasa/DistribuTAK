// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.function.Consumer;

/** 印のある間は取り込まず、期限では印を消してから取り込む順序で見分ける。 */
final class CotExternalObservation {
    static void observe(String uid,boolean fenced,boolean marked,Consumer<String> external){
        if(uid!=null&&!uid.isEmpty()&&(!fenced||marked))external.accept(uid);
    }
}
