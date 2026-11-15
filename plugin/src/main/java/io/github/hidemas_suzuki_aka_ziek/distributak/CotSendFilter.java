// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.Set;

/** ATAKの型を持たず、遅延した読み取りも含めて柵の判定を試せる口。 */
final class CotSendFilter {
    enum Result { IGNORED,CONSUMED }
    // ADR0030答え169(1)。予期しない例外では、その1件を止める。
    private static final Result ON_EXCEPTION=Result.CONSUMED;
    interface Event {String uid();boolean deletion();int linkCount();String linkUid(int index);}
    private CotSendFilter(){}
    static Result process(CotFence gate,Event event,long now){
        try{
            if(event==null)return Result.IGNORED;
            String uid=event.uid();if(gate.consume(uid,false,Set.of()))return Result.CONSUMED;
            if(event.deletion())for(int n=0,count=event.linkCount();n<count;n++){
                String target=event.linkUid(n);
                if(target!=null&&gate.consume(uid,true,Set.of(target)))return Result.CONSUMED;
            }
            return Result.IGNORED;
        }catch(RuntimeException e){gate.failedEvent(now,ON_EXCEPTION==Result.CONSUMED);return ON_EXCEPTION;}
    }
}
