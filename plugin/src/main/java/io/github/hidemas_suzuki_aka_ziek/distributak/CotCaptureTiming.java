// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.function.LongSupplier;

/** 照合と聞き手の再登録の本処理時間。照合間隔の判定だけに使う。 */
final class CotCaptureTiming {
    private final LongSupplier clock;
    private final long started;
    private long elapsed;
    private boolean finished;
    CotCaptureTiming(LongSupplier clock){this.clock=clock;started=clock.getAsLong();}
    void finish(){if(!finished){elapsed=Math.max(0,clock.getAsLong()-started);finished=true;}}
    long policyNanos(){return finished?elapsed:Math.max(0,clock.getAsLong()-started);}
}
