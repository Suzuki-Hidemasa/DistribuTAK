// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import android.os.SystemClock;
import java.util.function.LongSupplier;

/** 核へ渡す単調時計はここで決める。端末が眠っている間も進む。 */
final class AndroidClocks {
    static final LongSupplier MONOTONIC_NANOS = SystemClock::elapsedRealtimeNanos;
    private AndroidClocks() {}
}
