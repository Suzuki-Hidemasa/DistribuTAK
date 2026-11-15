// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.OptionalLong;

/** 全UIDで一つの最大値。再起動時には保存した最大値を渡す。 */
public final class SyncVersionClock {
    private long maximum,lastWall;
    private boolean first=true,rewound;
    public SyncVersionClock(long savedMaximum) {
        if(savedMaximum< -1)throw new IllegalArgumentException("版の最大値が範囲外です");maximum=savedMaximum;
    }
    public OptionalLong next(long wallMillis) {
        if(wallMillis<0)throw new IllegalArgumentException("時計の値が範囲外です");
        if(first?wallMillis<maximum:wallMillis<lastWall)rewound=true;
        first=false;lastWall=wallMillis;
        if(rewound) { if(wallMillis<=maximum)return OptionalLong.empty();rewound=false; }
        if(maximum==Long.MAX_VALUE)return OptionalLong.empty();
        long candidate=Math.max(wallMillis,maximum+1);
        if(candidate-wallMillis>CotXml.MAX_FUTURE_MILLIS)return OptionalLong.empty();
        maximum=candidate;return OptionalLong.of(candidate);
    }
    public long maximum() { return maximum; }
}
