// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.BitSet;

/** RFC 2401 appendix C の番号窓。RFC 6479 と同じく循環させ、ビットをずらさない。 */
final class ReplayWindow {
    static final int SIZE=2048;
    private final BitSet seen=new BitSet(SIZE);
    private long highest;
    private boolean initialized;
    void check(long counter) {
        if(!initialized || Long.compareUnsigned(counter,highest)>0) return;
        long distance=highest-counter;
        if(Long.compareUnsigned(distance,SIZE)>=0 || seen.get((int)counter & (SIZE-1)))
            throw new SecurityException("番号が古いか受信済みです");
    }
    void commit(long counter) {
        check(counter);
        if(!initialized) { highest=counter;initialized=true; }
        else if(Long.compareUnsigned(counter,highest)>0) {
            long distance=counter-highest;
            if(Long.compareUnsigned(distance,SIZE)>=0) seen.clear();
            else {
                for(int n=1;n<=(int)distance;n++) seen.clear((int)(highest+n) & (SIZE-1));
            }
            highest=counter;
        }
        seen.set((int)counter & (SIZE-1));
    }
}
