// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class CotCaptureTimingTest {
    @Test public void productionAndRebindDetermineEightMillisecondBackoff(){
        for(long elapsed:new long[]{8_000_000,8_000_001}){
            long[] now={100};var policy=new CotCapturePolicy();assertTrue(policy.begin(0,false));
            var timing=new CotCaptureTiming(()->now[0]);now[0]+=elapsed;timing.finish();now[0]+=1_000_000;
            assertEquals(elapsed,timing.policyNanos());
            policy.end(0,1,CotCapturePolicy.Result.SUCCESS,timing.policyNanos());
            assertEquals(elapsed>8_000_000,policy.timeBackoff());assertEquals(elapsed>8_000_000?20_000:5_000,policy.delay());
        }
    }
}
