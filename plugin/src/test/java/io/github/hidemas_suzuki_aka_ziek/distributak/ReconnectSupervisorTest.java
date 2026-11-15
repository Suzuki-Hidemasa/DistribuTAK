// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import org.junit.Test;
import static org.junit.Assert.*;
public class ReconnectSupervisorTest {
    @Test public void backoffNeverFasterThanCoreRetry(){
        var supervisor=new ReconnectSupervisor();supervisor.enable(0);
        long now=0;
        for(long seconds:new long[]{5,10,20,40,60,60}){
            supervisor.retry(now);assertFalse(supervisor.due(now+seconds*1_000_000_000L-1));
            now+=seconds*1_000_000_000L;assertTrue(supervisor.due(now));
        }
    }
    @Test public void thirdConsecutiveFailureStops(){var s=new ReconnectSupervisor();s.enable(0);s.failed(0);s.failed(5_000_000_000L);s.failed(15_000_000_000L);assertFalse(s.due(Long.MAX_VALUE));}
    @Test public void establishmentResetsFailureCountAndBackoff(){var s=new ReconnectSupervisor();s.enable(0);s.failed(0);s.failed(5_000_000_000L);s.established();s.failed(10_000_000_000L);assertTrue(s.due(15_000_000_000L));}
    @Test public void stoppingDisablesUntilExplicitEnable(){var s=new ReconnectSupervisor();s.enable(0);s.stop();assertFalse(s.due(Long.MAX_VALUE));s.enable(7);assertTrue(s.due(7));}
    @Test public void backwardsTickerDoesNotAccelerate(){var s=new ReconnectSupervisor();s.enable(100);s.retry(100);assertFalse(s.due(99));}
}
