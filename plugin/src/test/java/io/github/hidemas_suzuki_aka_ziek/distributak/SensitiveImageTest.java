// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.util.*;
import org.junit.Test;import static org.junit.Assert.*;
public class SensitiveImageTest {
    @Test public void detachThenEraseThenRecycleOnEveryDismissal() {
        var calls=new ArrayList<String>();
        SensitiveImage.clear(()->calls.add("detach"),()->calls.add("erase"),()->calls.add("recycle"));
        assertEquals(List.of("detach","erase","recycle"),calls);
    }
    @Test public void failedCleanupStepNeverPreventsLaterStepsOrEscapesToHost() {
        for(String failing:List.of("detach","erase","recycle")) {
            var calls=new ArrayList<String>();
            SensitiveImage.clear(()->step(calls,"detach",failing),()->step(calls,"erase",failing),()->step(calls,"recycle",failing));
            assertEquals(List.of("detach","erase","recycle"),calls);
        }
    }
    private static void step(List<String> calls,String name,String failing){calls.add(name);if(name.equals(failing))throw new IllegalStateException("test cleanup");}
}
