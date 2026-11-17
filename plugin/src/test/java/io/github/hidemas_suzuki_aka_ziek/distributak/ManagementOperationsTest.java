// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementOperations;

import java.security.SecureRandom;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ManagementOperationsTest {
    @Test public void repeatedRandomPrefixStillProducesUniqueOperations(){
        var operations=new ManagementOperations(new SecureRandom(){@Override public void nextBytes(byte[] bytes){Arrays.fill(bytes,(byte)0);}});
        Set<String> issued=new HashSet<>();for(int i=0;i<1024;i++)assertTrue(issued.add(Base64.getEncoder().encodeToString(operations.next())));
    }
    @Test public void exhaustedCounterCannotWrapOrRepeat()throws Exception{
        var operations=new ManagementOperations(new SecureRandom());var field=ManagementOperations.class.getDeclaredField("counter");field.setAccessible(true);field.setLong(operations,Long.MAX_VALUE);
        byte[] last=operations.next();assertEquals(16,last.length);assertThrows(IllegalStateException.class,operations::next);
    }
    @Test public void returnedArrayDoesNotChangeLaterOperations(){
        var operations=new ManagementOperations(new SecureRandom());byte[] first=operations.next();Arrays.fill(first,(byte)0);assertFalse(Arrays.equals(first,operations.next()));
    }
}
