// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;
import static org.junit.Assert.*;

public class CotExternalObservationTest {
    @Test public void importedSignalInsideFenceIsExternalOnlyWhileAMarkExists(){
        for(boolean fenced:new boolean[]{false,true})for(boolean marked:new boolean[]{false,true}){
            int[] calls={0};CotExternalObservation.observe("incoming",fenced,marked,uid->calls[0]++);
            assertEquals(!fenced||marked?1:0,calls[0]);
        }
    }
    @Test public void absentUidDoesNotNotify(){
        for(String uid:new String[]{null,""})CotExternalObservation.observe(uid,false,true,name->fail());
    }
    @Test public void markQueryIncludesPendingInFlightAndDurableMarksButDoesNotInventOneForUnreadStateOrOverflow(){
        var source=new CotSourceBuffer();var current=new AtomicReference<ExternalMarks>();
        assertFalse(source.externalMarked("incoming",current::get));
        source.external("incoming");assertTrue(source.externalMarked("incoming",current::get));
        try(var batch=source.take()){
            assertTrue(source.externalMarked("incoming",current::get));
            var marks=new ExternalMarks(new byte[32],new byte[32]);marks.add("incoming");current.set(marks);
            batch.committed();assertTrue(source.externalMarked("incoming",current::get));
        }
        current.set(new ExternalMarks(new byte[32],new byte[32]));assertFalse(source.externalMarked("incoming",current::get));
        for(int n=0;n<ExternalMarks.MAX_ENTRIES;n++)source.external("outside-"+n);
        assertFalse(source.external("overflow"));assertFalse(source.externalMarked("unmarked",current::get));
    }
}
