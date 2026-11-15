// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.*;

public class CotCapturePolicyTest {
    @Test public void syncStorageLimitsRemainTheSpecifiedValues(){
        assertEquals(4194304,StateEnvelope.SYNC_MAX_BYTES);
        assertEquals(4096,io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncState.MAX_UIDS);
        assertEquals(65536,io.github.hidemas_suzuki_aka_ziek.distributak.core.CotXml.MAX_BYTES);
        assertEquals(4194304-38,io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncState.MAX_PLAINTEXT_BYTES);
    }
    @Test public void scheduleUsesMapCountAndOnlyOneRunAndRetriesAfterLimit() {
        var p=new CotCapturePolicy();assertTrue(p.begin(0,false));assertFalse(p.begin(0,false));
        p.end(0,0,CotCapturePolicy.Result.SUCCESS,0);assertFalse(p.begin(9_999,false));assertTrue(p.begin(10_000,false));
        p.end(10_000,1,CotCapturePolicy.Result.SUCCESS,0);assertEquals(5_000,p.delay());
        assertTrue(p.begin(15_000,false));p.end(15_000,100,CotCapturePolicy.Result.SUCCESS,0);assertEquals(5_000,p.delay());
        assertTrue(p.begin(20_000,false));p.end(20_000,101,CotCapturePolicy.Result.SUCCESS,0);assertEquals(20_000,p.delay());
        assertTrue(p.begin(40_000,false));p.end(40_000,0,CotCapturePolicy.Result.LIMIT,0);assertEquals(20_000,p.delay());
        assertFalse(p.begin(40_001,true));assertTrue(p.begin(60_000,true));
    }
    @Test public void onlyIndependentCompletePeriodicScansCountAndFinalOwnershipCheckIsRequired() {
        var p=new CotCapturePolicy();p.saved("own",false);p.seen(Set.of("own"));
        p.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);assertFalse(p.deletable("own",true,true));
        p.absent(Set.of(),false,CotCapturePolicy.Result.SUCCESS);assertFalse(p.deletable("own",true,true));
        p.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);assertFalse(p.deletable("own",true,true));
        p.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);assertTrue(p.deletable("own",true,true));
        assertFalse(p.deletable("own",false,true));assertFalse(p.deletable("own",true,false));
        p.saved("own",true);assertFalse(p.deletable("own",true,true));
    }
    @Test public void failuresReappearanceGenerationTopologyReconnectAndRestartResetAbsence() {
        for(var reason:CotCapturePolicy.Result.values())if(reason!=CotCapturePolicy.Result.SUCCESS){
            var p=twice();p.absent(Set.of(),true,reason);p.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);assertFalse(p.deletable("own",true,true));
        }
        var p=twice();p.absent(Set.of("own"),true,CotCapturePolicy.Result.SUCCESS);p.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);assertFalse(p.deletable("own",true,true));
        p=twice();p.resetContinuity();p.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);assertFalse(p.deletable("own",true,true));
        p=new CotCapturePolicy();p.saved("own",false);for(int i=0;i<4;i++)p.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);assertFalse(p.deletable("own",true,true));
        p.seen(Set.of("never-sent"));for(int i=0;i<4;i++)p.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);assertFalse(p.deletable("never-sent",true,true));
    }
    private static CotCapturePolicy twice(){var p=new CotCapturePolicy();p.saved("own",false);p.seen(Set.of("own"));for(int i=0;i<2;i++)p.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);return p;}
    @Test public void signalsDoNotPostponeIndependentPeriodicDeadlineAndSlowMainBacksOff(){
        var p=new CotCapturePolicy();assertTrue(p.begin(0,false));assertTrue(p.periodic());p.end(0,1,CotCapturePolicy.Result.SUCCESS,0);
        assertTrue(p.begin(1000,true));assertFalse(p.periodic());p.end(1000,1,CotCapturePolicy.Result.SUCCESS,0);assertEquals(5000,p.due());
        assertTrue(p.begin(5000,false));assertTrue(p.periodic());p.end(5000,0,CotCapturePolicy.Result.SUCCESS,8_000_001);assertEquals(20_000,p.delay());
    }
    @Test public void finalRecheckReappearanceResetsThreeAbsences(){
        var p=twice();p.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);
        assertFalse(p.deletable("own",false,true));
        p.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);assertFalse(p.deletable("own",true,true));
    }
}
