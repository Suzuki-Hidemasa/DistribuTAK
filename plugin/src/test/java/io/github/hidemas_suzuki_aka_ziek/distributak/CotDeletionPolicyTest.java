// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.Set;
public class CotDeletionPolicyTest {
    @Test public void onlyThreeIndependentSuccessesWithFinalAbsenceAndOwnershipAllowDeletion(){
        var policy=new CotCapturePolicy();policy.saved("item",false);policy.seen(Set.of("item"));
        policy.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);policy.absent(Set.of(),false,CotCapturePolicy.Result.SUCCESS);
        assertFalse(policy.deletable("item",true,true));policy.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);
        assertFalse(policy.deletable("item",true,true));policy.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);
        assertFalse(policy.deletable("item",true,false));assertTrue(policy.deletable("item",true,true));
    }
    @Test public void failureReappearanceResetAndRestartDiscardPreviousAbsence(){
        for(int reason=0;reason<6;reason++){
            var policy=new CotCapturePolicy();policy.saved("item",false);policy.seen(Set.of("item"));
            for(int i=0;i<2;i++)policy.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);
            if(reason<3)policy.absent(Set.of(),true,CotCapturePolicy.Result.values()[reason+1]);
            else if(reason==3)policy.seen(Set.of("item"));else if(reason==4)policy.resetContinuity();
            else{policy=new CotCapturePolicy();policy.saved("item",false);policy.seen(Set.of("item"));}
            for(int i=0;i<2;i++)policy.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);
            assertFalse(policy.deletable("item",true,true));policy.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);assertTrue(policy.deletable("item",true,true));
        }
    }
    @Test public void finalReappearanceAndNeverSentPreventDeletion(){
        var policy=new CotCapturePolicy();policy.saved("item",false);policy.seen(Set.of("item"));
        for(int i=0;i<3;i++)policy.absent(Set.of(),true,CotCapturePolicy.Result.SUCCESS);
        assertFalse(policy.deletable("item",false,true));assertFalse(policy.deletable("never-sent",true,true));
    }
}
