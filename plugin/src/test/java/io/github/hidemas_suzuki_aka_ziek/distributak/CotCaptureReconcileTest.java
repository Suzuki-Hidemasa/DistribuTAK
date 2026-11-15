// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.*;

public class CotCaptureReconcileTest {
    @Test public void productionOwnershipTableIsEmptyAndRestoredSavedUidCannotGetPermission(){
        assertTrue(CotCaptureReconcile.CONFIRMED_CREATED_TYPES.isEmpty());
        var r=CotCaptureReconcile.closed(new CotCapturePolicy(),uid->false,uid->true);
        r.saved("old",false);r.complete(Map.of("old","private-type"),true,CotCapturePolicy.Result.SUCCESS);
        for(int i=0;i<5;i++)r.complete(Map.of(),true,CotCapturePolicy.Result.SUCCESS);
    }
    @Test public void unknownNeverPublishesOrMarksExternalAndIncompleteScansCannotCreateOrDelete(){
        var policy=new CotCapturePolicy();var sent=new ArrayList<String>();
        var port=new CotCaptureReconcile.Port(){
            public boolean owns(String uid,String type){return false;}
            public boolean forbidden(String uid){return false;}
            public boolean absent(String uid){return true;}
            public void capture(String uid){sent.add(uid);}
            public void remove(String uid){sent.add(uid);}
        };
        var r=new CotCaptureReconcile(policy,port);r.saved("old",false);r.complete(Map.of("old","type"),true,CotCapturePolicy.Result.SUCCESS);
        for(var failure:CotCapturePolicy.Result.values())if(failure!=CotCapturePolicy.Result.SUCCESS)r.complete(Map.of("new","type"),true,failure);
        for(int i=0;i<4;i++)r.complete(Map.of("new","type"),true,CotCapturePolicy.Result.SUCCESS);
        assertTrue(sent.isEmpty());
    }
    @Test public void onlyPersistedOwnedUidSeenThisSessionIsDeletedOnceAfterThreePeriodicAbsences(){
        var policy=new CotCapturePolicy();var sent=new ArrayList<String>();var deleted=new ArrayList<String>();
        var port=new CotCaptureReconcile.Port(){
            public boolean owns(String uid,String type){return uid.equals("own")||uid.equals("never-sent");}
            public boolean forbidden(String uid){return uid.equals("received");}
            public boolean absent(String uid){return true;}
            public void capture(String uid){sent.add(uid);}
            public void remove(String uid){deleted.add(uid);}
        };
        var r=new CotCaptureReconcile(policy,port,Set.of("type"));r.complete(Map.of(),true,CotCapturePolicy.Result.SUCCESS);
        r.complete(Map.of("own","type","never-sent","type","received","type"),true,CotCapturePolicy.Result.SUCCESS);
        r.saved("own",false);r.saved("not-seen",false);
        r.complete(Map.of("own","type","never-sent","type","received","type"),true,CotCapturePolicy.Result.SUCCESS);
        assertEquals(Set.of("own","never-sent"),new HashSet<>(sent));
        for(int i=0;i<10;i++)r.complete(Map.of(),false,CotCapturePolicy.Result.SUCCESS);assertTrue(deleted.isEmpty());
        for(int i=0;i<2;i++)r.complete(Map.of(),true,CotCapturePolicy.Result.SUCCESS);assertTrue(deleted.isEmpty());
        r.complete(Map.of(),true,CotCapturePolicy.Result.SUCCESS);assertEquals(List.of("own"),deleted);
        r.saved("own",true);r.complete(Map.of(),true,CotCapturePolicy.Result.SUCCESS);assertEquals(1,deleted.size());
    }
}
