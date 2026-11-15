// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.*;

public class CotCaptureStartupTest {
    static final String TYPE="test-type";
    record Evidence(boolean parentSelf,boolean archiveExplicitTrue,boolean howOne,boolean creationConfirmed,boolean reloaded){}
    static final class Port implements CotCaptureReconcile.Port {
        final Map<String,Evidence> proofs=new HashMap<>();final Set<String> forbidden=new HashSet<>();
        final List<String> captured=new ArrayList<>(),deleted=new ArrayList<>();
        public boolean owns(String uid,String type){var e=proofs.get(uid);return TYPE.equals(type)&&e!=null&&e.parentSelf&&e.archiveExplicitTrue&&e.howOne&&e.creationConfirmed&&!e.reloaded;}
        public boolean forbidden(String uid){return forbidden.contains(uid);}
        public boolean absent(String uid){return true;}
        public void capture(String uid){captured.add(uid);}
        public void remove(String uid){deleted.add(uid);}
        void prove(String uid){proofs.put(uid,new Evidence(true,true,true,true,false));}
    }
    static CotCaptureReconcile reconcile(Port p){return new CotCaptureReconcile(new CotCapturePolicy(),p,Set.of(TYPE));}
    static void success(CotCaptureReconcile r,Map<String,String> items){r.complete(items,true,CotCapturePolicy.Result.SUCCESS);}
    @Test public void baselineAndPreBaselineDisappearedUidsCannotBeCreatedChangedOrDeleted(){
        var p=new Port();p.prove("before");p.prove("during");var r=reconcile(p);
        r.beforeBaseline("during");success(r,Map.of("before",TYPE));
        success(r,Map.of("before",TYPE,"during",TYPE));r.saved("before",false);r.saved("during",false);
        for(int i=0;i<4;i++)success(r,Map.of());assertTrue(p.captured.isEmpty());assertTrue(p.deleted.isEmpty());
    }
    @Test public void firstSuccessfulScanOnlyEstablishesBaselineAfterFailures(){
        var p=new Port();p.prove("partial");var r=reconcile(p);
        r.complete(Map.of("partial",TYPE),true,CotCapturePolicy.Result.INTERRUPTED);assertFalse(r.baselined());
        r.complete(Map.of(),true,CotCapturePolicy.Result.LIMIT);assertFalse(r.baselined());
        success(r,Map.of());assertTrue(r.baselined());success(r,Map.of("partial",TYPE));assertTrue(p.captured.isEmpty());
    }
    @Test public void lateReloadAndUnprovenMetadataAreExcludedAndProductionTableStaysEmpty(){
        var p=new Port();var r=reconcile(p);success(r,Map.of());
        p.proofs.put("late",new Evidence(true,true,true,true,true));
        p.proofs.put("default-archive",new Evidence(true,false,true,true,false));
        p.proofs.put("no-creation",new Evidence(true,true,true,false,false));
        p.proofs.put("wrong-parent",new Evidence(false,true,true,true,false));
        p.proofs.put("wrong-how",new Evidence(true,true,false,true,false));
        var present=new HashMap<String,String>();for(String uid:p.proofs.keySet())present.put(uid,TYPE);success(r,present);assertTrue(p.captured.isEmpty());
        var closed=new CotCaptureReconcile(new CotCapturePolicy(),p);success(closed,Map.of());p.prove("fresh");success(closed,Map.of("fresh",TYPE));assertTrue(p.captured.isEmpty());assertTrue(CotCaptureReconcile.CONFIRMED_CREATED_TYPES.isEmpty());
    }
    @Test public void freshProofAndTestTableAllowAdditionChangeAndOnlySavedPeriodicDeletion(){
        var p=new Port();var r=reconcile(p);success(r,Map.of());p.prove("fresh");p.prove("never-saved");p.prove("wrong-type");
        success(r,Map.of("fresh",TYPE,"never-saved",TYPE,"wrong-type","other"));assertEquals(Set.of("fresh","never-saved"),new HashSet<>(p.captured));
        r.saved("fresh",false);success(r,Map.of("fresh",TYPE));assertEquals(2,Collections.frequency(p.captured,"fresh"));
        for(int i=0;i<5;i++)r.complete(Map.of(),false,CotCapturePolicy.Result.SUCCESS);assertTrue(p.deleted.isEmpty());
        for(int i=0;i<2;i++)success(r,Map.of());assertTrue(p.deleted.isEmpty());success(r,Map.of());assertEquals(List.of("fresh"),p.deleted);
        r.saved("fresh",true);success(r,Map.of());assertEquals(1,p.deleted.size());
        var immediate=new Port();var next=reconcile(immediate);success(next,Map.of());immediate.prove("fast");success(next,Map.of("fast",TYPE));next.saved("fast",false);
        for(int i=0;i<3;i++)success(next,Map.of());assertEquals(List.of("fast"),immediate.deleted);
    }
    @Test public void forbiddenFenceImportedReceivedAndExternalNeverAcquireOwnership(){
        var p=new Port();var r=reconcile(p);success(r,Map.of());var present=new HashMap<String,String>();
        for(String uid:List.of("self","fence","imported","received","external")){p.prove(uid);p.forbidden.add(uid);present.put(uid,TYPE);}
        success(r,present);for(String uid:present.keySet())r.saved(uid,false);for(int i=0;i<4;i++)success(r,Map.of());assertTrue(p.captured.isEmpty());assertTrue(p.deleted.isEmpty());
    }
    @Test public void baselineMemoryOverflowClosesOnlyCreatedCaptureForWholeGeneration(){
        var p=new Port();var r=reconcile(p);for(int i=0;i<4097;i++)r.beforeBaseline("pre-"+i);
        success(r,Map.of());assertTrue(r.limited());p.prove("fresh");success(r,Map.of("fresh",TYPE));assertTrue(p.captured.isEmpty());assertTrue(p.deleted.isEmpty());assertTrue(r.retained()<=4096);
        var next=reconcile(p);success(next,Map.of());success(next,Map.of("fresh",TYPE));assertEquals(List.of("fresh"),p.captured);
    }
    @Test public void ownershipOverflowAndIncompleteScanCreateAndDeleteNothing(){
        var p=new Port();var r=reconcile(p);success(r,Map.of());var present=new LinkedHashMap<String,String>();
        for(int i=0;i<4097;i++){String uid="new-"+i;p.prove(uid);present.put(uid,TYPE);}
        success(r,present);assertTrue(r.limited());assertTrue(p.captured.isEmpty());assertTrue(p.deleted.isEmpty());assertTrue(r.retained()<=4096);
        for(var result:CotCapturePolicy.Result.values())if(result!=CotCapturePolicy.Result.SUCCESS){
            var q=new Port();var s=reconcile(q);success(s,Map.of());q.prove("fresh");success(s,Map.of("fresh",TYPE));s.saved("fresh",false);success(s,Map.of("fresh",TYPE));q.captured.clear();
            success(s,Map.of());success(s,Map.of());s.complete(Map.of("new",TYPE),true,result);assertTrue(q.captured.isEmpty());success(s,Map.of());success(s,Map.of());assertTrue(q.deleted.isEmpty());success(s,Map.of());assertEquals(List.of("fresh"),q.deleted);
        }
    }
    @Test public void restartBaselineNeverRestoresOwnershipFromSavedRecord(){
        var p=new Port();p.prove("old");var r=reconcile(p);r.saved("old",false);success(r,Map.of("old",TYPE));for(int i=0;i<4;i++)success(r,Map.of());assertTrue(p.captured.isEmpty());assertTrue(p.deleted.isEmpty());
    }
}
