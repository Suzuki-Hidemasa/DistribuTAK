// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
public class CotPositionCaptureTest {
    @Test public void positionProductionBytesArePassedOnceAndWiped(){
        for(int i=0;i<3;i++){
            byte[] xml=CotCaptureBaselineTest.xml("position",i,CotCaptureBaselineTest.NOW+60_000,i==2?1:0),expected=xml.clone();
            var sent=new ArrayList<byte[]>();CotPositionCapture.capture(()->xml,bytes->sent.add(bytes.clone()));
            assertEquals(1,sent.size());assertArrayEquals(expected,sent.get(0));assertArrayEquals(new byte[xml.length],xml);
        }
    }
    @Test public void unchangedPositionKeepsDeadlineAndOnlyChangedPositionCreatesVersion(){
        long base=CotCaptureBaselineTest.NOW;long[] time={base},mono={0};
        var wall=new java.time.Clock(){public java.time.ZoneId getZone(){return java.time.ZoneOffset.UTC;}public java.time.Clock withZone(java.time.ZoneId zone){return this;}public java.time.Instant instant(){return java.time.Instant.ofEpochMilli(time[0]);}};
        var baseline=new CotCaptureBaseline();var state=new SyncState(new byte[32],new byte[32]);var versions=new ArrayList<byte[]>();
        try(var sync=new CotSync(new byte[32],state,wall,()->mono[0],s->{},(p,s,b)->false,r->{},new java.security.SecureRandom(),0)){
            int[] points={0,0,1,1};for(int i=0;i<points.length;i++){
                time[0]=base+i*10_000;mono[0]=i*10_000_000_000L;byte[] xml=CotCaptureBaselineTest.xml("self",points[i],base+60_000+i*10_000,i);
                CotPositionCapture.capture(()->xml,bytes->{try(var candidate=baseline.candidate("self",bytes,true)){
                    if(candidate==null)return;assertTrue(sync.publish(candidate.uid,candidate.xml,SyncState.Origin.LOCAL_POSITION));sync.flush();
                    var record=sync.snapshot().get("self");baseline.saved(record);versions.add(record.xml());assertEquals(base+60_000,record.stale());
                }});
            }
        }
        assertEquals(2,versions.size());
    }
}
