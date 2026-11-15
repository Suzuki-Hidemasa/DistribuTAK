// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;

public class CotCaptureBaselineTest {
    private static void save(CotCaptureBaseline b,CotCaptureBaseline.Candidate c){b.saved(CotRecord.record(c.uid,NOW,new byte[32],CotXml.inspect(c.xml).stale(),c.xml,0));}
    static final long NOW=1_800_000_000_000L;
    static byte[] xml(String uid,int point,long stale,int time){return ("<event uid=\""+uid+"\" time=\""+time+"\" start=\""+time+"\" stale=\""+Instant.ofEpochMilli(stale)+"\" how=\"m-g\"><point lat=\""+point+"\" lon=\"0\"/><detail><contact callsign=\"private-name\"/></detail></event>").getBytes(StandardCharsets.UTF_8);}
    @Test public void baselineAdvancesOnlyAfterSuccessfulSaveAndSameContentAndStaleIsSkipped(){
        var b=new CotCaptureBaseline();byte[] xml=xml("private-uid",0,NOW+60_000,0);
        try(var c=b.candidate("private-uid",xml,false)){assertNotNull(c);}
        try(var c=b.candidate("private-uid",xml,false)){assertNotNull(c);save(b,c);}
        assertNull(b.candidate("private-uid",xml,false));
        try(var c=b.candidate("private-uid",xml("private-uid",1,NOW+60_000,0),false)){assertNotNull(c);}
        assertNull(b.candidate("private-uid",xml,false));
    }
    @Test public void restoredSyncXmlSuppressesRestartAndShortenedStaleDoesNotCreateVersion(){
        var state=new SyncState(new byte[]{1},new byte[32]);byte[] xml=xml("private-uid",0,NOW+60_000,0);
        state.origin("private-uid",SyncState.Origin.LOCAL_CREATED);state.put(CotRecord.record("private-uid",NOW,new byte[32],NOW+60_000,xml,0),NOW);
        var b=new CotCaptureBaseline();b.restore(state);assertNull(b.candidate("private-uid",xml,false));
        assertNull(b.candidate("private-uid",xml("private-uid",0,NOW+CotXml.MAX_STALE_MILLIS+1,0),false));
        try(var c=b.candidate("private-uid",xml("private-uid",0,NOW+30_000,0),false)){assertNotNull(c);}
        try(var c=b.candidate("private-uid",xml("private-uid",1,NOW+60_000,0),false)){assertNotNull(c);}
        // timeの変更をstaleだけの延長と混同しない。
        try(var c=b.candidate("private-uid",xml("private-uid",0,NOW+120_000,1),false)){assertNotNull(c);}
    }
    @Test public void unchangedPositionDoesNotSendOrExtendStaleAndChangedPositionKeepsOldDeadline(){
        var b=new CotCaptureBaseline();
        try(var c=b.candidate("self",xml("self",0,NOW+60_000,0),true)){save(b,c);}
        assertNull(b.candidate("self",xml("self",0,NOW+120_000,1),true));
        try(var c=b.candidate("self",xml("self",1,NOW+120_000,2),true)){assertNotNull(c);assertEquals(NOW+60_000,CotXml.inspect(c.xml).stale());save(b,c);}
        assertNull(b.candidate("self",xml("self",1,NOW+240_000,3),true));
    }
    @Test public void twoContentChangesUseActualDurableDeadlineAcrossTimeAndRestart(){
        for(boolean longStale:new boolean[]{true,false}){
            var time=new java.util.concurrent.atomic.AtomicLong(NOW);
            var wall=new java.time.Clock(){
                public java.time.ZoneId getZone(){return java.time.ZoneOffset.UTC;}
                public java.time.Clock withZone(java.time.ZoneId zone){return this;}
                public java.time.Instant instant(){return java.time.Instant.ofEpochMilli(time.get());}
            };
            var initial=new SyncState(new byte[32],new byte[32]);
            final SyncState[] durable={initial};
            try(var sync=new CotSync(new byte[32],initial,wall,()->0,new CotSync.Store(){
                public void save(SyncState state){durable[0]=state;}
            },(peer,session,plain)->false,record->{},new java.security.SecureRandom(),0)){
                var baseline=new CotCaptureBaseline();
                long original=NOW+(longStale?CotXml.MAX_STALE_MILLIS+60_000:60_000);
                long first=0;
                for(int point=0;point<3;point++){
                    time.set(NOW+point*10_000);
                    try(var c=baseline.candidate("self",xml("self",point,original+point*10_000,point),true)){
                        assertNotNull(c);assertTrue(sync.publish(c.uid,c.xml,SyncState.Origin.LOCAL_POSITION));sync.flush();
                        var record=durable[0].get("self");baseline.saved(record);
                        if(point==0)first=record.stale();else assertTrue(record.stale()<=first);
                    }
                }
                assertNull(baseline.candidate("self",xml("self",2,original+90_000,9),true));
                var restored=new CotCaptureBaseline();restored.restore(durable[0]);
                assertNull(restored.candidate("self",xml("self",2,original+100_000,10),true));
                try(var changed=restored.candidate("self",xml("self",3,original+100_000,10),true)){
                    assertNotNull(changed);assertTrue(CotXml.inspect(changed.xml).stale()<=first);
                }
            }
        }
    }
    @Test public void fingerprintExclusionStartsEmptyAndWireHashRemainsFullXml(){
        byte[] a=xml("self",0,NOW+60_000,0),b=xml("self",0,NOW+60_000,1);
        assertFalse(java.util.Arrays.equals(CotCaptureXml.fingerprint(a,java.util.Set.of()),CotCaptureXml.fingerprint(b,java.util.Set.of())));
        assertArrayEquals(Crypto.blake2s(a),CotCaptureXml.fingerprint(a,java.util.Set.of()));
    }
    @Test public void genuinelyShortenedWireXmlRestoresWithoutManufacturingVersion(){
        byte[] original=xml("private-uid",0,NOW+CotXml.MAX_STALE_MILLIS+60_000,0),wire=CotXml.shortenStale(original,NOW);
        var state=new SyncState(new byte[]{1},new byte[32]);state.origin("private-uid",SyncState.Origin.LOCAL_CREATED);
        state.put(CotRecord.record("private-uid",NOW,new byte[32],CotXml.inspect(wire).stale(),wire,0),NOW);
        var b=new CotCaptureBaseline();b.restore(state);assertNull(b.candidate("private-uid",original,false));
        try(var c=b.candidate("private-uid",xml("private-uid",0,NOW+1,0),false)){assertNotNull(c);}
    }
}
