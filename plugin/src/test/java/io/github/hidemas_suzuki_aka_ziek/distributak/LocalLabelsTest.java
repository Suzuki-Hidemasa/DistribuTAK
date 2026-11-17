// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class LocalLabelsTest {
    @Test public void directionalControlsAreRejectedBeforeSaving()throws Exception{
        for(int point:new int[]{0x202a,0x202b,0x202c,0x202d,0x202e,0x2066,0x2067,0x2068,0x2069,0x200e,0x200f,0x061c})
            save(text()+new String(Character.toChars(point)),false);
    }
    private String text(){return UUID.randomUUID().toString().replace("-","").substring(0,12);}
    private void save(String label,boolean accepted)throws Exception {
        var f=new VersionSixStorageTest();
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());
            var administration=new GroupAdministration(group.state,group.certificate,group.identitySecret,group.handshakeSecret,
                    group.administratorSecret,StorageGroupTest.CLOCK,()->0,new java.security.SecureRandom())){
            f.storage().save(group);long sequence=group.saveSeq;
            var labels=Map.of(Base64.getEncoder().encodeToString(group.certificate.field(0)),label);
            if(accepted){
                f.storage().saveDirectory(group,administration.directory(),labels);
                try(var restored=f.storage().load(StorageGroupTest.CLOCK)){
                    assertTrue(label.equals(restored.management.aliases.values().iterator().next()));
                }
            }else{
                Exception failure=assertThrows(Exception.class,()->f.storage().saveDirectory(group,administration.directory(),labels));
                assertFalse(failure.toString().contains(label));assertEquals(sequence,group.saveSeq);
                try(var restored=f.storage().load(StorageGroupTest.CLOCK)){assertTrue(restored.management.aliases.isEmpty());}
            }
        }
    }
    @Test public void generatedLabelSurvivesExistingStorage()throws Exception{save(text(),true);}
    @Test public void scalarBoundarySurvivesStorage()throws Exception{save(new String(Character.toChars(0x1f340)).repeat(32),true);}
    @Test public void scalarOverflowIsRejected()throws Exception{save(text().substring(0,1).repeat(33),false);}
    @Test public void byteOverflowIsRejected()throws Exception{save(new String(Character.toChars(0x1f340)).repeat(33),false);}
    @Test public void isolatedHighSurrogateIsRejected()throws Exception{save(text()+"\ud800",false);}
    @Test public void isolatedLowSurrogateIsRejected()throws Exception{save(text()+"\udc00",false);}
    @Test public void lineBreakIsRejected()throws Exception{save(text()+"\n",false);}
    @Test public void controlCharacterIsRejected()throws Exception{save(text()+"\u0001",false);}
    @Test public void emptyLabelIsRejected()throws Exception{
        var f=new VersionSixStorageTest();
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());
            var administration=new GroupAdministration(group.state,group.certificate,group.identitySecret,group.handshakeSecret,
                    group.administratorSecret,StorageGroupTest.CLOCK,()->0,new java.security.SecureRandom())){
            f.storage().save(group);
            assertThrows(Exception.class,()->f.storage().saveDirectory(group,administration.directory(),
                    Map.of(Base64.getEncoder().encodeToString(group.certificate.field(0)),"")));
        }
    }
}
