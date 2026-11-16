// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class InvitationMaterialsReviewTest {
    @Test void initialAnnouncementSurvivesV5ReconstructionWithoutChangingBytesOrRank(){
        var t=new GroupAdministrationTest();var f=t.f;
        try(var a=f.new Node(1);var ga=t.service(a,true)){
            f.time.advance(1);
            try(var materials=ga.invitationMaterials(f.psk,0,null)){assertNotNull(materials);}
            var first=a.state.announcement();var snapshot=a.state.snapshot();
            var disk=new InMemoryAdminRecordStore();disk.save(new AdminRecordStore.Snapshot(snapshot.records(),snapshot.anchorSignature(),snapshot.revocations(),snapshot.administratorVersion(),snapshot.revocationVersion()));
            f.time.advance(5);var restored=new AdminState(f.group,Crypto.ed25519Public(f.admin),f.time,disk);restored.restore();assertNull(restored.announcement());
            try(var gb=new GroupAdministration(restored,a.cert,a.identity,a.secret,f.admin,f.time,()->f.time.nanos,new java.security.SecureRandom());
                var materials=gb.invitationMaterials(f.psk,0,null)){
                assertTrue(Arrays.equals(first.encode(),restored.announcement().encode()));assertEquals(0,KeyAnnouncement.compare(first,restored.announcement()));
                assertNotNull(disk.load().announcement());
            }
        }
    }
    @Test void nonAdministratorCannotMakeInitialAnnouncement(){
        var t=new GroupAdministrationTest();var f=t.f;
        try(var a=f.new Node(1);var ga=t.service(a,false)){
            assertThrows(SecurityException.class,()->ga.invitationMaterials(f.psk,0,null));assertNull(a.state.announcement());
        }
    }
}
