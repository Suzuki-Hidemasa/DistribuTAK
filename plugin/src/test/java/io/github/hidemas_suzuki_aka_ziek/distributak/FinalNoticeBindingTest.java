// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class FinalNoticeBindingTest {
    @Test public void reservedBindingRejectsOtherContentsPeersSessionsAndGenerations()throws Exception {
        for(boolean local:new boolean[]{false,true})try(var p=new RecoveryTransportTest.Pair(false)){
            byte[] peer=p.b.id(),session=p.sa.sessionId(peer);long generation=p.sa.generation();
            var body=p.body(1,List.of(peer));var hooks=new CorePersistenceCoordinator.PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot snapshot){}
            };
            assertTrue(local?p.ca.persistLocalRevocations(body,hooks):p.ca.receiveRevocations(body,hooks));
            byte[] operation=p.ca.finalNoticeOperation(peer,session,generation);assertNotNull(operation);
            var page=ManagementPage.split(ManagementPage.Kind.REVOCATION,operation,p.a.groupId,body.encode(),1).get(0);
            assertTrue(p.ca.maySendFinalNotice(peer,session,generation,page.envelope()));
            assertFalse(p.ca.maySendFinalNotice(p.a.id(),session,generation,page.envelope()));
            assertFalse(p.ca.maySendFinalNotice(peer,new byte[16],generation,page.envelope()));
            assertFalse(p.ca.maySendFinalNotice(peer,session,generation+1,page.envelope()));
            var other=p.body(2,List.of(peer));
            var changed=ManagementPage.split(ManagementPage.Kind.REVOCATION,operation,p.a.groupId,other.encode(),1).get(0);
            assertFalse(p.ca.maySendFinalNotice(peer,session,generation,changed.envelope()));
            operation[0]^=1;
            var different=ManagementPage.split(ManagementPage.Kind.REVOCATION,operation,p.a.groupId,body.encode(),1).get(0);
            assertFalse(p.ca.maySendFinalNotice(peer,session,generation,different.envelope()));
            assertFalse(Arrays.equals(p.receiver.nextManagementOperation(),p.ca.finalNoticeOperation(peer,session,generation)));
            p.time.now=999;assertTrue(p.ca.maySendFinalNotice(peer,session,generation,page.envelope()));
            p.time.now=1000;assertFalse(p.ca.maySendFinalNotice(peer,session,generation,page.envelope()));
        }
    }
    @Test public void unreservedOperationCannotAuthorizeExactRevocationPage()throws Exception {
        try(var p=new RecoveryTransportTest.Pair(false)){
            byte[] peer=p.b.id(),session=p.sa.sessionId(peer);long generation=p.sa.generation();
            var body=p.body(1,List.of(peer));
            assertTrue(p.ca.receiveRevocations(body,new CorePersistenceCoordinator.PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot snapshot){
                    for(int n=0;n<3;n++){
                        byte[] operation=new byte[16];operation[0]=(byte)n;
                        var page=ManagementPage.split(ManagementPage.Kind.REVOCATION,operation,p.a.groupId,body.encode(),1).get(0);
                        assertFalse(p.ca.maySendFinalNotice(peer,session,generation,page.envelope()));
                    }
                }
            }));
        }
    }
}
