// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class PersistingManagementKindsTest {
    @Test public void rosterSummaryAndAnnouncementShareExistingInboxAndAreWipedOnClose()throws Exception{
        try(var pair=new NormalRevocationControllerTest.Pair()){
            var h=pair.m;var group=NormalRevocationControllerTest.group(h);
            byte[] peer=NormalRevocationControllerTest.group(pair.a).id(),session=h.endpoint().sessionId(peer);
            var receiver=NormalRevocationControllerTest.receiver(h);
            NormalRevocationControllerTest.coordinator(h).saveUnchanged(()->{
                for(var kind:new ManagementPage.Kind[]{ManagementPage.Kind.ROSTER,ManagementPage.Kind.ROSTER_SUMMARY,ManagementPage.Kind.ANNOUNCEMENT}){
                    receiver.receive(peer,session,ManagementPage.split(kind,new byte[16],group.groupId,new byte[]{1},0).get(0).envelope());
                }
                assertEquals(3,uncheckedSize(h));
            });
            var packets=NormalRevocationControllerTest.queued(h);
            h.controller.close();h.drain();
            for(var packet:packets)assertArrayEquals(new byte[packet.wire.length],packet.wire);
        }
    }
    private static int uncheckedSize(LanControllerHarness h){
        try{return NormalRevocationControllerTest.inbox(h).size();}catch(Exception failure){throw new AssertionError(failure);}
    }
}
