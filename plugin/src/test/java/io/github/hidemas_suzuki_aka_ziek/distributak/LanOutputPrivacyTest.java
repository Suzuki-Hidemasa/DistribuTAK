// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;

public class LanOutputPrivacyTest {
    @Test public void createdAndRestoredScreenExcludeGroupAndLocalIdentifiers()throws Exception{
        LanControllerHarness.Disk saved;
        try(var h=new LanControllerHarness()){
            h.create();saved=h.disk;
            assertTrue(h.ui.last.text.contains("相手: 未登録"));
            inspectScreens(h);
        }
        try(var h=new LanControllerHarness(saved)){
            assertTrue(h.ui.last.member);inspectScreens(h);
        }
    }

    @Test public void joinedConnectedAndRestoredScreensExcludeAllIdentifiers()throws Exception{
        LanControllerHarness.Disk saved;
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()){
            connect(admin,member);saved=member.disk;
            assertTrue(admin.ui.last.member);assertTrue(member.ui.last.member);
            inspectRegisteredPeer(admin);inspectRegisteredPeer(member);
            inspectScreens(admin);inspectScreens(member);
        }
        try(var h=new LanControllerHarness(saved)){
            assertTrue(h.ui.last.member);inspectRegisteredPeer(h);inspectScreens(h);
        }
    }

    @Test public void actualReceiveLogsExcludeBothPeersAndKeepCounts()throws Exception{
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()){
            connect(admin,member);
            for(int count=1;count<=2;count++){
                admin.controller.sendTest();member.controller.sendTest();
                final int expected=count;
                LanControllerHarness.until(()->receipts(admin)==expected&&receipts(member)==expected,admin,member);
            }
            for(var receiver:List.of(admin,member)){
                for(var source:List.of(admin,member))inspect(receiver.logs,LanBehaviourWiringTest.group(source).id(),"receive log");
                for(int count=1;count<=2;count++){
                    String prefix="LAN_TEST_RX count="+count;
                    String entry=receiver.logs.stream().filter(text->text.startsWith(prefix)).findFirst().orElseThrow();
                    assertTrue("receive log must contain only its kind and count",entry.matches("LAN_TEST_RX count=[0-9]+"));
                }
            }
        }
    }

    private static long receipts(LanControllerHarness h){return h.logs.stream().filter(text->text.startsWith("LAN_TEST_RX ")).count();}

    private static void connect(LanControllerHarness admin,LanControllerHarness member)throws Exception{
        admin.create();member.beginJoin(admin);
        LanControllerHarness.until(()->member.ui.last.member&&admin.logs.contains("LAN_MEMBER_ISSUED"),admin,member);
        inspectGroupStatus(admin);inspectGroupStatus(member);
        admin.controller.connect();member.controller.connect();
        LanControllerHarness.until(()->admin.logs.stream().anyMatch(text->text.startsWith("LAN_ESTABLISHED"))
                &&member.logs.stream().anyMatch(text->text.startsWith("LAN_ESTABLISHED")),admin,member);
    }

    private static void inspectScreens(LanControllerHarness h)throws Exception{
        var group=LanBehaviourWiringTest.group(h);
        inspectGroupStatus(h);
        assertFalse("screen recording must not be empty",h.ui.statusTexts.isEmpty());
        inspect(h.ui.statusTexts,group.groupId,"group screen");
        inspect(h.ui.statusTexts,group.id(),"local screen");
        if(group.peerCertificate!=null)inspect(h.ui.statusTexts,Crypto.blake2s(group.peerCertificate.field(0)),"peer screen");
    }

    private static void inspectGroupStatus(LanControllerHarness h){
        assertTrue("screen must show group membership",h.ui.last.text.contains("グループ: 参加済み"));
    }

    private static void inspectRegisteredPeer(LanControllerHarness h)throws Exception{
        assertNotNull("connected peer certificate must be present",LanBehaviourWiringTest.group(h).peerCertificate);
        assertTrue("screen must show peer registration",h.ui.last.text.contains("相手: 登録済み"));
    }

    private static void inspect(List<String> recorded,byte[] generated,String kind){
        String full=UnknownRemovalTest.hex(generated),shortened=full.substring(0,8);
        for(String text:recorded){
            assertFalse(kind+" contains a full identifier",text.contains(full));
            assertFalse(kind+" contains a short identifier",text.contains(shortened));
        }
    }
}
