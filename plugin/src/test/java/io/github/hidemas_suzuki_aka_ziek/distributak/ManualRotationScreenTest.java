// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class ManualRotationScreenTest {
    static void assertRotationNotice(String text){
        assertTrue(text.contains("最大180秒"));assertTrue(text.contains("5秒に1回"));
        assertTrue(text.contains("新しい鍵で接続し直します"));
    }
    @Test public void confirmationExplainsExistingRotationLimits()throws Exception{
        try(var h=new LanControllerHarness(disk())){
            ask(h);assertRotationNotice(h.ui.managementTexts.get(h.ui.managementTexts.size()-1));
        }
    }
    static LanControllerHarness.Disk disk()throws Exception{
        var disk=new LanControllerHarness.Disk(LanControllerHarness.freePort());disk.enableSix();
        try(var group=LanGroup.create(disk.port(),LanControllerHarness.CLOCK,new java.security.SecureRandom())){disk.save(group);}
        return disk;
    }
    static Object ask(LanControllerHarness h){
        h.controller.rotateKey(h.controller.ticket());h.drain();assertNotNull(h.ui.confirmation);return h.ui.confirmation;
    }
    @Test public void rotationWaitsForConfirmationAndSavesOnce()throws Exception{
        try(var h=new LanControllerHarness(disk())){
            var group=LanBehaviourWiringTest.group(h);long before=group.keyVersion;
            Object token=ask(h);h.tick();assertEquals(before,group.keyVersion);
            h.controller.confirmManagement(token);h.drain();assertEquals(before+1,group.keyVersion);
            h.controller.confirmManagement(token);h.drain();assertEquals(before+1,group.keyVersion);
            try(var restored=h.disk.load(LanControllerHarness.CLOCK)){assertEquals(before+1,restored.keyVersion);}
        }
    }
    @Test public void cancellationMakesOldConfirmationInert()throws Exception{
        try(var h=new LanControllerHarness(disk())){
            var group=LanBehaviourWiringTest.group(h);long before=group.keyVersion;Object token=ask(h);
            h.controller.cancelManagement();h.drain();h.controller.confirmManagement(token);h.drain();assertEquals(before,group.keyVersion);
        }
    }
    @Test public void screenChangeCancelsRotation()throws Exception{
        try(var h=new LanControllerHarness(disk())){
            var group=LanBehaviourWiringTest.group(h);long before=group.keyVersion;Object token=ask(h);
            h.ui.epoch++;h.controller.confirmManagement(token);h.drain();assertEquals(before,group.keyVersion);
        }
    }
    @Test public void generationChangeCancelsRotation()throws Exception{
        try(var h=new LanControllerHarness(disk())){
            var group=LanBehaviourWiringTest.group(h);long before=group.keyVersion;Object token=ask(h);
            ((java.util.concurrent.atomic.AtomicLong)LanControllerHarness.field(h.controller,"generation")).incrementAndGet();
            h.controller.confirmManagement(token);h.drain();assertEquals(before,group.keyVersion);
        }
    }
    @Test public void secondPressDoesNotReplaceConfirmation()throws Exception{
        try(var h=new LanControllerHarness(disk())){
            Object token=ask(h);h.controller.rotateKey(h.controller.ticket());h.drain();assertSame(token,h.ui.confirmation);
        }
    }
    @Test public void localCertificateChangeCancelsRotation()throws Exception{
        try(var h=new LanControllerHarness(disk())){
            var group=LanBehaviourWiringTest.group(h);long before=group.keyVersion;Object token=ask(h);
            group.certificate=io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.certificate(
                    group.groupId,group.certificate.field(0),group.certificate.field(1),
                    io.github.hidemas_suzuki_aka_ziek.distributak.core.SignaturePurpose.identityProof(group.identitySecret,group.groupId,group.certificate.field(1)),
                    group.certificate.issuedAt()+1,group.administratorSecret);
            h.controller.confirmManagement(token);h.drain();assertEquals(before,group.keyVersion);
        }
    }
}
