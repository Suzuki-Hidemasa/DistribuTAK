// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class UnknownRemovalTest {
    static LanControllerHarness.Disk disk()throws Exception {
        var disk=new LanControllerHarness.Disk(LanControllerHarness.freePort());disk.enableSix();
        try(var group=LanGroup.create(disk.port(),LanControllerHarness.CLOCK,new java.security.SecureRandom())) {
            ManagementScreenTest.addUnknown(group,2);disk.save(group);
        }
        return disk;
    }
    static Object ask(LanControllerHarness h){
        h.controller.removeUnknown(h.controller.ticket());h.drain();assertNotNull(h.ui.confirmation);
        assertEquals(2,h.ui.confirmationCount);return h.ui.confirmation;
    }
    @Test public void allUnknownEntriesAreRemovedInOneSavedList()throws Exception {
        try(var h=new LanControllerHarness(disk())) {
            Object token=ask(h);var group=LanBehaviourWiringTest.group(h);long before=group.state.administrators().version();
            h.controller.confirmUnknown(token);h.drain();
            assertEquals(1,group.state.administrators().bindings().size());
            assertEquals(before+1,group.state.administrators().version());
            try(var restored=h.disk.load(LanControllerHarness.CLOCK)){assertEquals(1,restored.state.administrators().bindings().size());}
            assertTrue(h.ui.last.text.contains("すべて外しました"));
        }
    }
    @Test public void cancelKeepsEveryEntryAndDoesNotSave()throws Exception {
        try(var h=new LanControllerHarness(disk())) {
            ask(h);long before=LanBehaviourWiringTest.group(h).saveSeq;
            h.controller.cancelManagement();h.drain();
            assertEquals(3,LanBehaviourWiringTest.group(h).state.administrators().bindings().size());
            assertEquals(before,LanBehaviourWiringTest.group(h).saveSeq);assertNull(h.ui.confirmation);
        }
    }
    @Test public void changedScreenCancelsWholeRemoval()throws Exception {
        try(var h=new LanControllerHarness(disk())) {
            Object token=ask(h);h.ui.epoch++;
            h.controller.confirmUnknown(token);h.drain();
            assertEquals(3,LanBehaviourWiringTest.group(h).state.administrators().bindings().size());assertNull(h.ui.confirmation);
        }
    }
    @Test public void changedListCancelsWholeRemoval()throws Exception {
        try(var h=new LanControllerHarness(disk())) {
            Object token=ask(h);ManagementScreenTest.addUnknown(h,1);
            h.controller.confirmUnknown(token);h.drain();
            assertEquals(4,LanBehaviourWiringTest.group(h).state.administrators().bindings().size());assertNull(h.ui.confirmation);
        }
    }
    @Test public void duplicateConfirmationDoesNotWriteAgain()throws Exception {
        try(var h=new LanControllerHarness(disk())) {
            Object token=ask(h);h.controller.confirmUnknown(token);h.drain();long after=LanBehaviourWiringTest.group(h).saveSeq;
            h.controller.confirmUnknown(token);h.drain();assertEquals(after,LanBehaviourWiringTest.group(h).saveSeq);
        }
    }
    @Test public void noUnknownDoesNotOfferAnEmptyRemoval()throws Exception {
        try(var h=new LanControllerHarness()) {
            h.create();h.controller.removeUnknown(h.controller.ticket());h.drain();assertEquals(0,h.ui.confirmations);
            assertEquals(1,LanBehaviourWiringTest.group(h).state.administrators().bindings().size());
        }
    }
    @Test public void changedEndpointGenerationCancelsWholeRemoval()throws Exception {
        try(var h=new LanControllerHarness(disk())) {
            Object token=ask(h);
            ((java.util.concurrent.atomic.AtomicLong)LanControllerHarness.field(h.controller,"generation")).incrementAndGet();
            h.controller.confirmUnknown(token);h.drain();
            assertEquals(3,LanBehaviourWiringTest.group(h).state.administrators().bindings().size());assertNull(h.ui.confirmation);
        }
    }
    @Test public void confirmationDoesNotSaveBeforeUserAccepts()throws Exception {
        try(var h=new LanControllerHarness(disk())) {
            long before=LanBehaviourWiringTest.group(h).saveSeq;ask(h);h.tick();
            assertEquals(before,LanBehaviourWiringTest.group(h).saveSeq);assertEquals(3,LanBehaviourWiringTest.group(h).state.administrators().bindings().size());
        }
    }
    @Test public void generatedUnknownValuesAreAbsentFromScreenAndLogs()throws Exception {
        try(var h=new LanControllerHarness(disk())) {
            ask(h);String publicText=h.ui.last.text+String.join("",h.logs);
            for(var binding:LanBehaviourWiringTest.group(h).state.administrators().bindings())if(binding.state()==AdminBinding.State.UNKNOWN){
                byte[] value=binding.administratorKey();
                assertFalse(publicText.contains(java.util.Base64.getEncoder().encodeToString(value)));
                assertFalse(publicText.contains(hex(value)));assertFalse(publicText.contains(hex(Crypto.blake2s(value))));
            }
            assertEquals(Object.class,h.ui.confirmation.getClass());
            assertEquals("Management preparation",LanControllerHarness.field(h.controller,"preparation").toString());
        }
    }
    static String hex(byte[] value){var text=new StringBuilder();for(byte b:value)text.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return text.toString();}
}
