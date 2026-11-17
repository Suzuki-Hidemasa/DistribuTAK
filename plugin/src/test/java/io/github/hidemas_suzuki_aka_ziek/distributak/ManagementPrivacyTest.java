// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;

public class ManagementPrivacyTest {
    @Test public void confirmationAndLocalStateDoNotPrintGeneratedSecrets()throws Exception{
        try(var h=new LanControllerHarness(ManualRotationScreenTest.disk())){
            var group=LanBehaviourWiringTest.group(h);h.controller.rotateKey(h.controller.ticket());h.drain();assertNotNull(h.ui.confirmation);
            String text=h.ui.last.text+String.join("",h.logs)+LanControllerHarness.field(h.controller,"managementPending").toString()+group+group.management;
            for(byte[] value:List.of(group.identitySecret,group.handshakeSecret,group.administratorSecret,group.groupKey,group.groupId,group.id())){
                assertFalse(text.contains(Base64.getEncoder().encodeToString(value)));assertFalse(text.contains(UnknownRemovalTest.hex(value)));
            }
            assertEquals(Object.class,h.ui.confirmation.getClass());
        }
    }
    @Test public void choiceAndValidationNeverPrintGeneratedLabels(){
        String label=NamingScreenTest.label();var choice=new LanController.NamedChoice(new Object(),label);
        assertFalse(choice.toString().contains(label));
        var failure=assertThrows(IllegalArgumentException.class,()->LocalLabels.validate(label+"\n"));
        assertFalse(failure.toString().contains(label));
        var labels=new HashMap<String,String>();labels.put(UUID.randomUUID().toString(),label);labels.put(UUID.randomUUID().toString(),label);
        failure=assertThrows(IllegalArgumentException.class,()->LocalLabels.validate(labels));assertFalse(failure.toString().contains(label));
    }
    @Test public void labelOnlyStorageKeepsManagementVersionsAndReservations()throws Exception{
        var f=new VersionSixStorageTest();
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());
            var service=new GroupAdministration(group.state,group.certificate,group.identitySecret,group.handshakeSecret,
                    group.administratorSecret,group.clock,()->0,new java.security.SecureRandom())){
            f.storage().save(group);var before=group.management;long key=group.keyVersion;
            f.storage().saveDirectory(group,service.directory(),Map.of(Base64.getEncoder().encodeToString(group.certificate.field(0)),NamingScreenTest.label()));
            assertTrue(ManagementState.sameSnapshot(before.snapshot,group.management.snapshot));
            assertTrue(ManagementState.sameSubjects(before.union,group.management.union));assertEquals(key,group.keyVersion);
            assertTrue(group.management.reservations.isEmpty());assertTrue(group.management.outgoing.isEmpty());
        }
    }
    private List<byte[]> sensitive(UnknownOnlineTest.Pair p)throws Exception{
        var result=new ArrayList<byte[]>();
        for(var h:List.of(p.a,p.m)){
            var group=UnknownOnlineTest.group(h);
            for(byte[] value:List.of(group.identitySecret,group.handshakeSecret,group.groupKey,group.groupId,group.id(),group.certificate.field(0),group.certificate.field(1)))result.add(value.clone());
            if(group.administratorSecret!=null&&group.administratorSecret.length>0)result.add(group.administratorSecret.clone());
            result.add(Crypto.blake2s(group.state.administrators().signedBytes()));
        }
        return result;
    }
    private void inspect(UnknownOnlineTest.Pair p,List<byte[]> before)throws Exception{
        before.addAll(sensitive(p));
        assertFalse(p.a.ui.managementTexts.isEmpty());assertFalse(p.a.ui.choiceLabels.isEmpty());
        String output=String.join("",p.a.ui.managementTexts)+String.join("",p.m.ui.managementTexts)+String.join("",p.a.ui.choiceLabels)
                +String.join("",p.m.ui.choiceLabels)+String.join("",p.a.logs)+String.join("",p.m.logs)+p.a.ui.last.text+p.m.ui.last.text;
        for(byte[] value:before){assertFalse(output.contains(Base64.getEncoder().encodeToString(value)));assertFalse(output.contains(UnknownRemovalTest.hex(value)));Crypto.wipe(value);}
        String ordinary=String.join("",p.a.logs)+String.join("",p.m.logs)+p.a.ui.last.text+p.m.ui.last.text;
        for(String label:p.a.ui.choiceLabels)assertFalse(ordinary.contains(label));
    }
    @Test public void grantDialogsAndChoicesExcludeGeneratedSensitiveValues()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            AdministrationButtonsTest.prepare(p);var values=sensitive(p);
            p.a.controller.confirmManagement(AdministrationButtonsTest.select(p,LanController.ManagementAction.OFFER));p.a.drain();
            LanProofRenewalTest.until(()->UnknownOnlineTest.group(p.m).isAdministrator(),p.a,p.m);inspect(p,values);
        }
    }
    @Test public void revocationDialogsAndChoicesExcludeGeneratedSensitiveValues()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            AdministrationButtonsTest.prepare(p);var values=sensitive(p);
            p.a.controller.confirmManagement(AdministrationButtonsTest.select(p,LanController.ManagementAction.REVOKE));p.a.drain();inspect(p,values);
        }
    }
    @Test public void individualRemovalDialogsAndChoicesExcludeGeneratedSensitiveValues()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            ManagementReviewFixTest.promoted(p);var values=sensitive(p);
            p.a.controller.confirmManagement(AdministrationButtonsTest.select(p,LanController.ManagementAction.REMOVE));p.a.drain();
            LanProofRenewalTest.until(()->UnknownOnlineTest.group(p.a).state.administrators().entries().size()==1,p.a,p.m);inspect(p,values);
        }
    }
    @Test public void namingDialogsAllowOnlyTheSavedLabel()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            AdministrationButtonsTest.prepare(p);var values=sensitive(p);
            p.a.controller.chooseManagement(p.a.controller.ticket(),LanController.ManagementAction.RENAME);p.a.drain();
            p.a.controller.selectManagement(p.a.ui.choiceToken,p.a.ui.choices.get(0).token);p.a.drain();String label=NamingScreenTest.label();
            p.a.controller.setLabel(p.a.ui.input,label);p.a.drain();
            assertTrue(p.a.ui.managementTexts.stream().anyMatch(text->text.contains(label)));
            p.a.controller.confirmManagement(p.a.ui.confirmation);p.a.drain();inspect(p,values);
        }
    }
}
