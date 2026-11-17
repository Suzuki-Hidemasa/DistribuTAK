// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;
public class PreparationReceiveTest {
    @Test public void connectedTransportSecurityFailureIsNotSuppressed()throws Exception {
        try(var p=new UnknownOnlineTest.Pair()) {
            var group=UnknownOnlineTest.group(p.a);
            var administration=new GroupAdministration(group.state,group.certificate,group.identitySecret,group.handshakeSecret,group.administratorSecret,p.wall,()->System.nanoTime()+p.a.offset.get(),new java.security.SecureRandom());
            var sessions=(SessionManager)LanControllerHarness.field(p.a.controller,"managedSessions");
            administration.directory().saved(UnknownOnlineTest.group(p.m).certificate);
            try(var helper=new AdministrationPreparation(administration,sessions,java.util.List.of(group.urlAdmin),false,new AdministrationPreparation.Port(){
                public void own(AdminRecords.Record certificate){try{p.a.disk.saveLocalRenewal(group,certificate);p.a.endpoint().updateLocalCertificate(certificate);}catch(Exception e){throw new AssertionError("保存に失敗しました");}}
                public void issued(AdminRecords.Record certificate){}
                public void send(byte[] peer,RenewalMessage message){throw new SecurityException("送信を拒否しました");}
                public void commit(GroupAdministration.Preparation prepared,GroupAdministration.Candidate candidate){throw new AssertionError("保存する段階ではありません");}
            })) {
                helper.begin();assertNotNull(sessions.verifiedSession(UnknownOnlineTest.group(p.m).id()));
                assertThrows(SecurityException.class,helper::poll);
            }
        }
    }
    @Test public void nextPreparationUsesCertificateUpdatedThroughNormalRenewal()throws Exception {
        try(var p=new UnknownOnlineTest.Pair()) {
            var a=UnknownOnlineTest.group(p.a);var m=UnknownOnlineTest.group(p.m);
            request(p,m.certificate);
            var previous=(GroupAdministration)LanControllerHarness.field(p.m.controller,"incomingAdministration");assertNotNull(previous);
            p.wall.now.incrementAndGet();
            var certificate=AdminRecords.certificate(m.groupId,Crypto.ed25519Public(m.identitySecret),Crypto.x25519Public(m.handshakeSecret),
                    SignaturePurpose.identityProof(m.identitySecret,m.groupId,Crypto.x25519Public(m.handshakeSecret)),p.wall.millis(),a.administratorSecret);
            var apply=LanController.class.getDeclaredMethod("applyRenewal",AdminRecords.Record.class);apply.setAccessible(true);
            assertTrue((boolean)apply.invoke(p.m.controller,certificate));
            ((ProofRequests)LanControllerHarness.field(p.m.controller,"proofRequests")).forget(a.id());
            var second=request(p,certificate);
            var current=(GroupAdministration)LanControllerHarness.field(p.m.controller,"incomingAdministration");
            assertTrue(java.util.Arrays.equals(certificate.encode(),current.certificate().encode()));
            assertFalse(previous==current);
            assertNotNull(((ProofRequests)LanControllerHarness.field(p.m.controller,"proofRequests")).match(a.id(),p.m.endpoint().sessionId(a.id()),second));
        }
    }
    static RenewalMessage request(UnknownOnlineTest.Pair p,AdminRecords.Record base)throws Exception {
        var a=UnknownOnlineTest.group(p.a);byte[] request=new byte[16];new java.security.SecureRandom().nextBytes(request);
        var message=RenewalMessage.request(base,request,Crypto.ed25519Public(a.administratorSecret),RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,new byte[16]);
        var method=LanController.class.getDeclaredMethod("receiveProofRenewal",byte[].class,byte[].class,byte[].class);method.setAccessible(true);
        method.invoke(p.m.controller,a.id(),p.m.endpoint().sessionId(a.id()),message.encode());
        return message;
    }
}
