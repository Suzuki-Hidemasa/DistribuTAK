// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.TransferResources;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ManagementPersistenceAckTest {
    final ManagementPageAssemblerTest.Time time=new ManagementPageAssemblerTest.Time();
    final byte[] group=new byte[32],peer=ManagementPageTest.bytes(32,1),session=new byte[16];
    final ManagementPageAssembler assembler=new ManagementPageAssembler(group,time,new TransferResources(),true);
    ManagementPage page(int operation){byte[] id=new byte[16];id[0]=(byte)operation;return ManagementPage.split(ManagementPage.Kind.REVOCATION,id,group,new byte[]{1},0).get(0);}
    @Test void completedAssemblyNeedsExplicitPersistenceConfirmation(){
        var page=page(1);var result=assembler.receive(peer,session,1,page);
        assertNotNull(result.completed());assertNull(result.ack());
        assertNull(assembler.receive(peer,session,1,page).ack());
        assertNotNull(assembler.confirm(peer,session,1,page));
        assertTrue(assembler.receive(peer,session,1,page).ack().complete());
    }
    @Test void confirmationCannotCrossPeerSessionGenerationOrOperation(){
        var page=page(1);assembler.receive(peer,session,1,page);
        assertNull(assembler.confirm(new byte[32],session,1,page));
        assertNull(assembler.confirm(peer,ManagementPageTest.bytes(16,2),1,page));
        assertNull(assembler.confirm(peer,session,2,page));assertNull(assembler.confirm(peer,session,1,page(2)));
        assertNull(assembler.receive(peer,session,1,page).ack());
    }
    @Test void confirmationDoesNotRefreshOriginalRetentionDeadline(){
        var page=page(1);assembler.receive(peer,session,1,page);time.now+=239_999;
        assertNotNull(assembler.confirm(peer,session,1,page));time.now++;
        assertNull(assembler.confirm(peer,session,1,page));
    }
    @Test void eightCompletionRecordsAreSharedBetweenPendingAndConfirmed(){
        var first=page(1);assembler.receive(peer,session,1,first);assembler.confirm(peer,session,1,first);
        for(int i=2;i<=9;i++)assembler.receive(peer,session,1,page(i));
        assertNull(assembler.confirm(peer,session,1,first));
    }
    @Test void queuedPageCannotExtendProgressToProcessingTime(){
        var pages=ManagementPage.split(ManagementPage.Kind.REVOCATION,new byte[16],group,new byte[2050],0);
        assembler.receiveAt(peer,session,1,pages.get(0),time.millis());
        time.now=20_000;assembler.receiveAt(peer,session,1,pages.get(1),2_000);
        time.now=32_000;assertEquals(ManagementPageAssembler.Status.REJECTED,assembler.receiveAt(peer,session,1,pages.get(2),31_999).status());
    }
    @Test void forgottenPeerReleasesReservationAndCompletionRecord(){
        var page=page(1);assembler.receive(peer,session,1,page);assembler.confirm(peer,session,1,page);
        assembler.forget(peer);assertNull(assembler.confirm(peer,session,1,page));
        assertNotNull(assembler.receive(peer,session,2,page).completed());
    }
    @Test void receivedOwnsAndWipesPlaintextCopy()throws Exception{
        byte[] borrowed={1,2,3};var received=new SessionManager.Received(peer,borrowed,java.util.List.of(),session);
        var field=received.getClass().getDeclaredField("plaintext");field.setAccessible(true);byte[] owned=(byte[])field.get(received);
        received.close();assertArrayEquals(new byte[3],owned);assertArrayEquals(new byte[]{1,2,3},borrowed);
    }

    @Test void rejectedCompletedObjectCannotLaterBeConfirmed(){
        var page=page(1);assembler.receive(peer,session,1,page);assembler.reject(peer,session,1,page);
        assertNull(assembler.confirm(peer,session,1,page));assertEquals(ManagementPageAssembler.Status.REJECTED,assembler.receive(peer,session,1,page).status());
    }
    @Test void discardedAssemblyWipesOwnedBuffer()throws Exception{
        var pages=ManagementPage.split(ManagementPage.Kind.REVOCATION,new byte[16],group,new byte[2050],0);
        assembler.receive(peer,session,1,pages.get(0));var field=ManagementPageAssembler.class.getDeclaredField("assemblies");field.setAccessible(true);
        var assembly=((java.util.Map<?,?>)field.get(assembler)).values().iterator().next();var buffer=assembly.getClass().getDeclaredField("buffer");buffer.setAccessible(true);
        byte[] owned=(byte[])buffer.get(assembly);owned[0]=1;assembler.forget(peer);assertArrayEquals(new byte[owned.length],owned);
    }

}
