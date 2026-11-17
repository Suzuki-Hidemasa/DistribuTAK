// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class MembershipSaverTest {
    final GroupAdministrationTest setup=new GroupAdministrationTest();
    final SessionManagerTest f=setup.f;
    void cleared(byte[] bytes){assertNotNull(bytes);for(byte value:bytes)assertEquals(0,value);}
    @Test void matchingProofReachesSaveBeforeActivationAndIsWiped(){
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=setup.service(a,true);var gb=setup.service(b,false)){
            setup.connect(a,b,ga,gb);var request=gb.request(b.sessions,a.id);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),request);
            var approved=ga.approve(a.sessions,b.id);var candidate=gb.received(approved.administrators(),approved.revocations());
            var held=new AtomicReference<byte[]>();var calls=new AtomicInteger();
            gb.persist(candidate,(snapshot,secret)->{
                held.set(secret);calls.incrementAndGet();assertEquals(32,secret.length);assertFalse(gb.isAdministrator());
                assertTrue(Crypto.equal(request.administratorKey(),Crypto.ed25519Public(secret)));
            },value->assertTrue(gb.isAdministrator()));
            assertTrue(gb.isAdministrator());cleared(held.get());assertEquals(1,calls.get());
            assertThrows(SecurityException.class,()->gb.persist(candidate,(snapshot,secret)->calls.incrementAndGet(),value->fail()));
            assertEquals(1,calls.get());
        }
    }
    @Test void failedSaveWipesCopyAndLeavesAuthorityInactive(){
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=setup.service(a,true);var gb=setup.service(b,false)){
            setup.connect(a,b,ga,gb);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),gb.request(b.sessions,a.id));
            var approved=ga.approve(a.sessions,b.id);var candidate=gb.received(approved.administrators(),approved.revocations());
            var held=new AtomicReference<byte[]>();
            assertThrows(IllegalStateException.class,()->gb.persist(candidate,(snapshot,secret)->{
                held.set(secret);assertEquals(32,secret.length);throw new IllegalStateException("保存前に中断しました");
            },value->fail()));
            cleared(held.get());assertFalse(gb.isAdministrator());assertEquals(1,b.state.administrators().version());
        }
    }
    @Test void ordinarySaveReceivesNoSecret(){
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=setup.service(a,true);var gb=setup.service(b,false)){
            setup.connect(a,b,ga,gb);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),gb.request(b.sessions,a.id));
            ga.persist(ga.approve(a.sessions,b.id),(snapshot,secret)->assertEquals(0,secret.length),value->{});
        }
    }
    @Test void expiredProofDoesNotExportOrActivateSecret(){
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=setup.service(a,true);var gb=setup.service(b,false)){
            setup.connect(a,b,ga,gb);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),gb.request(b.sessions,a.id));
            var approved=ga.approve(a.sessions,b.id);f.time.advance(601);
            gb.persist(gb.received(approved.administrators(),approved.revocations()),(snapshot,secret)->assertEquals(0,secret.length),value->{});
            assertFalse(gb.isAdministrator());
        }
    }
    @Test void publicationFailureStopsAfterSaveAndWipesCopy(){
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=setup.service(a,true);var gb=setup.service(b,false)){
            setup.connect(a,b,ga,gb);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),gb.request(b.sessions,a.id));
            var approved=ga.approve(a.sessions,b.id);var held=new AtomicReference<byte[]>();
            assertThrows(IllegalStateException.class,()->gb.persist(gb.received(approved.administrators(),approved.revocations()),
                    (snapshot,secret)->held.set(secret),value->{throw new IllegalStateException("保存後に中断しました");}));
            cleared(held.get());assertThrows(IllegalStateException.class,gb::expire);assertFalse(gb.isAdministrator());
            assertEquals(2,b.state.administrators().version());
        }
    }
    @Test void staleCandidateDoesNotInvokeSaver(){
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=setup.service(a,true);var gb=setup.service(b,false)){
            setup.connect(a,b,ga,gb);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),gb.request(b.sessions,a.id));
            var approved=ga.approve(a.sessions,b.id);var candidate=gb.received(approved.administrators(),approved.revocations());
            gb.persist(candidate,snapshot->{},value->{});
            assertThrows(SecurityException.class,()->gb.persist(candidate,(snapshot,secret)->fail(),value->fail()));
        }
    }
    @Test void savedApprovalThatExpiresDuringSaveStopsFurtherOperations(){
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=setup.service(a,true);var gb=setup.service(b,false)){
            setup.connect(a,b,ga,gb);ga.receive(a.sessions,b.id,a.sessions.sessionId(b.id),gb.request(b.sessions,a.id));
            var candidate=ga.approve(a.sessions,b.id);var saved=new AtomicBoolean();
            assertThrows(SecurityException.class,()->ga.persist(candidate,(snapshot,secret)->{
                assertEquals(0,secret.length);saved.set(true);f.time.advance(601);
            },value->fail()));
            assertTrue(saved.get());assertThrows(IllegalStateException.class,ga::expire);assertFalse(ga.isAdministrator());
        }
    }
    private byte[] pendingSecret(GroupAdministration service)throws Exception{
        var field=GroupAdministration.class.getDeclaredField("pending");field.setAccessible(true);
        Object pending=((java.util.Map<?,?>)field.get(service)).values().iterator().next();
        var secret=pending.getClass().getDeclaredField("secret");secret.setAccessible(true);return ((byte[])secret.get(pending)).clone();
    }
    private void mismatchedBinding(boolean otherMember)throws Exception{
        try(var a=f.new Node(1);var b=f.new Node(2);var c=f.new Node(3);var ga=setup.service(a,true);var gb=setup.service(b,false)){
            setup.connect(a,b,ga,gb);var request=gb.request(b.sessions,a.id);byte[] secret=pendingSecret(gb);
            try{
                byte[] number=request.requestId();number[0]^=1;
                var proof=AdminControl.keyProof(f.group,number,request.baseVersion(),otherMember?c.identity:b.identity,secret);
                assertTrue(proof.verifyPossessionProof());assertTrue(Crypto.equal(proof.administratorKey(),request.administratorKey()));
                var binding=AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode());assertTrue(binding.verifies(f.group,2));
                var bindings=new java.util.ArrayList<>(ga.bindings());bindings.add(binding);
                var list=AdminRecords.administrators(f.group,2,f.time.millis,bindings,f.admin);
                var calls=new AtomicInteger();
                gb.persist(gb.received(list,b.state.revocations()),(snapshot,copy)->{calls.incrementAndGet();assertEquals(0,copy.length);},value->{});
                assertEquals(1,calls.get());assertFalse(gb.isAdministrator());
            }finally{Crypto.wipe(secret);}
        }
    }
    @Test void bindingForAnotherMemberDoesNotExportSecret()throws Exception{mismatchedBinding(true);}
    @Test void differentPossessionProofDoesNotExportSecret()throws Exception{mismatchedBinding(false);}
    @Test void sameVersionDoesNotExportSecret(){
        try(var a=f.new Node(1);var b=f.new Node(2);var ga=setup.service(a,true);var gb=setup.service(b,false)){
            setup.connect(a,b,ga,gb);var request=gb.request(b.sessions,a.id);var bindings=new java.util.ArrayList<>(ga.bindings());
            var binding=AdminBinding.bound(request.administratorKey(),request.memberId(),request.encode());assertTrue(binding.verifies(f.group,1));bindings.add(binding);
            var list=AdminRecords.administrators(f.group,1,f.time.millis+1,bindings,f.admin);var calls=new AtomicInteger();
            gb.persist(gb.received(list,b.state.revocations()),(snapshot,copy)->{calls.incrementAndGet();assertEquals(0,copy.length);},value->{});
            assertEquals(1,calls.get());assertFalse(gb.isAdministrator());
        }
    }
}
