// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class UnknownAdministrationTest {
    final SessionManagerTest f=new SessionManagerTest();final byte[] b=AdminRecordsTest.key(70),c=AdminRecordsTest.key(71);
    AdminState state() {
        var s=new AdminState(f.group,Crypto.ed25519Public(f.admin),f.time,new InMemoryAdminRecordStore());
        var list=AdminRecords.list(AdminRecords.Kind.ADMINS,f.group,0,f.time.millis,List.of(Crypto.ed25519Public(f.admin),Crypto.ed25519Public(b),Crypto.ed25519Public(c)),f.admin);
        s.bootstrap(list,AdminRecords.signAnchor(list,f.admin));s.acceptRevocations(AdminRecords.initialRevocations(f.group,f.time.millis,f.admin));return s;
    }
    @Test void allUnknownKeysAreRemovedAtomicallyAfterSave() {
        try(var n=f.new Node(1)) {
            var state=state();try(var ga=new GroupAdministration(state,n.cert,n.identity,n.secret,f.admin,f.time,()->f.time.nanos,new java.security.SecureRandom())) {
                var p=ga.prepareRemoval(n.sessions,List.of(Crypto.ed25519Public(b),Crypto.ed25519Public(c)),true);p.reissue(x->{});var candidate=p.commit();
                assertThrows(IllegalStateException.class,()->p.publish(candidate,s->{throw new IllegalStateException();},x->fail()));assertEquals(3,state.administrators().entries().size());
                p.publish(candidate,s->{},x->{});assertEquals(1,state.administrators().entries().size());
                f.time.advance(60);assertFalse(p.expired());assertEquals(GroupAdministration.Phase.COMPLETE,p.phase());
                p.cancel();assertEquals(GroupAdministration.Phase.COMPLETE,p.phase());
            }
        }
    }
    @Test void subsetOfUnknownKeysIsNeverAcceptedAsBulkOperation() {
        try(var n=f.new Node(1);var ga=new GroupAdministration(state(),n.cert,n.identity,n.secret,f.admin,f.time,()->f.time.nanos,new java.security.SecureRandom())) {
            assertThrows(SecurityException.class,()->ga.prepareRemoval(n.sessions,List.of(Crypto.ed25519Public(b)),true));
        }
    }
    @Test void bindingChangesDuringConfirmationCancelWholeOperation() {
        try(var n=f.new Node(1)) {
            var state=state();try(var ga=new GroupAdministration(state,n.cert,n.identity,n.secret,f.admin,f.time,()->f.time.nanos,new java.security.SecureRandom())) {
                var p=ga.prepareRemoval(n.sessions,List.of(Crypto.ed25519Public(b),Crypto.ed25519Public(c)),true);p.reissue(x->{});
                var changed=new ArrayList<>(ga.bindings());var proof=AdminControl.keyProof(f.group,new byte[16],0,AdminRecordsTest.key(72),b);
                changed.replaceAll(x->Crypto.equal(x.administratorKey(),Crypto.ed25519Public(b))?AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode()):x);
                state.acceptAdministrators(AdminRecords.administrators(f.group,1,f.time.millis,changed,f.admin),v->fail());
                assertThrows(SecurityException.class,p::commit);assertEquals(GroupAdministration.Phase.CANCELLED,p.phase());assertEquals(3,state.administrators().entries().size());
            }
        }
    }
    @Test void candidateNotYetSavedStillExpiresDuringCommit() {
        try(var n=f.new Node(1)) {
            var state=state();try(var ga=new GroupAdministration(state,n.cert,n.identity,n.secret,f.admin,f.time,()->f.time.nanos,new java.security.SecureRandom())) {
                var p=ga.prepareRemoval(n.sessions,List.of(Crypto.ed25519Public(b),Crypto.ed25519Public(c)),true);p.reissue(x->{});var candidate=p.commit();
                assertEquals(GroupAdministration.Phase.COMMIT,p.phase());f.time.advance(60);assertTrue(p.expired());
                assertThrows(SecurityException.class,()->p.publish(candidate,s->fail(),x->fail()));assertEquals(3,state.administrators().entries().size());
            }
        }
    }
}
