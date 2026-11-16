// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class RevocationConflictTest {
    final CorePersistenceCoordinatorTest t=new CorePersistenceCoordinatorTest();
    final SessionManagerTest f=t.f;
    AdminRecords.Record list(long version,byte[]... subjects){
        return AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,version,f.time.millis(),List.of(subjects),f.admin);
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void xAndYSurviveBothArrivalOrdersEvenWhenWinnerOmitsOne(boolean reverse){
        try(var a=f.new Node(1);var x=f.new Node(2);var y=f.new Node(3)){
            var c=t.coordinator(a);var low=list(1,x.id);var high=list(2,y.id);
            assertTrue(c.receiveRevocations(reverse?high:low,t.hooks(()->{})));
            assertTrue(c.receiveRevocations(reverse?low:high,t.hooks(()->{})));
            assertTrue(c.isRevoked(x.id));assertTrue(c.isRevoked(y.id));
            assertArrayEquals(high.encode(),a.state.revocations().encode());
            assertThrows(SecurityException.class,()->a.state.verifyCertificate(x.cert,x.cert.field(1)));
            assertThrows(SecurityException.class,()->a.sessions.rememberPeer(x.cert));
        }
    }
    @Test void losingListWithKnownSubjectsDoesNotSaveAgain(){
        try(var a=f.new Node(1)){
            var c=t.coordinator(a);assertTrue(c.receiveRevocations(list(2,key(80)),t.hooks(()->{})));
            assertFalse(c.receiveRevocations(list(1,key(80)),t.hooks(()->fail())));
        }
    }
    @Test void restartingReplaysLosingListsAndPreservesUnion()throws Exception{
        try(var a=f.new Node(1);var x=f.new Node(2);var y=f.new Node(3)){
            var c=t.coordinator(a);c.receiveRevocations(list(2,y.id),t.hooks(()->{}));
            assertTrue(c.receiveRevocations(list(1,x.id),t.hooks(()->{})));
            var store=(AdminRecordStore)SessionManagerTest.field(a.state,"store");
            var restored=new AdminState(f.group,Crypto.ed25519Public(f.admin),f.time,store);restored.restore();
            try(var sessions=new SessionManager(restored,a.cert,a.secret,f.psk,0,f.time,()->f.time.nanos,256)){
                var union=t.union(a);var after=new CorePersistenceCoordinator(restored,sessions,union,f.time,t.deadlines());
                assertTrue(after.isRevoked(x.id));assertTrue(after.isRevoked(y.id));
                assertThrows(SecurityException.class,()->restored.verifyCertificate(x.cert,x.cert.field(1)));
            }
        }
    }
    @Test void acceptedRevocationSurvivesSignerRemovalAndNewListFromRemovedSignerIsRefused(){
        var g=new AdminStateTest();var store=new InMemoryAdminRecordStore();var state=g.fresh(store);
        byte[] subject=Crypto.blake2s(Crypto.ed25519Public(g.identity));
        assertTrue(state.acceptRevocations(g.revocations(2,g.now,List.of(subject),g.a)));
        state.acceptAdministrators(g.admins(1,g.now,List.of(g.bp),g.b),v->fail());
        assertTrue(state.acceptRevocations(g.revocations(3,g.now,List.of(),g.b)));
        assertThrows(SecurityException.class,()->state.acceptRevocations(g.revocations(4,g.now,List.of(key(90)),g.a)));
        var restored=new AdminState(g.group,g.ap,g.clock,store);restored.restore();
        assertThrows(SecurityException.class,()->restored.verifyCertificate(g.certificate(g.b,g.now,SignaturePurpose.identityProof(g.identity,g.group,Crypto.x25519Public(g.handshake))),Crypto.x25519Public(g.handshake)));
    }
}
