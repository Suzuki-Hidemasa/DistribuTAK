// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class KeyRotationConvergenceTest {
    final AdminStateTest g=new AdminStateTest();final SessionManagerTest.Time time=new SessionManagerTest.Time();
    final CorePersistenceCoordinator.PersistenceHooks hooks=new CorePersistenceCoordinator.PersistenceHooks(){
        public void save(AdminRecordStore.Snapshot s){}
        public void saveKey(byte[] key,long version){}
    };
    class Peer implements AutoCloseable {
        final AdminState state=g.fresh();final byte[] identity,handshake,id;final AdminRecords.Record certificate;
        final SessionManager sessions;final KeyRotationCoordinator rotation;final RevocationUnion union;
        Peer(int n,byte[] administrator){
            identity=key(n);handshake=key(n+10);id=Crypto.blake2s(Crypto.ed25519Public(identity));
            certificate=AdminRecords.certificate(g.group,Crypto.ed25519Public(identity),Crypto.x25519Public(handshake),SignaturePurpose.identityProof(identity,g.group,Crypto.x25519Public(handshake)),g.now,g.b);
            sessions=new SessionManager(state,certificate,handshake,key(32),0,time,()->time.nanos,256);
            union=new RevocationUnion(g.group,new AdminStateTrust(state));union.add(state.revocations());
            rotation=new KeyRotationCoordinator(state,sessions,union,administrator,time,new MonotonicClock(()->time.nanos),new KeyRotationConflictTest.RandomWait(0));
        }
        public void close(){rotation.close();sessions.close();}
    }
    record Bundle(AdminRecords.Record revocations,KeyAnnouncement announcement,List<AdminRecords.Record> wraps){}
    Bundle bundle(Peer p){var value=p.rotation.publication();return new Bundle(value.revocations(),value.announcement(),value.envelopes());}
    void deliver(Bundle value,Peer to,boolean wrapFirst){
        var wrap=value.wraps.stream().filter(w->Crypto.equal(w.field(0),to.id)).findFirst().orElseThrow();
        if(wrapFirst)assertNotEquals(CorePersistenceCoordinator.KeyResult.APPLIED,to.rotation.persistence().applyGroupKey(value.announcement,wrap,to.id,to.handshake,to.sessions.keyVersion(),to.sessions.generation(),hooks));
        to.rotation.persistence().receiveRevocations(value.revocations,hooks);to.rotation.observe(value.announcement,value.revocations);
        to.rotation.persistence().applyGroupKey(value.announcement,wrap,to.id,to.handshake,to.sessions.keyVersion(),to.sessions.generation(),hooks);
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void sameVersionConflictsAgainAtNextVersionThenAllConvergeOnNewerSameKeyWithUnion(boolean reverse){
        try(var a=new Peer(100,g.a);var b=new Peer(101,g.b);var m=new Peer(102,g.a)){
            var recipients=List.of(a.certificate,b.certificate,m.certificate);byte[] x=key(80),y=key(81);
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,a.rotation.manual(List.of(x),recipients,hooks));
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,b.rotation.manual(List.of(y),recipients,hooks));
            var av1=bundle(a);var bv1=bundle(b);
            if(reverse){deliver(av1,b,false);deliver(bv1,a,true);}else{deliver(bv1,a,false);deliver(av1,b,true);}
            assertEquals(1,a.sessions.keyVersion());assertEquals(1,b.sessions.keyVersion());
            time.advance(5);
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,a.rotation.poll(recipients,hooks));
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,b.rotation.poll(recipients,hooks));
            var av2=bundle(a);var bv2=bundle(b);assertEquals(2,av2.announcement.keyVersion());assertEquals(2,bv2.announcement.keyVersion());
            assertFalse(Crypto.equal(av2.announcement.keyCommitment(),bv2.announcement.keyCommitment()));
            deliver(bv2,a,false);deliver(av2,b,true);time.advance(5);
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,a.rotation.poll(recipients,hooks));var finalValue=bundle(a);
            assertEquals(3,finalValue.announcement.keyVersion());deliver(finalValue,b,true);deliver(finalValue,m,true);
            assertEquals(KeyRotationCoordinator.Result.IDLE,b.rotation.poll(recipients,hooks));assertNull(b.rotation.publication());
            for(var p:List.of(a,b,m)){
                assertEquals(3,p.sessions.keyVersion());assertTrue(p.union.contains(x));assertTrue(p.union.contains(y));
                assertArrayEquals(finalValue.announcement.keyCommitment(),p.state.announcement().keyCommitment());
            }
            time.advance(5);a.sessions.rememberPeer(b.certificate);b.sessions.rememberPeer(a.certificate);
            var second=b.sessions.receive(a.sessions.start(b.id).packet());
            var confirm=a.sessions.receive(second.outbound().get(0).packet());b.sessions.receive(confirm.outbound().get(0).packet());
            assertTrue(a.sessions.isEstablished(b.id));assertTrue(b.sessions.isEstablished(a.id));
        }
    }
    @Test void remainingAdministratorConsolidatesAfterOtherAdministratorStops(){
        try(var a=new Peer(100,g.a);var b=new Peer(101,g.b);var m=new Peer(102,g.a)){
            var recipients=List.of(a.certificate,b.certificate,m.certificate);
            a.rotation.manual(List.of(key(80)),recipients,hooks);b.rotation.manual(List.of(key(81)),recipients,hooks);
            var av1=bundle(a);var bv1=bundle(b);deliver(av1,b,false);deliver(bv1,m,true);deliver(av1,m,false);a.rotation.close();
            time.advance(5);assertEquals(KeyRotationCoordinator.Result.PUBLISHED,b.rotation.poll(recipients,hooks));
            var merged=bundle(b);deliver(merged,m,true);
            assertEquals(2,m.sessions.keyVersion());assertTrue(m.union.contains(key(80)));assertTrue(m.union.contains(key(81)));
            assertArrayEquals(b.state.announcement().keyCommitment(),m.state.announcement().keyCommitment());
        }
    }
    @Test void revocationSignedByAStaysAfterARemovalAndBReissuesWithoutA(){
        try(var a=new Peer(100,g.a);var b=new Peer(101,g.b)){
            var recipients=List.of(a.certificate,b.certificate);a.rotation.manual(List.of(key(80)),recipients,hooks);deliver(bundle(a),b,false);
            var remove=g.admins(1,g.now,List.of(g.bp),g.b);b.state.acceptAdministrators(remove,v->fail());
            b.rotation.persistence().receiveRevocations(g.revocations(2,g.now,List.of(key(81)),g.b),hooks);
            assertThrows(SecurityException.class,()->b.rotation.observe(bundle(a).announcement,b.state.revocations()));
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,b.rotation.poll(recipients,hooks));
            var merged=bundle(b);assertTrue(merged.revocations.hasEntry(key(80)));assertTrue(merged.revocations.hasEntry(key(81)));
            assertTrue(Crypto.equal(g.bp,merged.announcement.signer()));assertTrue(merged.announcement.keyVersion()>1);
        }
    }
}
