// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.time.Clock;
import java.security.SecureRandom;
import java.util.function.LongSupplier;

/**
 * 管理DHTの有限保管を保存済みの失効と検証後の観察へ結ぶ。鍵は適用しない。
 * <p>
 * Connects bounded management DHT storage to durable revocations and validated observation, without applying keys.
 */
final class ManagedDhtExchange implements AutoCloseable,ManagedDependencies {
    private final LanGroup group;
    private final CorePersistenceCoordinator coordinator;
    private final LanRuntime.Storage storage;
    private final DhtRecordBudget budget=new DhtRecordBudget();
    private final GroupAdministration administration;
    private final KeyRotationCoordinator rotation;
    private final ManagedDhtStore store;
    private boolean closed;
    ManagedDhtExchange(LanGroup group,SessionManager sessions,CorePersistenceCoordinator coordinator,RevocationUnion union,
            Clock wall,Clock deadlines,LongSupplier nanos,SecureRandom random,LanRuntime.Storage storage){
        this.group=group;this.coordinator=coordinator;this.storage=storage;
        administration=group.isAdministrator()?new GroupAdministration(group.state,group.certificate,group.identitySecret,
                group.handshakeSecret,group.administratorSecret,wall,nanos,random):null;
        rotation=administration==null?null:administration.rotations(sessions,union,deadlines,coordinator);
        if(rotation!=null&&group.management!=null)group.management.restoreRotation(group,rotation);
        store=new ManagedDhtStore(group.groupId,wall,deadlines,new AdminStateTrust(group.state),union,
                peer->sessions.verifiedSession(peer)!=null&&!coordinator.isRevoked(peer),budget,this,this::accepted,this::allowed);
    }
    boolean allowed(){return !closed&&coordinator.permits(CorePersistenceCoordinator.Operation.DHT_WRITE);}
    ManagedDhtStore store(){return store;}
    DhtRecordBudget budget(){return budget;}
    TransferResources resources(){return coordinator.transferResources();}
    KeyRotationCoordinator rotation(){return rotation;}
    private void accepted(ManagedDhtRecord value){
        coordinator.execute(CorePersistenceCoordinator.Operation.DHT_WRITE,()->{});
        if(value.kind()==DhtKeys.LATEST_REVOCATIONS){
            coordinator.receiveRevocations(value.inner(),storage.persistenceHooks(group));
            if(coordinator.state()!=CorePersistenceCoordinator.State.RUNNING)throw new IllegalStateException("Management persistence stopped");
        }else if(value.kind()==DhtKeys.KEY_ANNOUNCEMENT){
            var announcement=value.announcement();
            var body=store.revocations(announcement.revocationVersion(),announcement.revocationDigest());
            if(body==null)throw new SecurityException("Missing announcement body");
            coordinator.execute(CorePersistenceCoordinator.Operation.KEY_ANNOUNCEMENT,()->{
                group.state.verifyAnnouncement(announcement,body);
                if(rotation!=null)rotation.observe(announcement,body);
            });
        }
    }
    @Override public KeyAnnouncement announcement(byte[] digest){
        var value=group.state.announcement();
        return value!=null&&Crypto.equal(Crypto.blake2s(value.signedBytes()),digest)?value:null;
    }
    @Override public AdminRecords.Record revocations(long version,byte[] digest){
        for(byte[] encoded:group.state.snapshot().records()){
            var value=AdminRecords.decode(encoded);
            if(value.kind()==AdminRecords.Kind.REVOCATIONS&&value.version()==version
                    &&Crypto.equal(Crypto.blake2s(value.signedBytes()),digest))return value;
        }
        var value=group.state.revocations();
        return value.version()==version&&Crypto.equal(Crypto.blake2s(value.signedBytes()),digest)?value:null;
    }
    @Override public void close(){
        if(closed)return;closed=true;store.clear();if(administration!=null)administration.close();
    }
}
