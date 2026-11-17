// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecordTest.*;
import static org.junit.jupiter.api.Assertions.*;

class ManagedDhtBudgetTest {
    @Test void discoveryAndManagedCopiesShareCountBytesAndReleaseOnClear(){
        var f=new ManagedDhtStoreTest.Fixture();var discovery=DiscoveryStore.shared(GROUP,f.wall,()->0,id->false,f.budget);
        var r=DiscoveryRecord.issue(GROUP,secret(10),Crypto.x25519Public(secret(11)),new byte[]{(byte)192,0,2,1},50000,1,NOW);
        assertEquals(DiscoveryStatus.ACCEPTED,discovery.putOwn(r.nodeId(),r.encode()));
        var m=f.rev(1,1);f.store.accept(null,m,false);assertEquals(2,f.budget.count());assertEquals(r.encode().length+m.encode().length,f.budget.bytes());
        f.store.clear();assertEquals(1,f.budget.count());discovery.clear();assertEquals(0,f.budget.count());assertEquals(0,f.budget.bytes());
    }
    @Test void expiredDiscoveryCopiesReleaseCapacityBeforeManagedAdmission(){
        var f=new ManagedDhtStoreTest.Fixture();var discovery=DiscoveryStore.shared(GROUP,f.wall,()->0,id->false,f.budget);
        var r=DiscoveryRecord.issue(GROUP,secret(10),Crypto.x25519Public(secret(11)),new byte[]{(byte)192,0,2,1},50000,1,NOW);
        discovery.putOwn(r.nodeId(),r.encode());f.now=r.expiresAt();
        var m=ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,GROUP,secret(1),revocations(1,f.now,0),1,0,Crypto.blake2s(f.state.administrators().signedBytes()),f.now,null);
        assertEquals(DhtWire.StoreStatus.ACCEPTED,f.store.accept(null,m,false));assertEquals(1,f.budget.count());assertEquals(0,discovery.size());
    }
    @Test void sharedRecordCeilingCannotBeExceededAndReplacementDoesNotUseAnotherSlot(){
        var budget=new DhtRecordBudget();for(int i=0;i<DhtRecordBudget.MAX_RECORDS;i++)assertTrue(budget.replace(0,1));
        assertFalse(budget.replace(0,1));assertTrue(budget.replace(1,2));assertEquals(DhtRecordBudget.MAX_RECORDS,budget.count());
        assertTrue(budget.replace(1,0));assertTrue(budget.replace(0,1));
    }
}
