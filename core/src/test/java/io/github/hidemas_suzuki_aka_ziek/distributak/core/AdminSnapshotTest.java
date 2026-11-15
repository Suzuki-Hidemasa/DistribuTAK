// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AdminSnapshotTest {
    @Test void bootstrapAndJoinedSnapshotsRestoreAndRejectModifiedRecords() throws Exception {
        var fixture=new UdpEndpointTest();
        try(var node=fixture.new Node(1,"127.0.0.1")) {
            var snapshot=node.state.snapshot();var store=new InMemoryAdminRecordStore();store.save(snapshot);
            var restored=new AdminState(fixture.group,Crypto.ed25519Public(fixture.admin),fixture.clock,store);
            restored.restore();restored.verifyCertificate(node.cert,Crypto.x25519Public(node.secret));
            byte[] anchor=snapshot.anchorSignature();anchor[0]^=1;
            assertArrayEquals(node.state.snapshot().anchorSignature(),snapshot.anchorSignature());
            var joined=new AdminState(fixture.group,Crypto.ed25519Public(fixture.admin),fixture.clock,new InMemoryAdminRecordStore());
            joined.join(List.of(node.state.administrators()),snapshot.anchorSignature(),node.state.revocations());
            assertArrayEquals(snapshot.anchorSignature(),joined.snapshot().anchorSignature());
            var records=snapshot.records();byte[] first=records.get(0);first[first.length-1]^=1;
            for(var bad:List.of(new AdminRecordStore.Snapshot(records,snapshot.anchorSignature(),snapshot.revocations(),snapshot.administratorVersion(),snapshot.revocationVersion()),
                    new AdminRecordStore.Snapshot(snapshot.records(),anchor,snapshot.revocations(),snapshot.administratorVersion(),snapshot.revocationVersion()),
                    new AdminRecordStore.Snapshot(snapshot.records(),snapshot.anchorSignature(),snapshot.revocations(),snapshot.administratorVersion()+1,snapshot.revocationVersion()))) {
                store.save(bad);
                var target=new AdminState(fixture.group,Crypto.ed25519Public(fixture.admin),fixture.clock,store);
                assertThrows(SecurityException.class,target::restore);
            }
            store.save(snapshot);var target=new AdminState(fixture.group,Crypto.ed25519Public(fixture.admin),fixture.clock,store);
            target.restore();target.verifyCertificate(node.cert,Crypto.x25519Public(node.secret));
        }
        assertThrows(IllegalStateException.class,()->new AdminState(fixture.group,Crypto.ed25519Public(fixture.admin),fixture.clock,new InMemoryAdminRecordStore()).snapshot());
    }
}
