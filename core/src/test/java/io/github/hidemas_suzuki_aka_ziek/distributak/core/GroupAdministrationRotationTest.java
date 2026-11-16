// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class GroupAdministrationRotationTest {
    @Test void administratorUsesOneRotationServiceAndCannotRevokeItselfOrBypassCooldown(){
        var t=new GroupAdministrationTest();var f=t.f;
        try(var a=f.new Node(1);var service=t.service(a,true)){
            var union=new RevocationUnion(f.group,new AdminStateTrust(a.state));union.add(a.state.revocations());
            var deadlines=new MonotonicClock(()->f.time.nanos);var rotations=service.rotations(a.sessions,union,deadlines);
            assertSame(rotations,service.rotations(a.sessions,union,deadlines));
            var hooks=new CorePersistenceCoordinator.PersistenceHooks(){public void save(AdminRecordStore.Snapshot s){}public void saveKey(byte[] key,long version){}};
            assertThrows(SecurityException.class,()->rotations.manual(List.of(a.id),List.of(a.cert),hooks));
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotations.manual(List.of(),List.of(a.cert),hooks));
            assertEquals(KeyRotationCoordinator.Result.TOO_EARLY,service.rotations(a.sessions,union,deadlines).manual(List.of(),List.of(a.cert),hooks));
            service.close();assertThrows(IllegalStateException.class,()->rotations.poll(List.of(a.cert),hooks));
        }
    }
}
