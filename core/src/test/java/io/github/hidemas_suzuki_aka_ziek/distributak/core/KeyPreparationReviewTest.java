// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class KeyPreparationReviewTest {
    @Test void preparationClockFailureRejectsAndWipesOpenedCopyWithoutSaving(){
        var t=new KeyRotationConflictTest();var f=t.f;boolean[] fail={false};
        Clock clock=new Clock(){
            public ZoneId getZone(){return ZoneOffset.UTC;}
            public Clock withZone(ZoneId z){return this;}
            public Instant instant(){return Instant.ofEpochMilli(millis());}
            public long millis(){if(fail[0])throw new IllegalStateException("injected clock failure");return f.time.millis();}
        };
        try(var a=f.new Node(1)){
            var disk=new InMemoryAdminRecordStore();disk.save(a.state.snapshot());
            var state=new AdminState(f.group,Crypto.ed25519Public(f.admin),clock,disk);state.restore();
            try(var sessions=new SessionManager(state,a.cert,a.secret,f.psk,0,clock,()->f.time.nanos,256)){
                var union=new RevocationUnion(f.group,new AdminStateTrust(state));
                var c=new CorePersistenceCoordinator(state,sessions,union,clock,t.t.deadlines());
                var announcement=t.ann(a,1,key(74));
                var wrap=GroupKeyEnvelope.wrap(f.group,a.id,Crypto.x25519Public(a.secret),1,f.time.millis(),key(74),f.admin,Crypto.blake2s(announcement.signedBytes()));
                var observed=new AtomicReference<byte[]>();int[] saved={0};
                var hooks=new CorePersistenceCoordinator.PersistenceHooks(){
                    public void save(AdminRecordStore.Snapshot s){saved[0]++;}
                    public void saveKey(byte[] k,long v){saved[0]++;}
                };
                try{
                    assertEquals(CorePersistenceCoordinator.KeyResult.REJECTED,c.applyGroupKey(announcement,wrap,a.id,a.secret,0,sessions.generation(),hooks,copy->{observed.set(copy);fail[0]=true;}));
                    assertNotNull(observed.get());assertEquals(32,observed.get().length);
                    boolean wiped=true;for(byte b:observed.get())wiped&=b==0;assertTrue(wiped);
                    assertEquals(0,saved[0]);assertEquals(0,sessions.keyVersion());assertEquals(CorePersistenceCoordinator.State.RUNNING,c.state());
                }finally{fail[0]=false;Crypto.wipe(observed.get());}
            }
        }
    }
}
