// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PersistingPageReceptionTest {
    @Test void sessionReceptionPassesOnlyTypedManagementPagesDuringSave(){
        var f=new CorePersistenceCoordinatorTest();
        try(var a=f.f.new Node(1);var b=f.f.new Node(2)){
            f.f.connect(a,b);var c=f.coordinator(a);var packets=new ArrayList<byte[]>();var plains=new ArrayList<byte[]>();
            for(var kind:ManagementPage.Kind.values()){
                var wire=ManagementPage.split(kind,new byte[16],f.f.group,new byte[]{1},1).get(0).envelope();plains.add(wire);
                var sent=b.sessions.send(a.id,wire);packets.add(sent.get(sent.size()-1).packet());
            }
            byte[] other=f.f.data(b,a,1);
            c.saveUnchanged(()->{
                for(int n=0;n<packets.size();n++)assertArrayEquals(plains.get(n),a.sessions.receive(packets.get(n)).plaintext());
                assertThrows(IllegalStateException.class,()->a.sessions.receive(other));
            });
        }
    }
}
