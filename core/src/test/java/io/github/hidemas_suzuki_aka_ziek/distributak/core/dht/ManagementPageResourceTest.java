// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementPage;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementPageAssembler;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtTransfersTest.*;
import static org.junit.jupiter.api.Assertions.*;

class ManagementPageResourceTest {
    final TransferResources resources=new TransferResources();
    final AtomicLong nanos=new AtomicLong();
    final AtomicLong delivered=new AtomicLong();
    final ManagementPageAssembler pages=new ManagementPageAssembler(GROUP,Clock.fixed(Instant.EPOCH,ZoneOffset.UTC),resources);
    final DhtTransfers transfers=new DhtTransfers(GROUP,(p,s,w)->true,nanos::get,new Random(1),
            (p,k,d)->delivered.incrementAndGet(),(p,r)->true,DhtTransfers.Limits.defaults(),resources);
    ManagementPage page(){return ManagementPage.split(ManagementPage.Kind.REVOCATION,tid(1),GROUP,data(2048,1),0).get(0);}
    void piece(int peer,int index){
        byte[] object=data(3000,2);
        transfers.receive(id(peer),SESSION,DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,tid(2),
                DhtTransfers.digestOf(object),3000,index,3,Arrays.copyOfRange(object,index*1024,Math.min(object.length,(index+1)*1024)))));
    }
    @Test void dhtAndPagesSharePeerCountTotalCountAndOneReservationPerAssembly() {
        piece(1,0);assertEquals(3000,resources.reservedBytes());assertEquals(1,resources.active());
        assertEquals(ManagementPageAssembler.Status.REJECTED,pages.receive(id(1).bytes(),SESSION,1,page()).status());
        assertEquals(ManagementPageAssembler.Status.INCOMPLETE,pages.receive(id(2).bytes(),SESSION,1,page()).status());
        piece(3,0);assertEquals(1,transfers.rejected());assertEquals(1,transfers.activeIn());
        assertEquals(2,resources.active());assertEquals(5048,resources.reservedBytes());
        piece(1,0);assertEquals(5048,resources.reservedBytes());
        transfers.clear();assertEquals(2048,resources.reservedBytes());assertEquals(1,resources.active());
        pages.clear();assertEquals(0,resources.reservedBytes());assertEquals(0,resources.active());
    }
    @Test void completionForgetTimeoutAndClearReleaseDhtReservationWithoutTouchingPages() {
        pages.receive(id(2).bytes(),SESSION,1,page());piece(1,0);piece(1,1);piece(1,2);
        assertEquals(1,delivered.get());assertEquals(2048,resources.reservedBytes());
        transfers.clear();piece(1,0);transfers.forget(id(1));transfers.forget(id(1));assertEquals(2048,resources.reservedBytes());
        piece(1,0);nanos.addAndGet(DhtTransfers.PROGRESS_NANOS);transfers.poll();
        assertEquals(2048,resources.reservedBytes());assertEquals(0,transfers.activeIn());
        transfers.clear();transfers.clear();assertEquals(2048,resources.reservedBytes());pages.clear();assertEquals(0,resources.reservedBytes());
    }
    @Test void pageReservationsAlsoPreventDhtAdmissionAndDhtRatesRemainUnchanged() {
        pages.receive(id(1).bytes(),SESSION,1,page());piece(1,0);
        assertEquals(1,transfers.rejected());assertEquals(0,transfers.activeIn());assertEquals(2048,resources.reservedBytes());
        var limits=DhtTransfers.Limits.defaults();
        assertEquals(200,limits.peerPerSecond);assertEquals(400,limits.peerBurst);
        assertEquals(400,limits.totalPerSecond);assertEquals(800,limits.totalBurst);
    }
}
