// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class RosterMessageTest {
    @Test void summaryRoundTripsAllExplicitFields(){
        var entries=List.of(new MemberDirectory.Summary(key(1),0,key(2)));
        var value=new RosterMessage.Summary(65536,key(3),new byte[0],entries);
        var decoded=RosterMessage.decodeSummary(value.encode());
        assertEquals(65536,decoded.total());assertEquals(1,decoded.entries().size());
        assertArrayEquals(key(1),decoded.entries().get(0).memberId());assertArrayEquals(value.encode(),decoded.encode());
    }
    @Test void summaryRejectsUnknownDuplicateMissingAndNonCanonicalFields(){
        byte[] valid=new RosterMessage.Summary(0,key(3),new byte[0],List.of()).encode();
        assertThrows(IllegalArgumentException.class,()->RosterMessage.decodeSummary(Crypto.concat(valid,new byte[]{56,0})));
        assertThrows(IllegalArgumentException.class,()->RosterMessage.decodeSummary(Crypto.concat(valid,new byte[]{8,1})));
        assertThrows(IllegalArgumentException.class,()->RosterMessage.decodeSummary(Arrays.copyOf(valid,valid.length-2)));
        assertThrows(IllegalArgumentException.class,()->RosterMessage.decodeSummary(Crypto.concat(new byte[]{8,(byte)129,0},Arrays.copyOfRange(valid,2,valid.length))));
    }
    @Test void thirtyTwoSummariesFitButThirtyThreeDuplicateAndOutOfOrderAreRejected(){
        var entries=new ArrayList<MemberDirectory.Summary>();
        for(int i=0;i<32;i++)entries.add(new MemberDirectory.Summary(key(i),i,key(90)));
        assertEquals(32,RosterMessage.decodeSummary(new RosterMessage.Summary(32,key(3),new byte[0],entries).encode()).entries().size());
        entries.add(new MemberDirectory.Summary(key(32),32,key(90)));
        assertThrows(IllegalArgumentException.class,()->new RosterMessage.Summary(33,key(3),new byte[0],entries));
        var duplicate=List.of(entries.get(0),entries.get(0));
        assertThrows(IllegalArgumentException.class,()->new RosterMessage.Summary(2,key(3),new byte[0],duplicate));
        assertThrows(IllegalArgumentException.class,()->new RosterMessage.Summary(2,key(3),new byte[0],List.of(entries.get(1),entries.get(0))));
    }
    @Test void certificateBatchRoundTripAndMalformedLengthAreRejected(){
        var f=new JoinHandshakeTest();var certificate=f.f.certificate();
        byte[] valid=RosterMessage.encodeCertificates(List.of(certificate));
        assertArrayEquals(certificate.encode(),RosterMessage.decodeCertificates(valid).get(0).encode());
        assertThrows(IllegalArgumentException.class,()->RosterMessage.decodeCertificates(new byte[65537]));
        assertThrows(IllegalArgumentException.class,()->RosterMessage.decodeCertificates(Crypto.concat(valid,new byte[]{32,0})));
        assertThrows(IllegalArgumentException.class,()->RosterMessage.encodeCertificates(List.of(certificate,certificate)));
    }
}
