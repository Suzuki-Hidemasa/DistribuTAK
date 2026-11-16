// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class RosterPullTest {
    final JoinHandshakeTest f=new JoinHandshakeTest();
    AdminRecords.Record certificate(int n,long issued){
        byte[] identity=key(n),handshake=Crypto.x25519Public(key(n+100));
        return AdminRecords.certificate(f.f.group,Crypto.ed25519Public(identity),handshake,
            SignaturePurpose.identityProof(identity,f.f.group,handshake),issued,f.f.a);
    }
    MemberDirectory directory(){return new MemberDirectory(f.f.fresh());}
    void pull(MemberDirectory a,MemberDirectory b){
        byte[] after=new byte[0];int rounds=0;
        while(true){
            assertTrue(++rounds<30,"pull must terminate");
            var summary=RosterMessage.summarize(a,after);var response=RosterMessage.respond(b,summary);
            var decoded=RosterMessage.decodeBatch(response.encode());
            assertTrue(decoded.certificates().size()<=32);
            for(var cert:decoded.certificates())a.saved(cert);
            if(!decoded.intervalDone())continue;
            if(!summary.more())break;
            after=summary.entries().get(summary.entries().size()-1).memberId();
        }
    }
    @Test void disjointSeventyEntryRostersConvergeInBothDirectionsAcrossChangingWindows(){
        var a=directory();var b=directory();
        for(int n=1;n<=70;n++)(n%2==0?a:b).saved(certificate(n,f.f.now));
        pull(a,b);pull(b,a);assertEquals(70,a.size());assertEquals(70,b.size());
        assertArrayEquals(RosterMessage.summarize(a,new byte[0]).digest(),RosterMessage.summarize(b,new byte[0]).digest());
    }
    @Test void moreRequiresFullWindowAndEmptyBatchRequiresIntervalDone(){
        assertThrows(IllegalArgumentException.class,()->new RosterMessage.Summary(65536,key(1),new byte[0],List.of(),true));
        assertThrows(IllegalArgumentException.class,()->new RosterMessage.Batch(List.of(),false));
        var empty=new RosterMessage.Batch(List.of(),true);
        assertTrue(RosterMessage.decodeBatch(empty.encode()).intervalDone());
        assertThrows(IllegalArgumentException.class,()->RosterMessage.decodeBatch(Arrays.copyOf(empty.encode(),empty.encode().length-2)));
    }
    @Test void equalTimeConflictDoesNotOverwriteAndPullTerminates(){
        var a=directory();var b=directory();var first=certificate(1,f.f.now);
        byte[] other=Crypto.x25519Public(key(240));var conflict=AdminRecords.certificate(f.f.group,first.field(0),other,
            SignaturePurpose.identityProof(key(1),f.f.group,other),f.f.now,f.f.a);
        a.saved(first);b.saved(conflict);var response=RosterMessage.respond(b,RosterMessage.summarize(a,new byte[0]));
        assertTrue(response.intervalDone());assertTrue(response.certificates().isEmpty());pull(a,b);
        assertArrayEquals(first.encode(),a.snapshot().get(0));
    }
    @Test void newerCertificateReplacesOnlyOlderAndEqualFullDigestReturnsEmpty(){
        var a=directory();var b=directory();a.saved(certificate(1,f.f.now-1));b.saved(certificate(1,f.f.now));
        pull(a,b);assertEquals(f.f.now,a.summary().get(0).issuedAt());
        var response=RosterMessage.respond(b,RosterMessage.summarize(a,new byte[0]));
        assertTrue(response.intervalDone());assertTrue(response.certificates().isEmpty());
    }
}
