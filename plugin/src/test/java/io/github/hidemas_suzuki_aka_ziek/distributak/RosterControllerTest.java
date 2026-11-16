// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.NormalRevocationControllerTest.*;

public class RosterControllerTest {
    @Test public void authenticatedFirstIsSavedOnlyOnAdministrator()throws Exception{
        try(var p=new Pair()){
            var member=group(p.m);long issued=LanControllerHarness.CLOCK.millis()+1;
            var certificate=AdminRecords.certificate(member.groupId,member.certificate.field(0),member.certificate.field(1),
                SignaturePurpose.identityProof(member.identitySecret,member.groupId,member.certificate.field(1)),issued,group(p.a).administratorSecret);
            p.m.endpoint().updateLocalCertificate(certificate);member.certificate=certificate;
            p.a.endpoint().expectPeerCertificate(certificate);
            p.a.offset.addAndGet(5_000_000_000L);p.m.offset.addAndGet(5_000_000_000L);
            p.m.endpoint().start(group(p.a).id());
            LanProofRenewalTest.until(()->group(p.a).management.roster.stream().map(AdminRecords::decode).anyMatch(c->c.issuedAt()==issued),p.a,p.m);
            assertEquals(0,p.m.disk.directorySaves);
            try(var loaded=p.a.disk.load(LanControllerHarness.CLOCK)){assertTrue(loaded.management.roster.stream().map(AdminRecords::decode).anyMatch(c->c.issuedAt()==issued));}
        }
    }
}
