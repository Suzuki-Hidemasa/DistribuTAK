// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class InvitationRevocationCoverageTest {
    @Test void newMemberCannotReceiveListAndKeyOmittingAcceptedRevocationUnion(){
        var t=new GroupAdministrationTest();var f=t.f;
        try(var a=f.new Node(1);var service=t.service(a,true)){
            a.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,1,f.time.millis(),List.of(key(80)),f.admin));
            a.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,2,f.time.millis(),List.of(),f.admin));
            assertThrows(SecurityException.class,()->JoinHandshake.Materials.verified(a.state,List.of(a.state.administrators()),0,f.psk));
            try(var invite=service.invitation(new byte[]{(byte)192,0,2,1},54321,key(92));var issuer=service.invitationIssuer(invite);
                var joiner=new JoinHandshake.Joiner(invite,key(94),key(95),f.time)){
                assertThrows(SecurityException.class,()->service.respondInvitation(issuer,joiner.request(),f.psk,0));assertFalse(issuer.isConsumed());
            }
        }
    }
}
