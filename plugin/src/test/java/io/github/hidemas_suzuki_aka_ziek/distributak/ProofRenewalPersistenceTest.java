// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.NormalRevocationControllerTest.*;

public class ProofRenewalPersistenceTest {
    @Test public void persistingDoesNotRememberProofRequestAndSameRequestCanRetryAfterSave()throws Exception{
        try(var p=new Pair()){
            var member=group(p.m);byte[] peer=group(p.a).id(),session=p.m.endpoint().sessionId(peer);
            var request=RenewalMessage.request(member.certificate,new byte[16],group(p.a).urlAdmin,
                RenewalMessage.Reason.INVITATION_PREPARE,new byte[16]);
            var method=LanController.class.getDeclaredMethod("receiveProofRenewal",byte[].class,byte[].class,byte[].class);method.setAccessible(true);
            var pending=(ProofRequests)LanControllerHarness.field(p.m.controller,"proofRequests");
            coordinator(p.m).saveUnchanged(()->{
                try{method.invoke(p.m.controller,peer,session,request.encode());}catch(Exception failure){throw new AssertionError(failure);}
                assertNull(pending.match(peer,session,request));
            });
            method.invoke(p.m.controller,peer,session,request.encode());assertNotNull(pending.match(peer,session,request));
        }
    }
}
