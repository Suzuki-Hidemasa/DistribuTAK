// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
final class AdministratorFixtures {
    static List<AdminBinding> bindings(LanGroup group,int count) {
        var result=new ArrayList<AdminBinding>();var local=AdminControl.keyProof(group.groupId,new byte[16],0,group.identitySecret,group.administratorSecret);
        result.add(AdminBinding.bound(local.administratorKey(),local.memberId(),local.encode()));
        for(int n=1;n<=count;n++) {
            byte[] secret=StoredUpdatesTest.key(n);if(Crypto.equal(Crypto.ed25519Public(secret),group.urlAdmin))continue;
            byte[] identity=Crypto.blake2s(Crypto.concat(new byte[]{1,7},secret));var proof=AdminControl.keyProof(group.groupId,new byte[16],0,identity,secret);
            result.add(AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode()));
        }return result;
    }
}
