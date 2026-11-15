// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class ProofRequestsTest {
    final AtomicLong time=new AtomicLong();
    final byte[] secret=new byte[32],group=new byte[32],session=new byte[16];
    final AdminRecords.Record base=AdminRecords.certificate(group,Crypto.ed25519Public(secret),Crypto.x25519Public(secret),
        SignaturePurpose.identityProof(secret,group,Crypto.x25519Public(secret)),100,secret);
    final byte[] peer=Crypto.blake2s(base.field(0));
    final ProofRequests pending=new ProofRequests(new SecureRandom(),time::get);
    RenewalMessage begin(){return pending.begin(peer,session,base,Crypto.ed25519Public(secret),RenewalMessage.Reason.AUTO_RENEWAL,null);}
    @Test void unsolicitedWrongPeerAndWrongSessionCannotMatch(){
        var request=begin();var reply=RenewalMessage.reply(request,secret);
        assertNotNull(pending.match(peer,session,reply));
        assertNull(pending.match(new byte[32],session,reply));
        byte[] other=session.clone();other[0]=1;assertNull(pending.match(peer,other,reply));
        assertNull(new ProofRequests(new SecureRandom(),time::get).match(peer,session,reply));
    }
    @Test void timeoutRejectsReplyAndNextRequestUsesFreshId(){
        var first=begin();time.set(60_000_000_000L);
        assertNull(pending.match(peer,session,RenewalMessage.reply(first,secret)));
        var second=begin();assertFalse(java.util.Arrays.equals(first.requestId(),second.requestId()));
    }
    @Test void retryWaitsFiveSecondsAndRetainsExactRequest(){
        var first=begin();assertNull(begin());time.set(4_999_999_999L);assertNull(begin());
        time.set(5_000_000_000L);assertTrue(java.util.Arrays.equals(first.encode(),begin().encode()));
    }
    @Test void changedSessionStartsNewIdAndOldReplyIsRejected(){
        var first=begin();byte[] other=session.clone();other[0]=1;
        var next=pending.begin(peer,other,base,Crypto.ed25519Public(secret),RenewalMessage.Reason.AUTO_RENEWAL,null);
        assertFalse(java.util.Arrays.equals(first.requestId(),next.requestId()));
        assertNull(pending.match(peer,session,RenewalMessage.reply(first,secret)));
    }
    @Test void requestIdAndBaseCannotBeSubstituted(){
        begin();var unsolicited=RenewalMessage.request(base,new byte[16],Crypto.ed25519Public(secret),RenewalMessage.Reason.AUTO_RENEWAL,null);
        assertNull(pending.match(peer,session,RenewalMessage.reply(unsolicited,secret)));
    }
    @Test void capacityIsGlobalAndOnePerPeer(){
        for(int i=0;i<32;i++){byte[] id=peer.clone();id[0]=(byte)i;assertNotNull(pending.begin(id,session,base,Crypto.ed25519Public(secret),RenewalMessage.Reason.AUTO_RENEWAL,null));}
        byte[] extra=peer.clone();extra[0]=32;assertNull(pending.begin(extra,session,base,Crypto.ed25519Public(secret),RenewalMessage.Reason.AUTO_RENEWAL,null));
    }
}
