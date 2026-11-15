// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/** 認証済みセッションへ結ぶ証明の保留。壁時計ではなく単調時計で期限を数える。 */
public final class ProofRequests implements AutoCloseable {
    public static final long TIMEOUT_NANOS=60_000_000_000L,RETRY_NANOS=5_000_000_000L;
    public static final int MAX_PENDING=32;
    private static final class Pending {
        final RenewalMessage request;final byte[] session;final long began;long last;
        Pending(RenewalMessage request,byte[] session,long now){this.request=request;this.session=session.clone();began=last=now;}
    }
    private final SecureRandom random;private final LongSupplier nanos;
    private final Map<String,Pending> entries=new HashMap<>();
    public ProofRequests(SecureRandom random,LongSupplier nanos){this.random=java.util.Objects.requireNonNull(random);this.nanos=java.util.Objects.requireNonNull(nanos);}
    private static String name(byte[] peer){Crypto.length(peer,32);return Base64.getEncoder().encodeToString(peer);}
    private void expire(long now){entries.values().removeIf(p->{boolean expired=now<p.began||now-p.began>=TIMEOUT_NANOS;if(expired)Crypto.wipe(p.session);return expired;});}
    public RenewalMessage begin(byte[] peer,byte[] session,AdminRecords.Record base,byte[] administrator,RenewalMessage.Reason reason,byte[] operation) {
        Crypto.length(session,16);long now=nanos.getAsLong();expire(now);String name=name(peer);Pending previous=entries.get(name);
        if(previous!=null) {
            if(Crypto.equal(previous.session,session)) {
                if(!previous.request.matchesBase(base)||previous.request.reason()!=reason||!java.util.Arrays.equals(previous.request.managementOperation(),operation))
                    throw new SecurityException("未完の証明要求は差し替えません");
                if(now<previous.last||now-previous.last<RETRY_NANOS)return null;
                previous.last=now;return previous.request;
            }
            Crypto.wipe(previous.session);entries.remove(name);
        }
        if(entries.size()>=MAX_PENDING)return null;
        byte[] id=new byte[16];random.nextBytes(id);var request=RenewalMessage.request(base,id,administrator,reason,operation);
        entries.put(name,new Pending(request,session,now));return request;
    }
    /** 受信の認証・基準証明書の検査は呼び出し元が先に済ませる。同じ要求で期限を延ばさない。 */
    public boolean remember(byte[] peer,byte[] session,RenewalMessage request) {
        if(request.operation()!=RenewalMessage.Operation.PROOF_REQUEST)throw new IllegalArgumentException("証明要求ではありません");
        Crypto.length(session,16);long now=nanos.getAsLong();expire(now);String name=name(peer);Pending previous=entries.get(name);
        if(previous!=null&&Crypto.equal(previous.session,session))return previous.request.sameRequest(request);
        if(previous==null&&entries.size()>=MAX_PENDING)return false;
        if(previous!=null)Crypto.wipe(previous.session);
        entries.put(name,new Pending(request,session,now));return true;
    }
    public RenewalMessage match(byte[] peer,byte[] session,RenewalMessage message) {
        expire(nanos.getAsLong());Pending pending=entries.get(name(peer));
        return pending!=null&&Crypto.equal(pending.session,session)&&pending.request.sameRequest(message)?pending.request:null;
    }
    public void forget(byte[] peer){Pending pending=entries.remove(name(peer));if(pending!=null)Crypto.wipe(pending.session);}
    public static boolean due(AdminRecords.Record certificate,long now) {
        return now>=certificate.issuedAt()&&now<certificate.expiresAt()
            &&certificate.expiresAt()-now<=(certificate.expiresAt()-certificate.issuedAt())/3;
    }
    @Override public void close(){for(var pending:entries.values())Crypto.wipe(pending.session);entries.clear();}
}
