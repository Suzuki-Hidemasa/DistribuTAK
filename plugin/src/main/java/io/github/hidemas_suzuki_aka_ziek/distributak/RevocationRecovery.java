// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.time.Clock;
import java.security.SecureRandom;
import java.util.*;

/**
 * 既存候補だけで失効一覧を取り直す。作業スレッドだけから呼び、保存 I/O は受信ロック外で行う。
 * <p>
 * Retrieves revocations using existing candidates only. Called solely on the worker thread, with persistence outside receive locks.
 */
final class RevocationRecovery implements AutoCloseable {
    interface Transport {
        boolean send(byte[] peer,byte[] session,byte[] wire);
        void start(byte[] peer);
        void rejected(ManagementPageSender.Offer result);
    }
    private final LanGroup group;
    private final SessionManager sessions;
    private final CorePersistenceCoordinator coordinator;
    private final CorePersistenceCoordinator.PersistenceHooks hooks;
    private final Clock clock;
    private final SecureRandom random;
    private final Transport transport;
    private final ManagementSendBudget budget;
    private final ManagementPageSender sender;
    private final Set<String> attempted=new HashSet<>();
    private byte[] peer,session;
    private RevocationsRecoveryRequest request;
    private long progress,lastRequest=Long.MIN_VALUE;
    private int requests;
    RevocationRecovery(LanGroup group,SessionManager sessions,CorePersistenceCoordinator coordinator,Clock clock,SecureRandom random,
                       Transport transport,CorePersistenceCoordinator.PersistenceHooks hooks){
        this.group=group;this.sessions=sessions;this.coordinator=coordinator;this.clock=clock;this.random=random;this.transport=transport;this.hooks=hooks;
        budget=new ManagementSendBudget(clock);
        sender=new ManagementPageSender(group.groupId,clock,budget,(p,s,w)->{
            if(!coordinator.permits(CorePersistenceCoordinator.Operation.REVOCATION_PAGE))return false;
            return transport.send(p,s,w);
        });
    }
    void poll(List<byte[]> candidates){
        coordinator.poll();
        if(coordinator.state()==CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS){
            if(!coordinator.permits(CorePersistenceCoordinator.Operation.RECOVERY_REQUEST)){abandon();attempted.clear();return;}
            if(peer!=null&&clock.millis()-progress>=ManagementPageAssembler.PROGRESS_MILLIS)abandon();
            if(peer!=null&&session!=null&&!Arrays.equals(session,sessions.sessionId(peer))){
                coordinator.abandonRecovery();Crypto.wipe(session);session=null;request=null;requests=0;
            }
            if(peer==null)for(byte[] candidate:candidates){
                String id=Base64.getEncoder().encodeToString(candidate);
                if(attempted.size()>=32)break;
                if(!attempted.add(id)||coordinator.isRevoked(candidate))continue;
                peer=candidate.clone();progress=clock.millis();
                try{if(sessions.verifiedSession(peer)==null)transport.start(peer);}
                catch(IllegalStateException pending){}
                catch(RuntimeException unavailable){abandon();continue;}
                break;
            }
            if(peer!=null){
                var verified=sessions.verifiedSession(peer);
                if(verified!=null&&request==null){
                    session=verified.sessionId();byte[] operation=new byte[16];random.nextBytes(operation);
                    var required=group.recoveryRequirement;
                    request=new RevocationsRecoveryRequest(group.groupId,operation,required.version(),required.digest());
                    if(!coordinator.bindRecovery(peer,session,verified.generation(),request)){abandon();return;}
                }
                if(request!=null&&requests<4&&(requests==0||clock.millis()-lastRequest>=1000)&&budget.tryTake(peer,1)){
                    requests++;lastRequest=clock.millis();transport.send(peer,session,request.envelope());
                }
            }
        }
        if(coordinator.permits(CorePersistenceCoordinator.Operation.REVOCATION_PAGE))sender.poll();
    }
    boolean receive(byte[] source,byte[] sourceSession,byte[] wire){
        var verified=sessions.verifiedSession(source);
        if(verified==null||!Arrays.equals(sourceSession,verified.sessionId()))return false;
        RevocationsRecoveryRequest incoming=null;
        try{incoming=RevocationsRecoveryRequest.decodeEnvelope(wire);}catch(IllegalArgumentException invalid){}
        if(incoming!=null){
            if(!coordinator.permits(CorePersistenceCoordinator.Operation.RECOVERY_REQUEST)||!Arrays.equals(group.groupId,incoming.group()))return true;
            var body=group.state.revocations();
            try{body.verify(AdminRecords.Kind.REVOCATIONS,group.groupId,group.state.administrators().entries());}
            catch(RuntimeException untrusted){return true;}
            if(body.format()==2){
                sender.discardOtherSessions(source,sourceSession,verified.generation());
                var offered=sender.offer(source,sourceSession,verified.generation(),ManagementPage.Kind.REVOCATION,
                        incoming.operationId(),body.encode(),body.entries().size(),false);
                if(offered!=ManagementPageSender.Offer.ACCEPTED)transport.rejected(offered);
            }
            sender.poll();return true;
        }
        ManagementPageAck ack=null;
        try{ack=ManagementPageAck.decodeEnvelope(wire);}catch(IllegalArgumentException invalid){}
        if(ack!=null){
            if(coordinator.permits(CorePersistenceCoordinator.Operation.PAGE_ACK))sender.acknowledge(source,sourceSession,verified.generation(),ack);
            return true;
        }
        ManagementPage page;
        try{page=ManagementPage.decodeEnvelope(wire);}catch(IllegalArgumentException invalid){return false;}
        if(coordinator.state()!=CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS)return false;
        if(page.kind()!=ManagementPage.Kind.REVOCATION)return true;
        var result=coordinator.receiveRecoveryPage(source,sourceSession,verified.generation(),page,hooks);
        if(result.status()==ManagementPageAssembler.Status.REJECTED||result.status()==ManagementPageAssembler.Status.CORRUPT){
            if(Arrays.equals(peer,source)&&Arrays.equals(session,sourceSession))abandon();return true;
        }
        if(result.completed()!=null&&coordinator.state()==CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS){abandon();return true;}
        if(result.status()==ManagementPageAssembler.Status.INCOMPLETE||result.status()==ManagementPageAssembler.Status.COMPLETE)progress=clock.millis();
        if(result.ack()!=null&&coordinator.permits(CorePersistenceCoordinator.Operation.PAGE_ACK))sender.sendAck(source,sourceSession,result.ack());
        return true;
    }
    private void abandon(){
        coordinator.abandonRecovery();Crypto.wipe(peer);Crypto.wipe(session);peer=null;session=null;request=null;requests=0;lastRequest=Long.MIN_VALUE;
    }
    public void close(){abandon();attempted.clear();}
}
