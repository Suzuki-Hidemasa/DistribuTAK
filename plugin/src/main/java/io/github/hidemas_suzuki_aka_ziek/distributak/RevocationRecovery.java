// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementOperations;
import java.time.Clock;
import java.security.SecureRandom;
import java.util.*;

/**
 * 通常失効と限定復旧の管理通信を共有する。復旧は既存候補だけを使う。作業スレッドだけから呼び、保存I/Oは受信ロック外で行う。
 * <p>
 * Shares management transport for normal revocations and limited recovery. Recovery uses existing candidates only. Called solely on the worker thread, with persistence outside receive locks.
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
    private final java.util.function.Supplier<CorePersistenceCoordinator.PersistenceHooks> hooks;
    private final Clock clock;
    private final ManagementOperations operations;
    private final Transport transport;
    private final ManagementSendBudget budget;
    private final ManagementPageSender sender;
    @FunctionalInterface interface Delivered {void completed(byte[] peer,byte[] session,long generation,byte[] target);}
    private Runnable beforeSending=()->{};
    void beforeSending(Runnable action){beforeSending=Objects.requireNonNull(action);}
    private void sendPages(){beforeSending.run();sender.poll();}
    private Delivered delivered=(p,s,g,t)->{};
    void onRevocationsDelivered(Delivered listener){delivered=Objects.requireNonNull(listener);}
    private final Set<String> attempted=new HashSet<>();
    private byte[] peer,session;
    private RevocationsRecoveryRequest request;
    private long progress,lastRequest=Long.MIN_VALUE;
    private int requests;
    private boolean exhausted;
    boolean exhausted(){return exhausted;}
    RevocationRecovery(LanGroup group,SessionManager sessions,CorePersistenceCoordinator coordinator,Clock clock,SecureRandom random,
                       Transport transport,CorePersistenceCoordinator.PersistenceHooks hooks){
        this(group,sessions,coordinator,clock,random,()->hooks,transport);
    }
    RevocationRecovery(LanGroup group,SessionManager sessions,CorePersistenceCoordinator coordinator,Clock clock,SecureRandom random,
                       java.util.function.Supplier<CorePersistenceCoordinator.PersistenceHooks> hooks,Transport transport){
        this.group=group;this.sessions=sessions;this.coordinator=coordinator;this.clock=clock;this.operations=coordinator.managementOperations(random);this.transport=transport;this.hooks=hooks;
        budget=new ManagementSendBudget(clock);
        sender=new ManagementPageSender(group.groupId,clock,budget,(p,s,w)->{
            if(!coordinator.permits(CorePersistenceCoordinator.Operation.REVOCATION_PAGE))return false;
            return transport.send(p,s,w);
        });
        sender.onCompletion((p,s,g,k,t)->{if(k==ManagementPage.Kind.REVOCATION)delivered.completed(p,s,g,t);});
    }
    void poll(List<byte[]> candidates){
        coordinator.poll();sender.discardUnverifiedSessions(sessions);sender.rotating(sessions.hasRotatingSessions());
        if(coordinator.state()==CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS){
            exhausted=false;
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
            exhausted=peer==null;
            if(peer!=null){
                var verified=sessions.verifiedSession(peer);
                if(verified!=null&&request==null){
                    session=verified.sessionId();byte[] operation=operations.next();
                    var required=group.recoveryRequirement;
                    request=new RevocationsRecoveryRequest(group.groupId,operation,required.version(),required.digest());
                    if(!coordinator.bindRecovery(peer,session,verified.generation(),request)){abandon();return;}
                }
                if(request!=null&&requests<4&&(requests==0||clock.millis()-lastRequest>=1000)&&budget.tryTake(peer,1)){
                    requests++;lastRequest=clock.millis();transport.send(peer,session,request.envelope());
                }
            }
        }
        if(coordinator.permits(CorePersistenceCoordinator.Operation.REVOCATION_PAGE))sendPages();
    }
    boolean receive(byte[] source,byte[] sourceSession,byte[] wire){
        return receive(source,sourceSession,wire,clock.millis());
    }
    boolean receive(byte[] source,byte[] sourceSession,byte[] wire,long receivedAt){
        var verified=sessions.verifiedSession(source);
        if(verified==null||!Arrays.equals(sourceSession,verified.sessionId()))return false;
        int field=ManagementEnvelopeFields.field(wire);
        if(field==ManagementEnvelopeFields.REVOCATIONS_RECOVERY_REQUEST){
            final RevocationsRecoveryRequest incoming;
            try{incoming=RevocationsRecoveryRequest.decodeEnvelope(wire);}catch(IllegalArgumentException invalid){return true;}
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
            sendPages();return true;
        }
        if(field==ManagementEnvelopeFields.PAGE_ACK){
            final ManagementPageAck ack;
            try{ack=ManagementPageAck.decodeEnvelope(wire);}catch(IllegalArgumentException invalid){return true;}
            if(coordinator.permits(CorePersistenceCoordinator.Operation.PAGE_ACK))sender.acknowledgeAt(source,sourceSession,verified.generation(),ack,receivedAt);
            return true;
        }
        if(field!=ManagementEnvelopeFields.REVOCATION_PAGE)return false;
        ManagementPage page;
        try{page=ManagementPage.decodeEnvelope(wire);}catch(IllegalArgumentException invalid){return true;}
        boolean recovering=coordinator.state()==CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS;
        if(page.kind()!=ManagementPage.Kind.REVOCATION)return true;
        var result=coordinator.receiveRevocationPage(source,sourceSession,verified.generation(),page,new CorePersistenceCoordinator.PersistenceHooks(){
            private CorePersistenceCoordinator.PersistenceHooks delegate;
            public void active(CorePersistenceCoordinator.PersistenceRequest request){delegate=hooks.get();delegate.active(request);}
            public void save(AdminRecordStore.Snapshot snapshot){delegate.save(snapshot);}
            public void save(CorePersistenceCoordinator.PersistenceRequest request){delegate.save(request);}
            public void clear(CorePersistenceCoordinator.PersistenceRequest request){delegate.clear(request);}
            public void stopped(CorePersistenceCoordinator.StopReason reason){group.storageBlocked=true;if(delegate!=null)delegate.stopped(reason);}
            public void selfRevoked(){if(delegate!=null)delegate.selfRevoked();}
        },receivedAt);
        if(result.status()==ManagementPageAssembler.Status.REJECTED||result.status()==ManagementPageAssembler.Status.CORRUPT){
            if(recovering&&Arrays.equals(peer,source)&&Arrays.equals(session,sourceSession))abandon();return true;
        }
        if(result.completed()!=null&&coordinator.state()==CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS){abandon();return true;}
        if(result.status()==ManagementPageAssembler.Status.INCOMPLETE||result.status()==ManagementPageAssembler.Status.COMPLETE)progress=Math.max(progress,receivedAt);
        if(result.ack()!=null&&coordinator.permits(CorePersistenceCoordinator.Operation.PAGE_ACK))sender.sendAck(source,sourceSession,result.ack());
        return true;
    }
    ManagementPageSender.Offer offerRevocations(byte[] destination){
        if(coordinator.state()!=CorePersistenceCoordinator.State.RUNNING)return ManagementPageSender.Offer.BUSY;
        var verified=sessions.verifiedSession(destination);if(verified==null)return ManagementPageSender.Offer.INVALID;
        var body=group.state.revocations();
        try{body.verify(AdminRecords.Kind.REVOCATIONS,group.groupId,group.state.administrators().entries());}
        catch(RuntimeException untrusted){return ManagementPageSender.Offer.INVALID;}
        if(body.format()!=2)return ManagementPageSender.Offer.INVALID;
        sender.discardOtherSessions(destination,verified.sessionId(),verified.generation());
        return sender.offer(destination,verified.sessionId(),verified.generation(),ManagementPage.Kind.REVOCATION,
                operations.next(),body.encode(),body.entries().size(),false);
    }
    byte[] nextManagementOperation(){return operations.next();}
    void cancelSavedDelivery(byte[] revocations,byte[] announcement){
        if(revocations!=null)sender.discardTarget(ManagementPage.Kind.REVOCATION,revocations);
        if(announcement!=null)sender.discardTarget(ManagementPage.Kind.ANNOUNCEMENT,announcement);
    }
    ManagementPageSender.Offer offerAnnouncement(byte[] peer,KeyAnnouncement announcement){
        return offerAnnouncement(peer,announcement,clock.millis());
    }
    ManagementPageSender.Offer offerAnnouncement(byte[] peer,KeyAnnouncement announcement,long offeredAt){
        if(!coordinator.permits(CorePersistenceCoordinator.Operation.KEY_ANNOUNCEMENT))return ManagementPageSender.Offer.BUSY;
        var verified=sessions.verifiedSession(peer);if(verified==null||coordinator.isRevoked(peer))return ManagementPageSender.Offer.INVALID;
        sender.discardOtherSessions(peer,verified.sessionId(),verified.generation());
        return sender.offer(peer,verified.sessionId(),verified.generation(),ManagementPage.Kind.ANNOUNCEMENT,
                operations.next(),announcement.encode(),0,false,offeredAt);
    }
    boolean announcementAck(byte[] peer,byte[] session,ManagementPageAck ack){
        return coordinator.permits(CorePersistenceCoordinator.Operation.KEY_ANNOUNCEMENT)&&sender.sendAck(peer,session,ack);
    }
    ManagementPageSender.Offer offerRoster(byte[] peer,ManagementPage.Kind kind,byte[] operation,byte[] data,int count){
        if(!coordinator.permits(CorePersistenceCoordinator.Operation.ROSTER))return ManagementPageSender.Offer.BUSY;
        var verified=sessions.verifiedSession(peer);if(verified==null)return ManagementPageSender.Offer.INVALID;
        sender.discardOtherSessions(peer,verified.sessionId(),verified.generation());
        return sender.offer(peer,verified.sessionId(),verified.generation(),kind,operation,data,count,false);
    }
    boolean rosterAck(byte[] peer,byte[] session,ManagementPageAck ack){
        return coordinator.permits(CorePersistenceCoordinator.Operation.ROSTER)&&sender.sendAck(peer,session,ack);
    }
    private void abandon(){
        coordinator.abandonRecovery();Crypto.wipe(peer);Crypto.wipe(session);peer=null;session=null;request=null;requests=0;lastRequest=Long.MIN_VALUE;
    }
    public void close(){abandon();sender.close();attempted.clear();}
}
