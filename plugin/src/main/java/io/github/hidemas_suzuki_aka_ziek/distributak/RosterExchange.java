// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtId;
import java.time.Clock;
import java.util.*;

/**
 * 管理者間の名簿pull。失効と同じ組立・送信予算を使い、作業スレッドからだけ呼ぶ。
 * <p>
 * Administrator roster pulls sharing assembly and send budgets with revocations, called only on the worker thread.
 */
final class RosterExchange implements AutoCloseable {
    private static final class Peer {
        final byte[] session;final long generation;
        byte[] after=new byte[0],operation,responseDigest;
        RosterMessage.Summary request;
        long started,progress,revision=-1;
        int failures;boolean done,awaitingAck,intervalDone;
        RosterMessage.Summary finishedRequest;
        Peer(SessionManager.VerifiedSession value){session=value.sessionId();generation=value.generation();}
    }
    private final LanGroup group;
    private final SessionManager sessions;
    private final CorePersistenceCoordinator coordinator;
    private final Clock clock;
    private final LanRuntime.Storage storage;
    private final RevocationRecovery transport;
    private final MemberDirectory directory;
    private final Map<DhtId,Peer> peers=new HashMap<>();
    private final RosterAckQueue acks;
    private record Arrival(byte[] operation,byte[] digest,long began){}
    private record ArrivalKey(DhtId peer,ManagementPage.Kind kind){}
    private final Map<ArrivalKey,Arrival> arrivals=new HashMap<>();
    private long conflicts;
    private List<byte[]> loadedRoster;
    RosterExchange(LanGroup group,SessionManager sessions,CorePersistenceCoordinator coordinator,Clock clock,LanRuntime.Storage storage,RevocationRecovery transport){
        this.group=group;this.sessions=sessions;this.coordinator=coordinator;this.clock=clock;this.storage=storage;this.transport=transport;
        directory=new MemberDirectory(group.state);acks=new RosterAckQueue(clock);reload();
        if(group.isAdministrator()&&group.management==null){directory.saved(group.certificate);if(group.peerCertificate!=null)directory.saved(group.peerCertificate);}
    }
    void reload(){
        if(group.isAdministrator()&&group.management!=null&&loadedRoster!=group.management.roster){
            directory.restoreSnapshot(group.management.roster);loadedRoster=group.management.roster;
        }
    }
    MemberDirectory directory(){return directory;}
    long conflicts(){return conflicts;}
    private boolean localAdministrator(){
        return group.isAdministrator()&&group.state.administrators().hasEntry(Crypto.ed25519Public(group.administratorSecret));
    }
    private boolean administrator(byte[] peer){
        if(!localAdministrator())return false;
        try{new MemberDirectory(group.state).administratorDirectory(sessions,peer,List.of());return true;}
        catch(RuntimeException unavailable){return false;}
    }
    private boolean current(byte[] id,Peer peer){
        var value=sessions.verifiedSession(id);
        return value!=null&&value.generation()==peer.generation&&Crypto.equal(value.sessionId(),peer.session)&&administrator(id);
    }
    private boolean expired(Peer peer){long now=clock.millis();return now<peer.started||now-peer.started>=240000||now-peer.progress>=30000;}
    private void failed(Peer peer){peer.failures++;peer.request=null;peer.operation=null;peer.responseDigest=null;peer.awaitingAck=false;peer.finishedRequest=null;peer.done=peer.failures>=3;}
    private void stopped(){storage.persistenceHooks(group).stopped(CorePersistenceCoordinator.StopReason.STORAGE_FAILED);}
    private void save(MemberDirectory candidate){
        try{storage.saveDirectory(group,candidate,group.management==null?Map.of():group.management.aliases);}
        catch(Exception failure){throw new IllegalStateException("名簿を保存できません",failure);}
    }
    private MemberDirectory candidate(){reload();var value=new MemberDirectory(group.state);value.restoreSnapshot(directory.snapshot());return value;}
    private List<byte[]> storedRoster(){return group.management==null?List.of():group.management.roster;}
    private boolean sameRoster(List<byte[]> expected){
        var current=storedRoster();if(current==expected)return true;if(current.size()!=expected.size())return false;
        for(int i=0;i<current.size();i++)if(!Arrays.equals(current.get(i),expected.get(i)))return false;return true;
    }
    private final class RosterSave implements Runnable {
        private final MemberDirectory candidate;private List<byte[]> expected=storedRoster();
        RosterSave(MemberDirectory candidate){this.candidate=candidate;}
        public void run(){save(candidate);expected=candidate.snapshot();}
        boolean current(){return sameRoster(expected);}
    }
    private void publish(MemberDirectory candidate){directory.restoreSnapshot(candidate.snapshot());loadedRoster=storedRoster();}
    void registerFirst(byte[] id){
        if(!localAdministrator()||!coordinator.permits(CorePersistenceCoordinator.Operation.ROSTER))return;
        var verified=sessions.verifiedSession(id);if(verified==null)return;
        reload();var first=sessions.authenticatedFirstCertificate(id);if(first==null)return;
        var held=directory.get(id);
        if(held!=null&&(held.issuedAt()>first.issuedAt()||held.issuedAt()==first.issuedAt()&&Arrays.equals(held.certificate().encode(),first.encode())))return;
        final MemberDirectory candidate;final boolean[] changed={false};
        try{
            candidate=candidate();coordinator.execute(CorePersistenceCoordinator.Operation.ROSTER,()->changed[0]=candidate.authenticatedFirst(sessions,id));
        }catch(SecurityException unavailable){return;}
        if(!changed[0])return;
        long revision=directory.revision();var base=group.state.snapshot();
        var save=new RosterSave(candidate);
        coordinator.saveRoster(new CorePersistenceCoordinator.RosterUpdate(save,()->{
            var now=sessions.verifiedSession(id);
            if(now==null||now.generation()!=verified.generation()||!Crypto.equal(now.sessionId(),verified.sessionId())
                    ||directory.revision()!=revision||!save.current()||!ManagementState.sameSnapshot(base,group.state.snapshot()))return false;
            try{candidate.authenticatedFirst(sessions,id);return true;}catch(SecurityException invalid){return false;}
        },()->publish(candidate)),this::stopped);
    }
    void poll(List<byte[]> candidates){
        coordinator.pruneRosterSummaryRetries(this::administrator);
        if(!coordinator.permits(CorePersistenceCoordinator.Operation.ROSTER)||!group.isAdministrator()){acks.close();coordinator.clearRosterAckRetries();return;}
        reload();
        flushAcks();
        for(var retry:coordinator.rosterAckRetries()){
            if(!administrator(retry.peer())||acks.offer(retry.peer(),retry.session(),retry.generation(),retry.ack(),retry.received(),retry.began()))
                coordinator.removeRosterAckRetry(retry);
        }
        flushAcks();
        var retained=new HashSet<DhtId>();
        for(byte[] id:candidates){
            var key=new DhtId(id);if(!administrator(id))continue;var verified=sessions.verifiedSession(id);if(verified==null)continue;
            retained.add(key);var peer=peers.get(key);
            if(peer==null||peer.generation!=verified.generation()||!Crypto.equal(peer.session,verified.sessionId())){
                peer=new Peer(verified);peers.put(key,peer);
            }
            if((peer.request!=null||peer.awaitingAck)&&expired(peer))failed(peer);
            if(peer.failures>=3)continue;
            if(peer.done&&peer.revision!=directory.revision()){peer.done=false;peer.after=new byte[0];}
            if(peer.done||peer.request!=null||peer.awaitingAck)continue;
            var request=RosterMessage.summarize(directory,peer.after);byte[] operation=transport.nextManagementOperation();
            if(transport.offerRoster(id,ManagementPage.Kind.ROSTER_SUMMARY,operation,request.encode(),request.entries().size())==ManagementPageSender.Offer.ACCEPTED){
                peer.request=request;peer.operation=operation;peer.started=peer.progress=clock.millis();peer.revision=directory.revision();
            }
        }
        arrivals.entrySet().removeIf(entry->!retained.contains(entry.getKey().peer())||clock.millis()-entry.getValue().began()>=240000);
        peers.entrySet().removeIf(entry->!retained.contains(entry.getKey())||!current(entry.getKey().bytes(),entry.getValue()));
    }
    boolean receive(byte[] id,byte[] session,byte[] wire,long receivedAt){
        int field=ManagementEnvelopeFields.field(wire);
        if(field!=ManagementEnvelopeFields.DIRECTORY_PAGE&&field!=ManagementEnvelopeFields.DIRECTORY_SUMMARY_PAGE)return false;
        coordinator.pruneRosterSummaryRetries(this::administrator);
        if(!coordinator.permits(CorePersistenceCoordinator.Operation.ROSTER)||!administrator(id))return true;
        final ManagementPage page;
        try{page=ManagementPage.decodeEnvelope(wire);}catch(IllegalArgumentException malformed){return true;}
        var verified=sessions.verifiedSession(id);if(verified==null||!Crypto.equal(session,verified.sessionId()))return true;
        reload();
        var peer=peers.get(new DhtId(id));
        var arrivalKey=new ArrivalKey(new DhtId(id),page.kind());var arrival=arrivals.get(arrivalKey);
        if(page.kind()==ManagementPage.Kind.ROSTER){
            var replay=coordinator.completedRosterAck(id,session,verified.generation(),page,receivedAt);
            if(replay!=null){queueAck(id,session,verified.generation(),replay.ack(),replay.received(),replay.began());return true;}
        }
        if(page.kind()==ManagementPage.Kind.ROSTER&&(peer==null||peer.request==null||!current(id,peer)||expired(peer)
                ||!Crypto.equal(page.operationId(),peer.operation)))return true;
        if(arrival==null||!Crypto.equal(arrival.operation(),page.operationId())||!Crypto.equal(arrival.digest(),page.objectDigest())){
            if(!arrivals.containsKey(arrivalKey)&&arrivals.size()>=32)return true;
            arrival=new Arrival(page.operationId(),page.objectDigest(),receivedAt);arrivals.put(arrivalKey,arrival);
        }
        final long began=arrival.began();
        var response=new RosterMessage.Batch[1];var batch=new RosterMessage.Batch[1];
        var result=coordinator.receiveRosterPage(id,session,verified.generation(),page,receivedAt,(data,count)->{
            var base=group.state.snapshot();long revision=directory.revision();
            if(page.kind()==ManagementPage.Kind.ROSTER_SUMMARY){
                var summary=RosterMessage.decodeSummary(data);if(summary.entries().size()!=count)throw new SecurityException("名簿の件数が違います");
                for(var entry:summary.entries())if(directory.compare(entry)==MemberDirectory.Difference.CONFLICT)conflicts++;
                response[0]=RosterMessage.respond(directory,summary);
                boolean missing=summary.entries().stream().anyMatch(entry->{var difference=directory.compare(entry);
                    return difference==MemberDirectory.Difference.UNKNOWN||difference==MemberDirectory.Difference.REMOTE_NEWER;});
                return new CorePersistenceCoordinator.RosterUpdate(null,()->administrator(id)&&clock.millis()>=began&&clock.millis()-began<240000
                        &&ManagementState.sameSnapshot(base,group.state.snapshot()),()->{
                    if(missing&&peer!=null&&peer.done&&peer.failures<3&&peer.request==null&&!peer.awaitingAck){peer.done=false;peer.after=new byte[0];}
                },()->transport.offerRoster(id,ManagementPage.Kind.ROSTER,page.operationId(),response[0].encode(),response[0].certificates().size())==ManagementPageSender.Offer.ACCEPTED);
            }
            batch[0]=RosterMessage.decodeBatch(data);if(batch[0].certificates().size()!=count)throw new SecurityException("名簿の件数が違います");
            var request=peer.request;byte[] high=request.more()?request.entries().get(request.entries().size()-1).memberId():null;
            for(var certificate:batch[0].certificates()){
                byte[] member=Crypto.blake2s(certificate.field(0));
                var difference=directory.compare(new MemberDirectory.Summary(member,certificate.issuedAt(),Crypto.blake2s(certificate.signedBytes())));
                if(difference==MemberDirectory.Difference.CONFLICT){conflicts++;throw new SecurityException("名簿の同時刻競合です");}
                if(difference!=MemberDirectory.Difference.UNKNOWN&&difference!=MemberDirectory.Difference.REMOTE_NEWER&&difference!=MemberDirectory.Difference.EQUAL)throw new SecurityException("名簿の差分ではありません");
                if(request.after().length!=0&&AdminRecords.compareBytes(member,request.after())<=0
                        ||high!=null&&AdminRecords.compareBytes(member,high)>0)throw new SecurityException("名簿の区間が違います");
            }
            var next=candidate();boolean changed=next.administratorDirectory(sessions,id,batch[0].certificates());
            var save=new RosterSave(next);
            return new CorePersistenceCoordinator.RosterUpdate(changed?save:null,()->{
                if(!current(id,peer)||expired(peer)||peer.request!=request||directory.revision()!=revision
                        ||!save.current()||!ManagementState.sameSnapshot(base,group.state.snapshot()))return false;
                try{next.administratorDirectory(sessions,id,batch[0].certificates());return true;}
                catch(SecurityException invalid){return false;}
            },
                ()->{if(changed)publish(next);});
        },this::stopped);
        if(result.completed()==null){
            if(page.kind()==ManagementPage.Kind.ROSTER&&peer!=null&&peer.request!=null){
                if(result.status()==ManagementPageAssembler.Status.REJECTED||result.status()==ManagementPageAssembler.Status.CORRUPT)failed(peer);
                else if(result.status()==ManagementPageAssembler.Status.INCOMPLETE)peer.progress=Math.max(peer.progress,receivedAt);
            }
            if(result.ack()!=null)queueAck(id,session,verified.generation(),result.ack(),receivedAt,began);
            return true;
        }
        if(batch[0]!=null&&peer!=null){
            peer.finishedRequest=peer.request;peer.request=null;peer.awaitingAck=true;peer.intervalDone=batch[0].intervalDone();peer.responseDigest=page.objectDigest();
            peer.progress=Math.max(peer.progress,receivedAt);
        }
        if(result.ack()!=null)queueAck(id,session,verified.generation(),result.ack(),receivedAt,Math.min(began,result.completed().began()));
        return true;
    }
    private void queueAck(byte[] id,byte[] session,long generation,ManagementPageAck ack,long received,long began){
        if(!acks.offer(id,session,generation,ack,received,began)&&ack.complete())coordinator.deferRosterAck(id,session,generation,ack,received,began);
        flushAcks();
    }
    private void flushAcks(){
        acks.poll((id,session,generation)->{
            var verified=sessions.verifiedSession(id);return coordinator.permits(CorePersistenceCoordinator.Operation.ROSTER)&&administrator(id)
                &&verified!=null&&verified.generation()==generation&&Crypto.equal(session,verified.sessionId());
        },(id,session,ack)->{
            if(!transport.rosterAck(id,session,ack))return false;
            var peer=peers.get(new DhtId(id));
            if(ack.complete()&&peer!=null&&peer.awaitingAck&&Crypto.equal(peer.operation,ack.operationId())&&Crypto.equal(peer.responseDigest,ack.objectDigest())){
                var request=peer.finishedRequest;peer.awaitingAck=false;peer.finishedRequest=null;peer.operation=null;peer.responseDigest=null;
                peer.failures=0;peer.revision=directory.revision();
                if(peer.intervalDone){if(request.more())peer.after=request.entries().get(request.entries().size()-1).memberId();else peer.done=true;}
            }
            return true;
        });
    }
    public void close(){acks.close();coordinator.clearRosterAckRetries();coordinator.clearRosterSummaryRetries();peers.clear();arrivals.clear();}

}
