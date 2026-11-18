// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.time.Clock;
import java.security.SecureRandom;
import java.util.function.LongSupplier;
import java.util.*;

/**
 * 管理DHTの有限保管を、検証・保存後の管理状態と鍵の適用へ結ぶ。
 * <p>
 * Connects bounded management DHT storage to validated and persisted management state and key application.
 */
final class ManagedDhtExchange implements AutoCloseable,ManagedDependencies {
    private final LanGroup group;
    private final CorePersistenceCoordinator coordinator;
    private final LanRuntime.Storage storage;
    private final DhtRecordBudget budget=new DhtRecordBudget();
    private final GroupAdministration administration;
    private final KeyRotationCoordinator rotation;
    private final ManagedDhtStore store;
    private final SessionManager sessions;
    private final Clock wall,deadlines;
    private final SecureRandom random;
    private final Map<DhtId,Lookup> lookups=new LinkedHashMap<>();
    private final Map<DhtId,byte[]> seenSessions=new LinkedHashMap<>();
    private RevocationRecovery transport;
    private long nextScan,lastLookup=Long.MIN_VALUE,nextPublish;
    private static final long[] RETRIES={0,5000,15000,30000,60000};
    private static final class Lookup {
        final long began;int attempt;boolean busy;
        Lookup(long began){this.began=began;}
    }
    private boolean closed;
    ManagedDhtExchange(LanGroup group,SessionManager sessions,CorePersistenceCoordinator coordinator,RevocationUnion union,
            Clock wall,Clock deadlines,LongSupplier nanos,SecureRandom random,LanRuntime.Storage storage){
        this.group=group;this.coordinator=coordinator;this.storage=storage;this.sessions=sessions;
        this.wall=wall;this.deadlines=deadlines;this.random=random;
        administration=group.isAdministrator()?new GroupAdministration(group.state,group.certificate,group.identitySecret,
                group.handshakeSecret,group.administratorSecret,wall,nanos,random):null;
        rotation=administration==null?null:administration.rotations(sessions,union,deadlines,coordinator);
        if(rotation!=null&&group.management!=null)group.management.restoreRotation(group,rotation);
        store=new ManagedDhtStore(group.groupId,wall,deadlines,new AdminStateTrust(group.state),union,
                peer->sessions.verifiedSession(peer)!=null&&!coordinator.isRevoked(peer),budget,this,this::accepted,this::allowed);
    }
    boolean allowed(){return !closed&&coordinator.permits(CorePersistenceCoordinator.Operation.DHT_WRITE);}
    ManagedDhtStore store(){return store;}
    DhtRecordBudget budget(){return budget;}
    TransferResources resources(){return coordinator.transferResources();}
    KeyRotationCoordinator rotation(){return rotation;}
    private java.util.function.Predicate<AdminRecords.Record> beforeAdministrators=value->false;
    private Runnable administratorRemoved=()->{};
    void administratorRemoved(Runnable value){administratorRemoved=Objects.requireNonNull(value);}
    void beforeAdministrators(java.util.function.Predicate<AdminRecords.Record> value){beforeAdministrators=value;}
    KeyRotationCoordinator.Result manual(List<byte[]> revoked){
        if(!allowed()||rotation==null)throw new IllegalStateException("今は操作できません");
        return rotation.manual(revoked,recipients(),storage.persistenceHooks(group));
    }
    void transport(RevocationRecovery value){transport=value;value.beforeSending(this::refreshSavedDelivery);}
    private void lookup(DhtId key){if(!lookups.containsKey(key)&&lookups.size()<8)lookups.put(key,new Lookup(deadlines.millis()));}
    ManagementPageAck receiveAnnouncement(byte[] peer,byte[] session,byte[] wire,long receivedAt){
        if(!allowed())return null;
        var current=sessions.verifiedSession(peer);if(current==null||!Crypto.equal(current.sessionId(),session))return null;
        final ManagementPage page;
        try{page=ManagementPage.decodeEnvelope(wire);}catch(IllegalArgumentException invalid){return null;}
        return coordinator.receiveAnnouncementPage(peer,session,current.generation(),page,receivedAt,a->{
            var admins=group.state.administrators();
            if(!Crypto.equal(a.group(),group.groupId)||!a.hasValidSignature())throw new SecurityException("Invalid announcement");
            if(a.signedAt()>wall.millis()+300000)throw new SecurityException("Future announcement");
            if(a.adminVersion()>admins.version()){
                lookup(DhtKeys.derive(group.groupId,DhtKeys.ADMIN_HISTORY,DhtKeys.adminHistorySubject(admins.version()+1)));return false;
            }
            a.verify(group.groupId,admins.entries());
            if(a.adminVersion()!=admins.version()||!Crypto.equal(a.adminDigest(),Crypto.blake2s(admins.signedBytes())))
                throw new SecurityException("Announcement authority reference differs");
            var body=store.revocations(a.revocationVersion(),a.revocationDigest());
            if(body==null){lookup(DhtKeys.derive(group.groupId,DhtKeys.LATEST_REVOCATIONS,new byte[32]));return false;}
            group.state.verifyAnnouncement(a,body);
            if(!group.isAdministrator())return admitMemberAnnouncement(a,body);
            var outer=ManagedDhtRecord.issue(group.groupId,group.administratorSecret,a,0,admins.version(),Crypto.blake2s(admins.signedBytes()),a.signedAt());
            var status=store.accept(null,outer,false);
            return status==DhtWire.StoreStatus.ACCEPTED||status==DhtWire.StoreStatus.DUPLICATE||status==DhtWire.StoreStatus.OLD;
        });
    }
    private boolean admitMemberAnnouncement(KeyAnnouncement a,AdminRecords.Record body){
        group.state.verifyAnnouncement(a,body);if(!store.rememberAnnouncement(a))return false;
        if(a.keyVersion()>group.keyVersion&&group.state.coversRevocations(body))lookup(DhtKeys.derive(group.groupId,DhtKeys.WRAPPED_KEY,group.id()));
        return true;
    }
    /**
     * 既存pollから有限の探索を進め、保存済みの候補だけを配送する。
     * <p>
     * Advances bounded discovery from the existing poll and delivers only persisted candidates.
     */
    void poll(LanDht dht){
        if(!allowed())return;
        long now=deadlines.millis();var peers=dht.managementPeers();
        publishedInners.entrySet().removeIf(e->wall.millis()>=e.getValue().expiresAt());
        seenSessions.entrySet().removeIf(e->sessions.verifiedSession(e.getKey().bytes())==null);
        boolean fresh=false;
        for(var peer:peers){var current=sessions.verifiedSession(peer.id().bytes());if(current==null)continue;
            var previous=seenSessions.put(peer.id(),current.sessionId());
            if(previous==null||!Crypto.equal(previous,current.sessionId()))fresh=true;
        }
        if(fresh||now>=nextScan){
            for(int kind:new int[]{DhtKeys.LATEST_ADMINS,DhtKeys.LATEST_REVOCATIONS,DhtKeys.KEY_ANNOUNCEMENT})lookup(DhtKeys.derive(group.groupId,kind,new byte[32]));
            nextScan=now+25000+random.nextInt(10001);
        }
        for(var key:store.dependencyKeys())lookup(key);
        var iterator=lookups.entrySet().iterator();
        while(iterator.hasNext()){var e=iterator.next();if(now<e.getValue().began||now-e.getValue().began>=120000)iterator.remove();}
        if(!peers.isEmpty()&&(lastLookup==Long.MIN_VALUE||now-lastLookup>=1000)){
            for(var e:new ArrayList<>(lookups.entrySet())){
                var op=e.getValue();if(op.busy||op.attempt>=RETRIES.length||now-op.began<RETRIES[op.attempt])continue;
                var peer=peers.get(op.attempt%peers.size());op.busy=true;op.attempt++;lastLookup=now;
                if(!dht.findManaged(peer,e.getKey(),value->{
                    if(closed||lookups.get(e.getKey())!=op)return;op.busy=false;
                    if(value!=null)lookups.remove(e.getKey());
                },()->!closed&&allowed()&&lookups.get(e.getKey())==op&&deadlines.millis()>=op.began&&deadlines.millis()-op.began<120000))op.busy=false;
                break;
            }
        }
        publishSaved(dht,peers,now);
    }
    private List<AdminRecords.Record> recipients(){
        var result=new ArrayList<AdminRecords.Record>();
        if(group.management!=null)for(var encoded:group.management.roster){
            var cert=AdminRecords.decode(encoded);byte[] id=Crypto.blake2s(cert.field(0));
            try{group.state.verifyCertificate(cert,cert.field(1));if(!coordinator.isRevoked(id))result.add(cert);}
            catch(SecurityException invalid){}
        }
        return result;
    }
    private KeyRotationCoordinator.Publication lastPublication;
    private byte[] revocationTarget,announcementTarget;
    private AdminRecordStore.Snapshot publishedBasis;
    // 最大20相手の位置と束縛だけを持ち、本文は保存済みの状態から読む。
    // Hold only positions and bindings for at most 20 peers, reading payloads from persisted state.
    private static final class PublicationCursor {
        final Contact peer;final byte[] session;final long generation;int position;long expiresAt;
        PublicationCursor(Contact peer,byte[] session,long generation){this.peer=peer;this.session=session.clone();this.generation=generation;}
    }
    private final List<PublicationCursor> publicationCursors=new ArrayList<>();
    private boolean publishing;

    // 対象32B・内側の照合値32B・期限8Bの計72B。本体とJavaの管理領域を含まない。
    // Fixed data totals 72B: target 32B, inner digest 32B, expiry 8B; excludes payload and Java overhead.
    private record PublishedInner(byte[] digest,long expiresAt){}
    private final Map<DhtId,PublishedInner> publishedInners=new HashMap<>();
    private static final class PageRecipient {
        final byte[] session;final long generation,began;boolean revocation,announcement;
        PageRecipient(byte[] session,long generation,long began){this.session=session.clone();this.generation=generation;this.began=began;}
    }
    private final Map<DhtId,PageRecipient> pageRecipients=new HashMap<>();
    private KeyRotationCoordinator.Publication currentPublication(){
        if(closed||rotation==null||!group.isAdministrator())return null;var value=rotation.publication();if(value==null)return null;
        try{group.state.verifyAnnouncement(value.announcement(),value.revocations());return value;}
        catch(SecurityException|IllegalStateException invalid){return null;}
    }
    private void refreshSavedDelivery(){
        var publication=currentPublication();
        if(publication!=lastPublication){
            if(transport!=null)transport.cancelSavedDelivery(revocationTarget,announcementTarget);
            revocationTarget=publication==null?null:ManagementPage.digestOf(publication.revocations().encode());
            announcementTarget=publication==null?null:ManagementPage.digestOf(publication.announcement().encode());
            lastPublication=publication;pageRecipients.clear();publicationCursors.clear();publishing=false;nextPublish=0;
        }
    }
    private void publishSaved(LanDht dht,List<Contact> peers,long now){
        if(rotation==null||!group.isAdministrator())return;
        boolean authorized=group.state.administrators().hasEntry(Crypto.ed25519Public(group.administratorSecret));
        if(authorized&&rotation.pending())rotation.poll(recipients(),storage.persistenceHooks(group));
        var publication=currentPublication();
        var basis=group.management==null?group.state.snapshot():group.management.snapshot;
        refreshSavedDelivery();
        if(!authorized)return;
        if(publishedBasis!=basis){publishedBasis=basis;publicationCursors.clear();publishing=false;nextPublish=0;}
        if(peers.isEmpty()&&!publishing)return;
        if(publication!=null&&transport!=null)for(var peer:peers){
            var current=sessions.verifiedSession(peer.id().bytes());if(current==null||coordinator.isRevoked(peer.id().bytes()))continue;
            var delivery=pageRecipients.get(peer.id());
            if(delivery==null||delivery.generation!=current.generation()||!Arrays.equals(delivery.session,current.sessionId())){
                delivery=new PageRecipient(current.sessionId(),current.generation(),now);pageRecipients.put(peer.id(),delivery);
            }
            if(now<delivery.began||now-delivery.began>=240000)continue;
            if(!delivery.revocation)delivery.revocation=transport.offerRevocations(peer.id().bytes())==ManagementPageSender.Offer.ACCEPTED;
            if(delivery.revocation&&!delivery.announcement)
                delivery.announcement=transport.offerAnnouncement(peer.id().bytes(),publication.announcement(),delivery.began)==ManagementPageSender.Offer.ACCEPTED;
        }
        if(!publishing){
            if(now<nextPublish)return;
            for(var peer:peers.stream().limit(20).toList()){
                var current=sessions.verifiedSession(peer.id().bytes());
                if(current!=null&&!coordinator.isRevoked(peer.id().bytes()))publicationCursors.add(new PublicationCursor(peer,current.sessionId(),current.generation()));
            }
            publishing=true;
            var savedRecords=basis.records();var savedCerts=recipients();
            int count=savedRecords.size()+3+(publication==null?0:publication.envelopes().size());
            for(int position=0;position<count;position++)publicationRecord(position,savedRecords,publication,savedCerts);
            var first=publicationRecord(0,savedRecords,publication,savedCerts);
            if(first!=null)for(var cursor:publicationCursors)cursor.expiresAt=first.expiresAt();
        }
        var records=basis.records();var certs=recipients();
        var cursors=publicationCursors.iterator();
        while(cursors.hasNext()){
            var cursor=cursors.next();var current=sessions.verifiedSession(cursor.peer.id().bytes());
            if(current==null||current.generation()!=cursor.generation||!Arrays.equals(current.sessionId(),cursor.session)
                    ||coordinator.isRevoked(cursor.peer.id().bytes())){cursors.remove();continue;}
            int total=records.size()+3+(publication==null?0:publication.envelopes().size());
            while(cursor.position<total){
                if(cursor.expiresAt!=0&&wall.millis()>=cursor.expiresAt){cursor.position=total;break;}
                var record=publicationRecord(cursor.position,records,publication,certs);
                if(record==null){cursor.position++;cursor.expiresAt=0;continue;}
                if(cursor.expiresAt==0)cursor.expiresAt=record.expiresAt();
                if(dht.managementSendFull())return;
                var target=record.key();var saved=publication;
                if(!dht.publishManaged(cursor.peer,record.encode(),ignored->{},()->allowed()
                        &&sessions.verifiedSession(cursor.peer.id().bytes())!=null
                        &&sessions.verifiedSession(cursor.peer.id().bytes()).generation()==cursor.generation
                        &&Arrays.equals(sessions.sessionId(cursor.peer.id().bytes()),cursor.session)
                        &&!coordinator.isRevoked(cursor.peer.id().bytes())&&store.get(target)==record
                        &&(record.kind()!=DhtKeys.WRAPPED_KEY&&record.kind()!=DhtKeys.KEY_ANNOUNCEMENT||saved!=null&&currentPublication()==saved))){
                    if(dht.managementSendFull())return;
                    break;
                }
                cursor.position++;cursor.expiresAt=0;
            }
            if(cursor.position>=total)cursors.remove();
        }
        if(publicationCursors.isEmpty()){publishing=false;nextPublish=now+3600000;}
    }
    private ManagedDhtRecord publicationRecord(int position,List<byte[]> records,KeyRotationCoordinator.Publication publication,List<AdminRecords.Record> certs){
        var admins=group.state.administrators();
        if(position==0){
            var prior=group.state.administratorsAt(admins.version()-1);
            return preparePublication(DhtKeys.LATEST_ADMINS,admins,prior==null?admins:prior,null,null);
        }
        if(position<=records.size()){
            var record=AdminRecords.decode(records.get(position-1));if(record.kind()!=AdminRecords.Kind.ADMINS)return null;
            var prior=group.state.administratorsAt(record.version()-1);
            return preparePublication(DhtKeys.ADMIN_HISTORY,record,prior==null?record:prior,null,null);
        }
        if(position==records.size()+1)return preparePublication(DhtKeys.LATEST_REVOCATIONS,group.state.revocations(),admins,null,null);
        if(publication==null)return null;
        var ann=publication.announcement();var authority=group.state.administratorsAt(ann.adminVersion());if(authority==null)return null;
        if(position==records.size()+2)return preparePublication(DhtKeys.KEY_ANNOUNCEMENT,null,authority,ann,null);
        var wrap=publication.envelopes().get(position-records.size()-3);
        if(coordinator.isRevoked(wrap.field(0))||publication!=currentPublication())return null;
        var cert=certs.stream().filter(c->Crypto.equal(Crypto.blake2s(c.field(0)),wrap.field(0))).findFirst().orElse(null);
        return cert==null?null:preparePublication(DhtKeys.WRAPPED_KEY,wrap,authority,null,cert.encode());
    }
    private ManagedDhtRecord preparePublication(int kind,AdminRecords.Record inner,AdminRecords.Record authority,
            KeyAnnouncement announcement,byte[] certificate){
        long signedAt=announcement==null?inner.signedAt():announcement.signedAt();
        if(wall.millis()-signedAt>=86400000)return null;
        byte[] subject=kind==DhtKeys.ADMIN_HISTORY?DhtKeys.adminHistorySubject(inner.version()):kind==DhtKeys.WRAPPED_KEY?inner.field(0):new byte[32];
        var key=DhtKeys.derive(group.groupId,kind,subject);var held=store.get(key);
        boolean same=held!=null&&(announcement==null?Arrays.equals(held.inner().encode(),inner.encode()):Arrays.equals(held.announcement().encode(),announcement.encode()));
        byte[] innerDigest=Crypto.blake2s(announcement==null?inner.signedBytes():announcement.signedBytes());
        var published=publishedInners.get(key);
        if(!same&&published!=null&&Arrays.equals(published.digest(),innerDigest))return null;
        if(!publishedInners.containsKey(key)&&publishedInners.size()>=DhtRecordBudget.MAX_RECORDS)return null;
        if(!same){
            var digest=Crypto.blake2s(authority.signedBytes());
            var value=announcement==null?ManagedDhtRecord.issue(kind,group.groupId,group.administratorSecret,inner,0,authority.version(),digest,signedAt,certificate)
                    :ManagedDhtRecord.issue(group.groupId,group.administratorSecret,announcement,0,authority.version(),digest,signedAt);
            var status=store.accept(null,value,false);
            if(status!=DhtWire.StoreStatus.ACCEPTED&&status!=DhtWire.StoreStatus.DUPLICATE)return null;
            held=store.get(key);
        }
        if(held==null)return null;publishedInners.put(key,new PublishedInner(innerDigest,held.expiresAt()));
        return Crypto.equal(held.signer(),Crypto.ed25519Public(group.administratorSecret))?held:null;
    }
    private void accepted(ManagedDhtRecord value){
        coordinator.execute(CorePersistenceCoordinator.Operation.DHT_WRITE,()->{});
        if(value.kind()==DhtKeys.LATEST_ADMINS||value.kind()==DhtKeys.ADMIN_HISTORY){
            boolean heldAdministrator=group.isAdministrator();
            try{
                var current=group.state.administrators();
                if(value.inner().version()>current.version()||value.inner().version()==current.version()&&AdminRecords.compare(value.inner(),current)>0){
                    if(!beforeAdministrators.test(value.inner())&&!coordinator.receiveAdministrators(value.inner(),storage.persistenceHooks(group))){
                        if(coordinator.state()==CorePersistenceCoordinator.State.RUNNING)throw new ManagedDhtStore.PersistenceDeferred();
                        throw new IllegalStateException("Administrator persistence stopped");
                    }
                }
            }finally{
                if(heldAdministrator&&!group.isAdministrator()){
                    if(administration!=null)administration.close();
                    administratorRemoved.run();
                }
            }
        }else if(value.kind()==DhtKeys.LATEST_REVOCATIONS){
            coordinator.receiveRevocations(value.inner(),storage.persistenceHooks(group));
            if(coordinator.state()!=CorePersistenceCoordinator.State.RUNNING)throw new IllegalStateException("Management persistence stopped");
        }else if(value.kind()==DhtKeys.KEY_ANNOUNCEMENT){
            var announcement=value.announcement();
            var body=store.revocations(announcement.revocationVersion(),announcement.revocationDigest());
            if(body==null)throw new SecurityException("Missing announcement body");
            coordinator.execute(CorePersistenceCoordinator.Operation.KEY_ANNOUNCEMENT,()->{
                group.state.verifyAnnouncement(announcement,body);
                if(rotation!=null&&group.isAdministrator())rotation.observe(announcement,body);
            });
            if(announcement.keyVersion()>group.keyVersion&&group.state.coversRevocations(body))lookup(DhtKeys.derive(group.groupId,DhtKeys.WRAPPED_KEY,group.id()));
        }else if(value.kind()==DhtKeys.WRAPPED_KEY&&Crypto.equal(value.subject(),group.id())){
            var announcement=store.announcement(value.inner().field(4));
            if(announcement==null)throw new SecurityException("Missing wrap announcement");
            if(announcement.keyVersion()>group.keyVersion){
                var result=coordinator.applyGroupKey(announcement,value.inner(),group.id(),group.handshakeSecret,
                        group.keyVersion,sessions.generation(),storage.persistenceHooks(group));
                if(result!=CorePersistenceCoordinator.KeyResult.APPLIED)throw new SecurityException("Key application deferred");
            }
        }
    }
    @Override public KeyAnnouncement announcement(byte[] digest){
        var value=group.state.announcement();
        return value!=null&&Crypto.equal(Crypto.blake2s(value.signedBytes()),digest)?value:null;
    }
    @Override public AdminRecords.Record revocations(long version,byte[] digest){
        for(byte[] encoded:group.state.snapshot().records()){
            var value=AdminRecords.decode(encoded);
            if(value.kind()==AdminRecords.Kind.REVOCATIONS&&value.version()==version
                    &&Crypto.equal(Crypto.blake2s(value.signedBytes()),digest))return value;
        }
        var value=group.state.revocations();
        return value.version()==version&&Crypto.equal(Crypto.blake2s(value.signedBytes()),digest)?value:null;
    }
    @Override public void close(){
        if(closed)return;closed=true;
        if(transport!=null){transport.cancelSavedDelivery(revocationTarget,announcementTarget);transport.beforeSending(()->{});}
        store.clear();publicationCursors.clear();publishing=false;lookups.clear();seenSessions.clear();publishedInners.clear();pageRecipients.clear();if(administration!=null)administration.close();
    }
}
