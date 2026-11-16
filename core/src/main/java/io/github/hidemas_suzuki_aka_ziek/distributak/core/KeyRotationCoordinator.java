// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.RevocationUnion;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.*;

/**
 * 競合の統合と手動の入れ替えで、待機・番号予約・保存後の公開を共有する。製品への接続は第8回。
 * <p>
 * Shares delays, version reservations and publication after persistence between conflict consolidation and manual rotations.
 * Product integration is round eight.
 */
public final class KeyRotationCoordinator implements AutoCloseable {
    public enum Result {IDLE,WAITING,TOO_EARLY,PUBLISHED,CANCELLED,VERSION_LIMIT}
    public static final long INTERVAL_MILLIS=5000,MAX_DELAY_MILLIS=2000;
    private final AdminState admin;
    private final SessionManager sessions;
    private final RevocationUnion union;
    private final CorePersistenceCoordinator persistence;
    private final Clock wall,deadlines;
    private final SecureRandom random;
    private final byte[] secret,group;
    private final byte[] member;
    private final java.util.function.BooleanSupplier active;
    private long maxKey,maxRevocation,observedVersion=-1,triggerVersion,scheduledAt,delay,lastOperation;
    private boolean pending,operated,closed,issuing;
    private byte[] firstAnnouncement,secondAnnouncement,handledUnion,handledFirst,handledSecond;
    private Publication publication;

    KeyRotationCoordinator(AdminState admin,SessionManager sessions,RevocationUnion union,byte[] administratorSecret,
            Clock wall,Clock deadlines,SecureRandom random){
        this(admin,sessions,union,administratorSecret,wall,deadlines,random,null,()->true);
    }
    KeyRotationCoordinator(AdminState admin,SessionManager sessions,RevocationUnion union,byte[] administratorSecret,
            Clock wall,Clock deadlines,SecureRandom random,byte[] member,java.util.function.BooleanSupplier active){
        this.admin=Objects.requireNonNull(admin);this.sessions=Objects.requireNonNull(sessions);this.union=Objects.requireNonNull(union);
        this.wall=Objects.requireNonNull(wall);this.deadlines=Objects.requireNonNull(deadlines);this.random=Objects.requireNonNull(random);
        this.member=member==null?null:member.clone();this.active=Objects.requireNonNull(active);
        Crypto.length(administratorSecret,32);secret=administratorSecret.clone();group=admin.administrators().group();
        persistence=new CorePersistenceCoordinator(admin,sessions,union,wall,deadlines);
        maxKey=sessions.keyVersion();maxRevocation=admin.revocations().version();
        var current=admin.announcement();if(current!=null){observedVersion=current.keyVersion();firstAnnouncement=current.signedBytes();}
    }
    public CorePersistenceCoordinator persistence(){return persistence;}
    /**
     * 保存した予約の上限を復元する。上限は後退させない。
     * <p>
     * Restores saved reservation ceilings without allowing them to regress.
     */
    public synchronized void restoreReservations(long keyVersion,long revocationVersion){
        open();if(keyVersion<0||revocationVersion<0)throw new IllegalArgumentException("Negative reservation");
        maxKey=Math.max(maxKey,keyVersion);maxRevocation=Math.max(maxRevocation,revocationVersion);
    }
    public synchronized long reservedKeyVersion(){return maxKey;}
    public synchronized long reservedRevocationVersion(){return maxRevocation;}
    private void open(){if(closed)throw new IllegalStateException("Rotation coordinator is closed");}
    private boolean authorized(){return active.getAsBoolean()&&admin.administrators().hasEntry(Crypto.ed25519Public(secret))&&!sessions.isClosed();}
    private void requireAuthority(){open();sessions.refresh();if(!authorized())throw new SecurityException("Administrator is no longer authorized");}
    private static boolean equal(byte[] a,byte[] b){return Arrays.equals(a,b);}
    private byte[] unionStamp(){return CorePersistenceCoordinator.revocationDigest(union.subjects());}
    private void discardPublication(){if(publication!=null){publication.close();publication=null;}}
    /**
     * 署名と参照本体の検証後にだけ競合を観測する。失効の保存は受信の調整処理で先に行う。
     * <p>
     * Observes conflicts only after verifying signatures and referenced bodies. Persist revocations through the receive coordinator first.
     */
    public synchronized void observe(KeyAnnouncement value,AdminRecords.Record body){
        open();admin.verifyAnnouncement(value,body);
        maxKey=Math.max(maxKey,value.keyVersion());maxRevocation=Math.max(maxRevocation,body.version());
        byte[] bytes=value.signedBytes();
        if(value.keyVersion()>observedVersion){observedVersion=value.keyVersion();firstAnnouncement=bytes;secondAnnouncement=null;}
        else if(value.keyVersion()==observedVersion&&!equal(firstAnnouncement,bytes)){
            if(secondAnnouncement==null||AdminRecords.compareBytes(bytes,secondAnnouncement)>0)secondAnnouncement=bytes;
        }
        reconcile();
    }
    private void reconcile(){
        open();union.restore(admin);maxRevocation=Math.max(maxRevocation,admin.revocations().version());maxKey=Math.max(maxKey,sessions.keyVersion());
        if(!authorized()){pending=false;discardPublication();return;}
        var current=admin.announcement();
        boolean conflict=secondAnnouncement!=null&&observedVersion>=sessions.keyVersion();
        if(pending&&conflict)triggerVersion=Math.max(triggerVersion,observedVersion);
        if(pending&&current!=null&&current.keyVersion()>triggerVersion&&current.keyVersion()==sessions.keyVersion()
                &&admin.coversRevocations(admin.revocations())&&union.covers(admin.revocations())){
            pending=false;handledUnion=unionStamp();
            if(observedVersion<=current.keyVersion()){handledFirst=firstAnnouncement;handledSecond=secondAnnouncement;}
            discardPublication();return;
        }
        if(publication!=null&&(!equal(admin.snapshot().announcement(),publication.announcement.encode())
                ||!equal(publication.unionStamp,unionStamp())))discardPublication();
        boolean missing=!admin.coversRevocations(admin.revocations())||!union.covers(admin.revocations());
        byte[] stamp=unionStamp();
        boolean handled=equal(stamp,handledUnion)&&equal(firstAnnouncement,handledFirst)&&equal(secondAnnouncement,handledSecond);
        if((conflict||missing)&&!handled){
            if(!pending){pending=true;scheduledAt=deadlines.millis();delay=random.nextInt((int)MAX_DELAY_MILLIS+1);triggerVersion=Math.max(observedVersion,sessions.keyVersion());}
        }
    }
    public synchronized boolean pending(){reconcile();return pending;}
    private boolean tooEarly(long now){return operated&&(now<lastOperation||now-lastOperation<INTERVAL_MILLIS);}
    public synchronized Result poll(List<AdminRecords.Record> recipients,CorePersistenceCoordinator.PersistenceHooks hooks){
        requireAuthority();reconcile();if(!pending)return Result.IDLE;
        long now=deadlines.millis();if(now<scheduledAt||now-scheduledAt<delay||tooEarly(now))return Result.WAITING;
        return issue(List.of(),recipients,hooks);
    }
    public synchronized Result manual(List<byte[]> revoked,List<AdminRecords.Record> recipients,CorePersistenceCoordinator.PersistenceHooks hooks){
        requireAuthority();
        for(byte[] subject:revoked){
            Crypto.length(subject,32);if(member!=null&&Crypto.equal(subject,member))throw new SecurityException("Cannot revoke own membership");
            for(var binding:admin.administrators().bindings())if(binding.state()==AdminBinding.State.BOUND&&Crypto.equal(subject,binding.memberId()))
                throw new SecurityException("Remove administrator authority before revoking membership");
        }
        reconcile();
        boolean known=!revoked.isEmpty();for(byte[] subject:revoked)if(!union.contains(subject))known=false;
        if(known&&!pending)return Result.IDLE;
        if(tooEarly(deadlines.millis()))return Result.TOO_EARLY;
        return issue(revoked,recipients,hooks);
    }
    private Result issue(List<byte[]> revoked,List<AdminRecords.Record> recipients,CorePersistenceCoordinator.PersistenceHooks hooks){
        if(issuing)throw new IllegalStateException("Rotation is already being persisted");
        if(maxKey==Long.MAX_VALUE||maxRevocation==Long.MAX_VALUE){pending=false;return Result.VERSION_LIMIT;}
        var subjects=new TreeSet<byte[]>(AdminRecords::compareBytes);subjects.addAll(admin.revokedSubjects());subjects.addAll(union.subjects());
        for(byte[] subject:revoked){Crypto.length(subject,32);subjects.add(subject.clone());}
        if(subjects.size()>AdminRecords.MAX_ENTRIES)throw new AdminRecords.RevocationLimitException();
        long version=++maxKey,revocationVersion=++maxRevocation;lastOperation=deadlines.millis();operated=true;
        discardPublication();byte[] key=new byte[32];random.nextBytes(key);Publication candidate=null;issuing=true;
        try{
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group,revocationVersion,wall.millis(),List.copyOf(subjects),secret);
            if(!union.covers(body))throw new SecurityException("Candidate omits the revocation union");
            var admins=admin.administrators();
            var announcement=KeyAnnouncement.issue(group,secret,version,wall.millis(),body.version(),Crypto.blake2s(body.signedBytes()),
                KeyAnnouncement.commitment(group,version,key),admins.version(),Crypto.blake2s(admins.signedBytes()));
            var wraps=new ArrayList<AdminRecords.Record>();var seen=new TreeSet<byte[]>(AdminRecords::compareBytes);
            for(var certificate:recipients){
                byte[] recipient=Crypto.blake2s(certificate.field(0));if(subjects.contains(recipient)||union.contains(recipient)||!seen.add(recipient))continue;
                try{admin.verifyCertificate(certificate,certificate.field(1));}catch(SecurityException invalid){continue;}
                wraps.add(GroupKeyEnvelope.wrap(group,recipient,certificate.field(1),version,wall.millis(),key,secret,Crypto.blake2s(announcement.signedBytes())));
            }
            candidate=new Publication(this,body,announcement,wraps,CorePersistenceCoordinator.revocationDigest(List.copyOf(subjects)));
            if(!persistence.persistRotation(body,announcement,key,candidate,hooks))return Result.CANCELLED;
            publication=candidate;candidate=null;pending=false;
            handledUnion=unionStamp();handledFirst=firstAnnouncement;handledSecond=secondAnnouncement;
            observedVersion=version;firstAnnouncement=announcement.signedBytes();secondAnnouncement=null;
            return Result.PUBLISHED;
        }finally{issuing=false;Crypto.wipe(key);if(candidate!=null)candidate.close();}
    }
    /**
     * 保存済みで現在も有効な送信候補だけを返す。取消後に取得済み候補を使うことも断る。
     * <p>
     * Returns only a persisted, still-current publication. Previously obtained publications are also unusable after cancellation.
     */
    public synchronized Publication publication(){if(issuing)return null;reconcile();return publication;}
    /**
     * 公開番号と送信待ちを含む保存候補。秘密鍵の保存は同じフックに別引数で渡す。
     * <p>
     * A persistence candidate including reserved versions and outgoing envelopes. The same hook receives the secret key separately.
     */
    public record SavedRotation(AdminRecordStore.Snapshot management,List<AdminRecords.Record> envelopes,long keyVersion,long revocationVersion){
        public SavedRotation{Objects.requireNonNull(management);envelopes=List.copyOf(envelopes);if(keyVersion<0||revocationVersion<0)throw new IllegalArgumentException("Negative reservation");}
        @Override public String toString(){return "Saved key rotation";}
    }
    /**
     * 保存した鍵・管理状態・包みを照合してから送信待ちを復元する。旧包みのdigestは書き換えない。
     * <p>
     * Restores outgoing envelopes only after checking the saved key and management state. Never rewrites old envelope digests.
     */
    public synchronized void restorePublication(SavedRotation saved,byte[] key){
        requireAuthority();var announcement=admin.announcement();var body=admin.revocations();
        if(announcement==null||!AdminState.sameSnapshot(saved.management(),admin.snapshot())||sessions.keyVersion()!=saved.keyVersion()
                ||body.version()!=saved.revocationVersion()||announcement.keyVersion()!=saved.keyVersion()
                ||!admin.coversRevocations(body)||!union.covers(body))throw new SecurityException("Saved rotation differs from current state");
        admin.verifyAnnouncement(announcement,body);announcement.checkKey(group,saved.keyVersion(),key);
        var admins=admin.administrators();
        for(var envelope:saved.envelopes()){
            envelope.verify(AdminRecords.Kind.WRAPPED_KEY,group,admins);
            if(envelope.format()!=2||envelope.version()!=saved.keyVersion()||union.contains(envelope.field(0))
                    ||!Crypto.equal(envelope.field(4),Crypto.blake2s(announcement.signedBytes())))throw new SecurityException("Saved envelope is not current");
        }
        restoreReservations(saved.keyVersion(),saved.revocationVersion());discardPublication();pending=false;
        publication=new Publication(this,body,announcement,saved.envelopes(),unionStamp());
        lastOperation=deadlines.millis();operated=true;
    }
    public static final class Publication implements AutoCloseable {
        private final KeyRotationCoordinator owner;
        private final AdminRecords.Record revocations;
        private final KeyAnnouncement announcement;
        private final List<AdminRecords.Record> envelopes;
        private final byte[] unionStamp;
        private volatile boolean closed;
        private Publication(KeyRotationCoordinator owner,AdminRecords.Record revocations,KeyAnnouncement announcement,List<AdminRecords.Record> envelopes,byte[] unionStamp){
            this.owner=owner;this.revocations=revocations;this.announcement=announcement;this.envelopes=List.copyOf(envelopes);this.unionStamp=unionStamp.clone();
        }
        private void valid(){synchronized(owner){
            if(closed||!owner.persistence.permits(CorePersistenceCoordinator.Operation.KEY_ANNOUNCEMENT))throw new IllegalStateException("Publication is unavailable");
            owner.reconcile();if(closed)throw new IllegalStateException("Publication was cancelled");
        }}
        SavedRotation saved(AdminRecordStore.Snapshot management){return new SavedRotation(management,envelopes,announcement.keyVersion(),revocations.version());}
        public AdminRecords.Record revocations(){valid();return revocations;}
        public KeyAnnouncement announcement(){valid();return announcement;}
        public List<AdminRecords.Record> envelopes(){valid();return envelopes;}
        @Override public void close(){closed=true;}
        @Override public String toString(){return "Key rotation publication";}
    }
    @Override public synchronized void close(){closed=true;pending=false;discardPublication();Crypto.wipe(secret);}
    @Override public String toString(){return "Key rotation coordinator";}
}
