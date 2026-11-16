// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.*;
import java.util.function.Supplier;
/** 管理者の検証済み名簿。番地、CoT、呼び名は保持しない。登録の根拠を4つに限定する。 */
public final class MemberDirectory {
    public static final int MAX_MEMBERS=65536;
    public enum Difference { UNKNOWN, EQUAL, LOCAL_NEWER, REMOTE_NEWER, CONFLICT }
    public static final class Conflict extends SecurityException {Conflict(){super("同じ発行時刻の証明書の内容が違います");}}
    public record Summary(byte[] memberId,long issuedAt,byte[] digest) {
        public Summary {Crypto.length(memberId,32);Crypto.length(digest,32);if(issuedAt<0)throw new IllegalArgumentException("発行時刻が不正です");memberId=memberId.clone();digest=digest.clone();}
        @Override public byte[] memberId(){return memberId.clone();}
        @Override public byte[] digest(){return digest.clone();}
        @Override public String toString(){return "Member summary";}
    }
    public static final class Entry {
        private final AdminRecords.Record certificate;
        private final byte[] member,digest;
        private final List<byte[]> administrators;
        private Entry(AdminRecords.Record certificate,List<AdminBinding> bindings) {
            this.certificate=certificate;member=Crypto.blake2s(certificate.field(0));digest=Crypto.blake2s(certificate.signedBytes());
            var keys=new ArrayList<byte[]>();for(var binding:bindings)
                if(binding.state()==AdminBinding.State.BOUND&&Crypto.equal(binding.memberId(),member)
                        &&Crypto.equal(binding.identityKey(),certificate.field(0)))keys.add(binding.administratorKey());
            administrators=List.copyOf(keys);
        }
        public byte[] memberId(){return member.clone();}
        public byte[] identityKey(){return certificate.field(0);}
        public byte[] handshakeKey(){return certificate.field(1);}
        public AdminRecords.Record certificate(){return certificate;}
        public long issuedAt(){return certificate.issuedAt();}
        public byte[] digest(){return digest.clone();}
        public List<byte[]> administratorKeys(){var out=new ArrayList<byte[]>();for(byte[] key:administrators)out.add(key.clone());return List.copyOf(out);}
        @Override public String toString(){return "Member entry";}
    }
    private final AdminState state;
    private final Supplier<List<AdminBinding>> bindings;
    private final TreeMap<String,AdminRecords.Record> records=new TreeMap<>();
    private long revision;
    public MemberDirectory(AdminState state){this(state,()->state.administrators().bindings());}
    MemberDirectory(AdminState state,Supplier<List<AdminBinding>> bindings){this.state=Objects.requireNonNull(state);this.bindings=Objects.requireNonNull(bindings);}
    private static String name(byte[] member){Crypto.length(member,32);return org.bouncycastle.util.encoders.Hex.toHexString(member);}
    private List<AdminBinding> verifiedBindings() {
        var current=state.administrators();var result=bindings.get();
        for(var binding:result)if(!current.hasEntry(binding.administratorKey())||!binding.verifies(current.group(),current.version()))
            throw new SecurityException("管理者の対応が今の一覧と違います");
        return result;
    }
    private Entry entry(AdminRecords.Record certificate){return new Entry(certificate,verifiedBindings());}
    public synchronized Entry get(byte[] member){var certificate=records.get(name(member));return certificate==null?null:entry(certificate);}
    public synchronized int size(){return records.size();}
    /**
     * 期限切れや失効後の項目も、正確な署名根拠として保存する。
     * <p>
     * Preserves expired and revoked entries as exact signed evidence for storage.
     */
    public synchronized List<byte[]> snapshot(){var result=new ArrayList<byte[]>();for(var certificate:records.values())result.add(certificate.encode());return List.copyOf(result);}
    /**
     * 保存済み名簿を一括復元する。期限切れや失効を通信へ許可しない。
     * <p>
     * Atomically restores a stored roster without authorizing expired or revoked entries for communication.
     */
    public synchronized void restoreSnapshot(List<byte[]> encoded){
        var next=new TreeMap<String,AdminRecords.Record>();
        for(byte[] bytes:encoded){var certificate=AdminRecords.decode(bytes);state.verifyStoredCertificateEvidence(certificate);
            String key=name(Crypto.blake2s(certificate.field(0)));if(next.containsKey(key))throw new SecurityException("保存名簿が重複しています");put(next,certificate);}
        records.clear();records.putAll(next);revision=Math.addExact(revision,1);
    }
    public synchronized long revision(){return revision;}
    public synchronized List<Summary> summary(){var out=new ArrayList<Summary>();for(var cert:records.values())out.add(new Summary(Crypto.blake2s(cert.field(0)),cert.issuedAt(),Crypto.blake2s(cert.signedBytes())));return List.copyOf(out);}
    public synchronized Difference compare(Summary remote) {
        var local=records.get(name(remote.memberId()));if(local==null)return Difference.UNKNOWN;
        if(local.issuedAt()<remote.issuedAt())return Difference.REMOTE_NEWER;if(local.issuedAt()>remote.issuedAt())return Difference.LOCAL_NEWER;
        return Crypto.equal(Crypto.blake2s(local.signedBytes()),remote.digest())?Difference.EQUAL:Difference.CONFLICT;
    }
    public synchronized List<Entry> validRecipients() {
        var out=new ArrayList<Entry>();for(var certificate:records.values()) {
            try{state.verifyCertificate(certificate,certificate.field(1));out.add(entry(certificate));}
            catch(SecurityException unavailable){}
        }return List.copyOf(out);
    }
    private void check(AdminRecords.Record certificate,boolean allowExpired){state.verifyCertificate(certificate,certificate.field(1),allowExpired);}
    private boolean put(TreeMap<String,AdminRecords.Record> target,AdminRecords.Record certificate) {
        String key=name(Crypto.blake2s(certificate.field(0)));var old=target.get(key);
        if(old!=null) {
            if(old.issuedAt()>certificate.issuedAt())return false;
            if(old.issuedAt()==certificate.issuedAt()) {
                if(!Crypto.equal(Crypto.blake2s(old.signedBytes()),Crypto.blake2s(certificate.signedBytes())))throw new Conflict();return false;
            }
        }
        if(old==null&&target.size()>=MAX_MEMBERS)throw new IllegalStateException("名簿の件数が上限です");
        target.put(key,certificate);return true;
    }
    private boolean register(AdminRecords.Record certificate,boolean allowExpired) {
        check(certificate,allowExpired);boolean changed=put(records,certificate);if(changed)revision=Math.addExact(revision,1);return changed;
    }
    public synchronized boolean joined(UdpEndpoint.AdminJoined joined){return register(joined.certificate(),false);}
    public synchronized boolean authenticatedFirst(SessionManager sessions,byte[] peerId) {
        var certificate=sessions.authenticatedFirstCertificate(peerId);
        if(certificate==null||!Crypto.equal(peerId,Crypto.blake2s(certificate.field(0))))throw new SecurityException("認証済みのFIRSTがありません");
        return register(certificate,false);
    }
    public synchronized boolean administratorDirectory(SessionManager sessions,byte[] sender,List<AdminRecords.Record> supplied) {
        var session=sessions.verifiedSession(sender);var certificate=sessions.peerCertificate(sender);
        if(session==null||certificate==null||!Crypto.equal(sender,Crypto.blake2s(certificate.field(0))))throw new SecurityException("管理者のセッションがありません");
        check(certificate,false);boolean administrator=false;
        for(var binding:verifiedBindings())if(binding.state()==AdminBinding.State.BOUND&&Crypto.equal(binding.memberId(),sender)
                &&Crypto.equal(binding.identityKey(),certificate.field(0)))administrator=true;
        if(!administrator)throw new SecurityException("対応を確かめた管理者ではありません");
        var next=new TreeMap<>(records);boolean changed=false;
        for(var candidate:supplied){check(candidate,false);changed=put(next,candidate)||changed;}
        if(changed){long nextRevision=Math.addExact(revision,1);records.clear();records.putAll(next);revision=nextRevision;}return changed;
    }
    public synchronized boolean saved(AdminRecords.Record certificate){return register(certificate,true);}
    synchronized void clear(){records.clear();revision=Math.addExact(revision,1);}
    @Override public String toString(){return "Member directory";}
}
