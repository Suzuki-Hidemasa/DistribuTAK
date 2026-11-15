// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.SessionManager;
import java.util.Objects;

/**
 * 同じグループの握手と正しいDHT応答を確認した相手。Contactから公開の変換はしない。
 * 作れるのは、SessionManagerが全検査を通した確立済みのセッション（VerifiedSession）からだけ（核 C1）。
 * 作ったときの世代を持ち、ネットワークが変わったあとの古い世代の受信は核の口で捨てる。
 */
public final class AuthenticatedPeer {
    /** 世代を持たない試験用の相手。同じパッケージの試験だけが作る。 */
    static final long UNBOUND=-1;
    private final Contact contact;
    private final long generation;
    private AuthenticatedPeer(Contact contact,long generation) {
        this.contact=Objects.requireNonNull(contact);this.generation=generation;
    }
    /** 確立済みのセッションだけから作る。世代は、セッションの中の値（SessionManager が作ったときのもの）を使い、呼ぶ側からは渡さない。 */
    public static AuthenticatedPeer fromVerifiedSession(SessionManager.VerifiedSession session) {
        Objects.requireNonNull(session);
        return new AuthenticatedPeer(new Contact(new DhtId(session.peerId())),session.generation());
    }
    /** 核の試験だけが使う。世代は問わない。本番の配送は fromVerifiedSession を使う。 */
    static AuthenticatedPeer fromVerifiedDhtResponse(Contact contact){return new AuthenticatedPeer(contact,UNBOUND);}
    /** 核の試験だけが使う。世代を決めて作る。 */
    static AuthenticatedPeer fromVerifiedDhtResponse(Contact contact,long generation){return new AuthenticatedPeer(contact,generation);}
    public Contact contact(){return contact;}
    public DhtId id(){return contact.id();}
    long generation(){return generation;}
    @Override public String toString(){return "Authenticated DHT peer";}
}
