// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

/**
 * DHTの線と認証済みのセッションの境目（核C2）。実装は SessionManager と UdpEndpoint を使う。
 * 呼ぶのは DhtNode と同じ1本のスレッドだけ。別スレッドからの受信は待ち行列を通してから渡す。
 * 相手の番号・セッションの番号・番地は、ログにも例外の文にも出さない。
 */
public interface DhtLink {
    /**
     * いま確立している（全検査を通した）セッションなら、その相手を返す。
     * 相手の番号とセッションの番号が今のセッションと合わないときは null。
     */
    AuthenticatedPeer authenticated(byte[] peerId,byte[] sessionId);
    /** 平文をその相手のそのセッションで送る。送り始められたときだけ true。RuntimeException は呼ぶ側が false と同じに扱う。 */
    boolean send(byte[] peerId,byte[] sessionId,byte[] plaintext);
    /**
     * 自分が始めた揮発の相手（保存していない相手）を手放す。手放したときだけ true。
     * 保存した相手・知らない相手・閉じているときは false。呼ぶ側は false のとき何も外さない。
     */
    boolean releaseVolatile(byte[] peerId);
    /**
     * 揮発の相手の枠に空きがあるか。false のときだけ、核は自分が始めた相手を 1 台手放してから新しい握手を始める。
     * 実装が分からないときは true（手放さない側）にする。
     */
    default boolean volatileSlotFree(){return true;}
    /**
     * 核から握手を始めてよいか。招待した相手を待つ間（pin が残る間）は false にする（答え 182 の 8）。
     * false のとき核は握手を始めず、手放しもせず、その相手を使えない（UNAVAILABLE）として探索を先へ進める。既存のセッションには関係しない。
     * 実装が分からないときは true にする。
     */
    default boolean startAllowed(){return true;}
}
