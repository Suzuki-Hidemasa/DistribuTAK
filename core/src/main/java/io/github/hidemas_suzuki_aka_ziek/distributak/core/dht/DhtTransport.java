// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.Objects;

/**
 * 配送と認証の境目。送り手が握手か紹介で知ったContactだけへ送る。
 * 実装は送信を待ち行列へ入れ、sendの中からDhtNodeへ応答を同期して返さない。
 * 同じスレッドからpollとreceiveを呼び、DHTの線の形はC2のアダプターで扱う。
 */
public interface DhtTransport {
    enum Operation { PING,FIND_NODE,FIND_VALUE,STORE }
    /** idはこの核の口での照合用。線のrequest_idとの対応は配送側が管理する。 */
    final class Request {
        private final long id;
        private final Operation operation;
        private final DhtId target;
        Request(long id,Operation operation,DhtId target) {
            this.id=id;this.operation=Objects.requireNonNull(operation);this.target=Objects.requireNonNull(target);
        }
        public long id(){return id;}
        public Operation operation(){return operation;}
        public DhtId target(){return target;}
        @Override public String toString(){return "DHT request";}
    }
    /**
     * falseは配送を開始できなかった場合。RuntimeExceptionも核ではfalseと同じに扱い、文は記録しない。
     * 探索は失敗した照会に数え、PINGは古い相手を残す（回答7546）。候補の握手と遅れは配送側で数える。
     */
    boolean send(Contact destination,Request request);
    /** 探索が相手へ送れるようになっているか。READY は今すぐ送れる。 */
    enum Readiness { READY,CONNECTING,BUSY,UNAVAILABLE }
    /**
     * 探索が候補へ照会する前に聞く。副作用があってよいが、同じ相手へ何度聞いても握手や開始の数を増やしてはならない。
     * 既定は READY（握手を受け持たない配送側は、これまでどおり send の成否だけで決める）。
     */
    default Readiness prepare(Contact destination){return Readiness.READY;}
    /**
     * 探索の候補が NEW から初めて BUSY になったときに、その探索が 1 回だけ呼ぶ。直前の prepare が BUSY を返した相手の件だけ。
     * 件数を数えるための知らせで、握手や送信を始めてはならない。既定は何もしない。例外は核が握りつぶす。
     */
    default void firstBusy(Contact destination){}
}
