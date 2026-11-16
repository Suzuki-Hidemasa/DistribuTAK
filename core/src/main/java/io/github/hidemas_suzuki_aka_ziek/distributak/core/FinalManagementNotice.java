// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * 取り消す相手への、署名済み失効一覧の内側だけの一方向送信枠。
 * 同じスレッドから呼ぶ。作成から1秒で閉じるため、所有側はpollを定期的に呼ぶ。失効の適用や通常の切断は待たせない。
 * <p>
 * A one-way sending slot only for the inner signed revocation list addressed to a revoked peer.
 * Call on one thread. The owner polls periodically to close it one second after creation, without delaying revocation or normal disconnection.
 */
public final class FinalManagementNotice implements AutoCloseable {
    /**
     * 確定したページだけを送る専用口。closeは所有する送信鍵も破棄する。核には鍵を渡さない。
     * <p>
     * A dedicated port only for finalized pages; close also destroys its owned sending key. The core never receives that key.
     */
    public interface Port extends AutoCloseable {
        boolean send(byte[] plaintext);
        void close();
    }
    /**
     * SENTは送出だけを表し、相手の受信・一覧の完成・自動消去を保証しない。
     * <p>
     * SENT means only emission and guarantees neither reception, completion of the peer's list, nor automatic erasure.
     */
    public enum Outcome {INCOMPLETE,SENT}
    private final byte[] peer;
    private final Clock clock;
    private final ManagementSendBudget budget;
    private final long started;
    private long lastClock;
    private Port port;
    private List<ManagementPage> pages;
    private boolean attempted,closed;
    private Outcome outcome=Outcome.INCOMPLETE;
    public FinalManagementNotice(byte[] peer,byte[] group,byte[] operation,AdminRecords.Record record,Clock clock,ManagementSendBudget budget,Port port){
        Crypto.length(peer,32);Crypto.length(group,32);Crypto.length(operation,16);Objects.requireNonNull(record);
        if(record.kind()!=AdminRecords.Kind.REVOCATIONS||!Arrays.equals(group,record.group())||!record.hasValidSignature())
            throw new IllegalArgumentException("Invalid final notice");
        this.peer=peer.clone();this.clock=Objects.requireNonNull(clock);this.budget=Objects.requireNonNull(budget);
        this.port=Objects.requireNonNull(port);started=clock.millis();lastClock=started;
        byte[] inner=record.encode();
        pages=inner.length<=4096?ManagementPage.split(ManagementPage.Kind.REVOCATION,operation,group,inner,record.entries().size()):List.of();
    }
    private void expire(){long now=clock.millis();if(now<lastClock||now-started>=1000)close();lastClock=now;}
    public void poll(){
        expire();if(closed||attempted)return;attempted=true;
        if(pages.isEmpty()||!budget.tryTake(peer,pages.size()))return;
        boolean all=true;
        for(var page:pages){
            expire();if(closed){all=false;break;}
            try{if(!port.send(page.envelope()))all=false;}catch(RuntimeException failed){all=false;}
            expire();
        }
        if(all)outcome=Outcome.SENT;
    }
    /**
     * 受信はすべて捨てる。ACKも再送も行わず、期限だけを確認する。
     * <p>
     * Discards all received messages, sending neither ACKs nor retries and checking only expiry.
     */
    public void receive(byte[] ignored){expire();}
    public Outcome outcome(){return outcome;}
    public boolean closed(){return closed;}
    public void close(){
        if(closed)return;closed=true;pages=List.of();Port owned=port;port=null;
        try{owned.close();}catch(RuntimeException ignored){
            // 枠を復活させず、所有側の破棄処理は一度だけ呼ぶ。
            // Never revive the slot, and invoke the owner's destruction callback only once.
        }
    }
}
