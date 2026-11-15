// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

/** 同じ回線での再試行だけを許し、核の握手より短い待ちを作らない。 */
final class ReconnectSupervisor {
    private boolean enabled;
    private int attempt,failures;
    private long next;
    void enable(long now){enabled=true;attempt=failures=0;next=now;}
    void stop(){enabled=false;}
    boolean active(){return enabled;}
    ReconnectSupervisor snapshot(){var copy=new ReconnectSupervisor();copy.restore(this);return copy;}
    void restore(ReconnectSupervisor previous){enabled=previous.enabled;attempt=previous.attempt;failures=previous.failures;next=previous.next;}
    boolean due(long now){return enabled&&now>=next;}
    void retry(long now){
        long delay=Math.min(60,5L<<Math.min(attempt++,4))*1_000_000_000L;
        next=now>Long.MAX_VALUE-delay?Long.MAX_VALUE:now+delay;
    }
    void failed(long now){if(++failures>=3)stop();else retry(now);}
    void established(){attempt=failures=0;}
}
