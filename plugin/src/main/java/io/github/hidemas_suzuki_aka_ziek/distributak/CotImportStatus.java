// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

/** 本体の取り込みの状態。入力の値は保持せず、固定の文と件数だけを表示する。 */
final class CotImportStatus {
    private long gateSkipped;
    private long invalidInput,expired,attempts;
    private int savedMarks=-1;
    synchronized void start(int size){clear();savedMarks(size);}
    synchronized void clear(){gateSkipped=0;invalidInput=0;expired=0;attempts=0;savedMarks=-1;}
    synchronized void gateSkipped(){if(gateSkipped<Long.MAX_VALUE)gateSkipped++;}
    synchronized void attempts(long count){attempts=count;}
    synchronized void invalidInput(){if(invalidInput<Long.MAX_VALUE)invalidInput++;}
    synchronized void expired(long count){expired=count;}
    synchronized void savedMarks(int size){savedMarks=size;}
    synchronized String text(long coreSkipped){
        return "\n取り込み（今回の同期）"
                +"\n取り込みの試行: "+attempts
                +"\n核で外来と一致して見送った件数: "+(coreSkipped<0?"未開始":Long.toString(coreSkipped))
                +"\n取り込みの直前に外来と一致して見送った件数: "+gateSkipped
                +"\n入力が無効で見送った件数: "+invalidInput
                +"\n外来の印の期限切れ件数: "+expired
                +"\n外来の印（external.bin・保存済み）件数: "+(savedMarks<0?"未読":Integer.toString(savedMarks));
    }
}
