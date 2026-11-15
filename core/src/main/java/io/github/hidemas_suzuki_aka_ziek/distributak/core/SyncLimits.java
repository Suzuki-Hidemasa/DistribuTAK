// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

/** ATAKのヒープに対する一覧の予算。wireの上限とは別に扱う。 */
public record SyncLimits(int peerBytes,int totalBytes) {
    public static final SyncLimits DEFAULT=new SyncLimits(8*1024*1024,32*1024*1024);
    public SyncLimits{if(peerBytes<=0||totalBytes<peerBytes)throw new IllegalArgumentException("一覧の予算が範囲外です");}
    public static SyncLimits forHeap(long maxHeapBytes){
        long total=Math.min(DEFAULT.totalBytes,maxHeapBytes/8);
        if(total<=0)throw new IllegalArgumentException("ヒープの上限が範囲外です");
        return new SyncLimits((int)Math.min(DEFAULT.peerBytes,total),(int)total);
    }
}
